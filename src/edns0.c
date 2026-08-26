/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  EDNS parsing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTLDNS
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"
#include "log.h"
#include "edns0.h"
// dotdoh_inject_client() prototype (declared in the dnsmasq-free server header)
#include "dotdoh/server.h"
#include "config/config.h"
#include "datastructure.h"
#include "shmem.h"
// pthread_once for the one-time client-option MAC-key init
#include <pthread.h>
// getrandom()
#include <sys/random.h>
// HMAC-SHA256 for the per-run client-attribution MAC (same crypto lib as the TOTP code)
#include <nettle/hmac.h>

// EDNS(0) Client Subnet [Optional, RFC7871]
#define EDNS0_ECS EDNS0_OPTION_CLIENT_SUBNET

// EDNS(0) COOKIE [Standard, RFC7873]
#define EDNS0_COOKIE 10

// EDNS(0) MAC address [NOT STANDARDIZED]
//
// BYTE encoding, payload size: 6 bytes
// dnsmasq option: --add-mac
#define EDNS0_MAC_ADDR_BYTE EDNS0_OPTION_MAC
// TEXT encoding, payload size: 17 bytes
// dnsmasq option: --add-mac=text
#define EDNS0_MAC_ADDR_TEXT EDNS0_OPTION_NOMDEVICEID
// BASE64 encoding, payload size: 8 bytes
// dnsmasq option: --add-mac=base64
#define EDNS0_MAC_ADDR_BASE64 EDNS0_MAC_ADDR_TEXT

// EDNS(0) CPE-ID (Common Platform Enumeration Identifier) [NOT STANDARDIZED]
// Payload: String of any length (can be zero)
// dnsmasq option: --add-cpe-id=...
#define EDNS0_CPE_ID EDNS0_OPTION_NOMCPEID

static ednsData edns = { 0 };

const char * __attribute__ ((pure)) peekEDNSClient(void)
{
	return config.dns.EDNS0ECS.v.b && edns.valid && edns.client_set ? edns.client : NULL;
}

ednsData *getEDNS(void)
{
	if(edns.valid)
	{
		// Return pointer to ednsData structure and reset it for the
		// next query
		edns.valid = false;
		return &edns;
	}

	// No valid EDNS data available
	return NULL;
}

// Per-run secret shared between our inbound DoT/DoH server (which injects the
// private-client option) and the parser below. Both run in this same FTL process,
// so the key never leaves our memory. The option carries an HMAC-SHA256 MAC over
// (client address || question section) keyed by this secret, not the secret
// itself, so a loopback sniffer cannot learn the key and forge attributions: the
// most it could do is replay an identical, already-legitimate query, which has no
// effect. Trusted only when the MAC verifies AND (in FTL_new_query) the query
// source is loopback. It does not defend against a process that can read our
// memory, which is already privileged and out of scope.
#define DOTDOH_MAC_LEN 16
static unsigned char dotdoh_mac_key[DOTDOH_MAC_LEN];
static pthread_once_t dotdoh_mac_key_once = PTHREAD_ONCE_INIT;
static void dotdoh_mac_key_init(void)
{
	if(getrandom(dotdoh_mac_key, sizeof(dotdoh_mac_key), 0) != (ssize_t)sizeof(dotdoh_mac_key))
	{
		// Fall back to an all-zero key both sides share (still gated on a loopback
		// source); log so a weakened boundary is visible. Practically never hit.
		// Zero explicitly: a short read may have filled only a prefix, and a
		// half-random key is worse than a known all-zero one (both peers must agree).
		memset(dotdoh_mac_key, 0, sizeof(dotdoh_mac_key));
		log_err("dotdoh: could not obtain a random client-option key");
	}
}

// Byte length of the question section (all QDCOUNT questions) from offset 12, or
// 0 if the message is malformed. The MAC is bound to these bytes so a captured
// MAC cannot be replayed onto a different query.
static size_t __attribute__((pure)) dotdoh_question_len(const unsigned char *msg, const size_t msglen)
{
	if(msg == NULL || msglen < 12)
		return 0;
	const unsigned qdcount = ((unsigned)msg[4] << 8) | msg[5];
	size_t pos = 12;
	for(unsigned q = 0; q < qdcount; q++)
	{
		for(;;)
		{
			if(pos >= msglen)
				return 0;
			const unsigned char c = msg[pos];
			if(c == 0) { pos += 1; break; }
			if((c & 0xC0) == 0xC0) { pos += 2; break; } // compression pointer
			if(c & 0xC0) return 0;                       // reserved label type
			pos += 1 + c;
		}
		pos += 4; // QTYPE + QCLASS
		if(pos > msglen)
			return 0;
	}
	return pos - 12;
}

// HMAC-SHA256(key = dotdoh_mac_key, code || addr || question), truncated into out.
// Binds the value to the exact query (so the MAC is not a reusable bearer secret)
// AND to the option code (so a dest option cannot be replayed as a client one).
static void dotdoh_addr_mac(const unsigned short code,
                            const unsigned char *addr, const size_t addrlen,
                            const unsigned char *question, const size_t qlen,
                            unsigned char out[DOTDOH_MAC_LEN])
{
	const unsigned char codebytes[2] = { (unsigned char)(code >> 8), (unsigned char)(code & 0xff) };
	struct hmac_sha256_ctx ctx;
	hmac_sha256_set_key(&ctx, sizeof(dotdoh_mac_key), dotdoh_mac_key);
	hmac_sha256_update(&ctx, sizeof(codebytes), codebytes);
	hmac_sha256_update(&ctx, addrlen, addr);
	if(qlen > 0)
		hmac_sha256_update(&ctx, qlen, question);
	hmac_sha256_digest(&ctx, DOTDOH_MAC_LEN, out);
}

// Encode ip as [family(1B): 4 or 6][address] into out (<= 17 bytes), returning the
// encoded length (5 or 17) or 0 if ip does not parse. A v4-mapped IPv6 address
// (::ffff:a.b.c.d) folds to IPv4 so an encrypted client is attributed to the same
// client as plain DNS (the source filter folds it too), not a distinct v6 client.
static size_t dotdoh_encode_addr(const char *ip, unsigned char *out)
{
	struct in_addr v4;
	struct in6_addr v6;
	if(inet_pton(AF_INET, ip, &v4) == 1)
	{
		out[0] = 4;
		memcpy(out + 1, &v4.s_addr, 4);
		return 5;
	}
	if(inet_pton(AF_INET6, ip, &v6) == 1)
	{
		if(IN6_IS_ADDR_V4MAPPED(&v6))
		{
			out[0] = 4;
			memcpy(out + 1, &v6.s6_addr[12], 4);
			return 5;
		}
		out[0] = 6;
		memcpy(out + 1, v6.s6_addr, 16);
		return 17;
	}
	return 0;
}

// add_pseudoheader() invokes dnsmasq's non-reentrant rrfilter() - which mutates a
// process-wide static workspace - whenever an existing OPT RR is not the last
// record, is a signed (TSIG/TKEY) packet, or carries a malformed option. Reaching
// that from our worker threads (the DoT reactor, the terminator handlers, the h3
// pool) races the dnsmasq main thread and the other workers and corrupts the heap.
// A well-formed DNS query never triggers it (its OPT, if any, is the sole last
// additional record with valid options), so detect the unsafe shapes here and let
// the caller reject the query. Read-only; touches no shared state.
static bool dotdoh_opt_rrfilter_safe(unsigned char *buf, size_t plen)
{
	int is_sign = 0, is_last = 0;
	unsigned char *udp = NULL;
	const unsigned char *opt = find_pseudoheader((struct dns_header *)(void *)buf,
	                                             plen, NULL, &udp, &is_sign, &is_last);
	if(opt == NULL)
		return true;             // no OPT: add_pseudoheader appends a fresh one
	if(is_sign || !is_last)
		return false;            // signed, or OPT not last -> rrfilter / reject
	// The OPT fixed fields after `udp` are CLASS(2) + TTL(4) + RDLEN(2); walk its
	// option TLVs exactly as add_pseudoheader does - an option whose length overruns
	// RDLEN makes it delete the OPT via rrfilter (RFC 6891 option framing).
	if(udp + 8 > buf + plen)
		return false;
	const unsigned int rdlen = ((unsigned int)udp[6] << 8) | udp[7];
	const unsigned char *rdata = udp + 8;
	if(rdata + rdlen > buf + plen)
		return false;
	for(unsigned int i = 0; i + 4 < rdlen;)
	{
		const unsigned int len = ((unsigned int)rdata[i + 2] << 8) | rdata[i + 3];
		if(i + 4 + len > rdlen)
			return false;    // malformed option -> add_pseudoheader takes rrfilter
		i += len + 4;
	}
	return true;
}

// Build [family][address][MAC] for ip and add it (replace=1, overwriting any
// instance a client injected itself) as the given private option code. The MAC
// over (code || address || question) binds it to this exact query. Returns the new
// packet length, unchanged if ip does not parse.
static size_t dotdoh_inject_addr(unsigned char *buf, size_t plen, size_t cap,
                                 const unsigned short code, const char *ip)
{
	unsigned char payload[1 + 16 + DOTDOH_MAC_LEN];
	size_t optlen = dotdoh_encode_addr(ip, payload);
	if(optlen == 0)
		return plen;
	dotdoh_addr_mac(code, payload + 1, optlen - 1, buf + 12,
	                dotdoh_question_len(buf, plen), payload + optlen);
	optlen += DOTDOH_MAC_LEN;
	return add_pseudoheader((struct dns_header *)(void *)buf, plen, cap,
	                        code, payload, optlen, 0, 1);
}

size_t dotdoh_inject_client(unsigned char *buf, size_t plen, size_t cap,
                            const char *client_ip, const char *dest_ip)
{
	if(buf == NULL || client_ip == NULL)
		return plen;

	// Refuse a query whose OPT would drive add_pseudoheader() into the
	// non-reentrant rrfilter() path (see dotdoh_opt_rrfilter_safe). Returning the
	// length unchanged makes dotdoh_prepare_query fail closed, so the malformed or
	// adversarial query is rejected rather than resolved unattributed.
	if(!dotdoh_opt_rrfilter_safe(buf, plen))
		return plen;

	pthread_once(&dotdoh_mac_key_once, dotdoh_mac_key_init);

	// The parser trusts either option only when the source is loopback AND its MAC
	// verifies (see below). Both hash the same (unchanged) question section.
	plen = dotdoh_inject_addr(buf, plen, cap, EDNS0_OPTION_PIHOLE_CLIENT, client_ip);
	if(dest_ip != NULL)
		plen = dotdoh_inject_addr(buf, plen, cap, EDNS0_OPTION_PIHOLE_DEST, dest_ip);
	return plen;
}

void FTL_parse_pseudoheaders(const unsigned char *msg, const size_t msglen,
                             unsigned char *pheader, const size_t plen)
{
	// Invalidate any previous query's EDNS up front. getEDNS() is consume-once,
	// so a query that populated `edns` but was never read must not leak into the
	// next one - only a valid OPT parsed below makes it valid again. This matters
	// now that `edns` also carries the private client-attribution options.
	edns.valid = false;

	// Return early if we have no pseudoheader (a.k.a. additional records)
	if (!pheader)
	{
		log_debug(DEBUG_EDNS0, "No EDNS(0) pheader found");
		return;
	}

	// Working pointer
	unsigned char *p = pheader;

// RFC 6891                   EDNS(0) Extensions                   6.1.2.  Wire Format
// 
//    An OPT RR has a fixed part and a variable set of options expressed as
//    {attribute, value} pairs.  The fixed part holds some DNS metadata,
//    and also a small collection of basic extension elements that we
//    expect to be so popular that it would be a waste of wire space to
//    encode them as {attribute, value} pairs.
// 
//    The fixed part of an OPT RR is structured as follows:
// 
//        +------------+--------------+------------------------------+
//        | Field Name | Field Type   | Description                  |
//        +------------+--------------+------------------------------+
//        | NAME       | domain name  | MUST be 0 (root domain)      |
	if(*p++ != 0)
		return;
//        +------------+--------------+------------------------------+
//        | TYPE       | u_int16_t    | OPT (41)                     |
	unsigned short type;
	GETSHORT(type, p);
	if(type != 41)
		return;
//        +------------+--------------+------------------------------+
//        | CLASS      | u_int16_t    | requestor's UDP payload size |
	unsigned short class;
	GETSHORT(class, p);
	log_debug(DEBUG_EDNS0, "requestor's UDP payload size: %u bytes", class);
//        +------------+--------------+------------------------------+
//        | TTL        | u_int32_t    | extended RCODE and flags     |
	unsigned long ttl;
	GETLONG(ttl, p);
//        +------------+--------------+------------------------------+
//        | RDLEN      | u_int16_t    | length of all RDATA          |
	unsigned short rdlen;
	GETSHORT(rdlen, p);
//        +------------+--------------+------------------------------+
//        | RDATA      | octet stream | {attribute,value} pairs      |
//        +------------+--------------+------------------------------+

//   The variable part of an OPT RR may contain zero or more options in
//   the RDATA.  Each option MUST be treated as a bit field.  Each option
//   is encoded as:
//
//                  +0 (MSB)                            +1 (LSB)
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    0: |                          OPTION-CODE                          |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    2: |                         OPTION-LENGTH                         |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    4: |                                                               |
//       /                          OPTION-DATA                          /
//       /                                                               /
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

// RFC 6891                   EDNS(0) Extensions                   6.1.3.  OPT Record TTL Field Use
//
//   The extended RCODE and flags, which OPT stores in the RR Time to Live
//   (TTL) field, are structured as follows:
//
//                  +0 (MSB)                            +1 (LSB)
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    0: |         EXTENDED-RCODE        |            VERSION            |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    2: | DO|                           Z                               |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//
//   EXTENDED-RCODE
//      Forms the upper 8 bits of extended 12-bit RCODE (together with the
//      4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0
//      indicates that an unextended RCODE is in use (values 0 through
//      15).
//
//   VERSION
//      Indicates the implementation level of the setter.  Full
//      conformance with this specification is indicated by version '0'.
//      Requestors are encouraged to set this to the lowest implemented
//      level capable of expressing a transaction, to minimise the
//      responder and network load of discovering the greatest common
//      implementation level between requestor and responder.  A
//      requestor's version numbering strategy MAY ideally be a run-time
//      configuration option.
//      If a responder does not implement the VERSION level of the
//      request, then it MUST respond with RCODE=BADVERS.  All responses
//      MUST be limited in format to the VERSION level of the request, but
//      the VERSION of each response SHOULD be the highest implementation
//      level of the responder.  In this way, a requestor will learn the
//      implementation level of a responder as a side effect of every
//      response, including error responses and including RCODE=BADVERS.
	unsigned char edns0_version = (ttl >> 16) & 0xFF;
	if(edns0_version != 0x00)
		return;

	// Reset EDNS(0) data
	memset(&edns, 0, sizeof(ednsData));
	edns.ede = EDE_UNSET;
	edns.valid = true;

	size_t offset; // The header is 11 bytes before the beginning of OPTION-DATA
	// Require the full 4-byte OPTION-CODE/OPTION-LENGTH header to be
	// present before reading it, otherwise a truncated option would make
	// the two GETSHORTs below read past the pseudoheader buffer
	while ((offset = (p - pheader - 11u)) + 4u <= rdlen && rdlen < UINT16_MAX)
	{
		unsigned short code, optlen;
		GETSHORT(code, p);
		GETSHORT(optlen, p);
		offset += 4;

		// Avoid buffer overflow due to an malicious packet
		if(offset + optlen > rdlen)
		{
			log_warn("Found malicious EDNS payload (payload larger than advertised), skipping record.");
			break;
		}

		// Debug logging
		log_debug(DEBUG_EDNS0, "code %u, optlen %u (bytes %zu - %zu of %u)",
		          code, optlen, offset, offset + optlen, rdlen);

		if (code == EDNS0_ECS && config.dns.EDNS0ECS.v.b && optlen >= 4)
		{
			// EDNS(0) CLIENT SUBNET
			// RFC 7871              Client Subnet in DNS Queries              6.  Option Format
			//   This protocol uses an EDNS0 [RFC6891] option to include client
			//   address information in DNS messages.  The option is structured as
			//   follows:
			//
			//                +0 (MSB)                            +1 (LSB)
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//   0: |                          OPTION-CODE                          |
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//   2: |                         OPTION-LENGTH                         |
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//   4: |                            FAMILY                             |
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			short family;
			GETSHORT(family, p);
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//   6: |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			unsigned char source_netmask = *p++;
			p++; // We are not interested in the scope prefix-length. It MUST be 0 in queries
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//   8: |                           ADDRESS...                          /
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			union all_addr addr = {};
			const size_t addrlen = optlen - 4;
			if(family == 1 && addrlen <= sizeof(addr.addr4.s_addr)) // IPv4
				memcpy(&addr.addr4.s_addr, p, addrlen);
			else if(family == 2 && addrlen <= sizeof(addr.addr6.s6_addr)) // IPv6
				memcpy(addr.addr6.s6_addr, p, addrlen);
			else
			{
				// Unhandled family: p has already advanced by the
				// 4-byte FAMILY/prefix header above, so consume the
				// remaining option data to line up with the next option
				p += optlen - 4;
				continue;
			}

			// Advance working pointer (we already walked 4 bytes above)
			p += optlen - 4;

			char ipaddr[ADDRSTRLEN] = { 0 };
			inet_ntop(family == 1 ? AF_INET : AF_INET6, &addr.addr4.s_addr, ipaddr, sizeof(ipaddr));

			// Only use /32 (IPv4) and /128 (IPv6) addresses
			if(!(family == 1 && source_netmask == 32) &&
			   !(family == 2 && source_netmask == 128))
			{
				log_debug(DEBUG_EDNS0, "CLIENT SUBNET: %s/%u found (IPv%u)",
				          ipaddr, source_netmask, family == 1 ? 4u : 6u);
				continue;
			}

			// Copy data to edns struct
			strncpy(edns.client, ipaddr, ADDRSTRLEN);
			edns.client[ADDRSTRLEN-1] = '\0';

			// Only set the address as useful when it is not the
			// loopback address of the distant machine (127.0.0.0/8 or ::1)
			if((family == 1 && (ntohl(addr.addr4.s_addr) & 0xFF000000) == 0x7F000000) ||
			   (family == 2 && IN6_IS_ADDR_LOOPBACK(&addr.addr6)))
			{
				log_debug(DEBUG_EDNS0, "CLIENT SUBNET: Skipped %s/%u (IPv%u loopback address)",
				          ipaddr, source_netmask, family == 1 ? 4u : 6u);
			}
			else
			{
				edns.client_set = true;
				log_debug(DEBUG_EDNS0, "CLIENT SUBNET: %s/%u - OK (IPv%u)",
				          ipaddr, source_netmask, family == 1 ? 4u : 6u);
			}
		}
		else if((code == EDNS0_OPTION_PIHOLE_CLIENT || code == EDNS0_OPTION_PIHOLE_DEST) &&
		        (optlen == 5 + DOTDOH_MAC_LEN || optlen == 17 + DOTDOH_MAC_LEN))
		{
			// Pi-hole-private hint injected by our own inbound DoT/DoH server:
			// [family(1B): 4 or 6][address(4 or 16B)][MAC]. PIHOLE_CLIENT carries
			// the real downstream client, PIHOLE_DEST the address it connected to.
			// Trusted only when the MAC verifies (proving it came from our own
			// process) AND later when the query source is loopback (FTL_new_query).
			const unsigned char pfam = *p;
			union all_addr paddr = {};
			int af = 0;
			size_t addrlen = 0;
			if(pfam == 4 && optlen == 5 + DOTDOH_MAC_LEN)
			{
				af = AF_INET;
				addrlen = 4;
				memcpy(&paddr.addr4.s_addr, p + 1, 4);
			}
			else if(pfam == 6 && optlen == 17 + DOTDOH_MAC_LEN)
			{
				af = AF_INET6;
				addrlen = 16;
				memcpy(paddr.addr6.s6_addr, p + 1, 16);
			}
			// Recompute the MAC over (address || question of this message) and
			// constant-time compare it to the one carried in the option.
			pthread_once(&dotdoh_mac_key_once, dotdoh_mac_key_init);
			unsigned char tdiff = 0;
			if(af != 0)
			{
				// Bound the question walk to where our OPT (pheader) begins: inject
				// saw the query without it, so a lying QDCOUNT must not let verify
				// read into the appended option and disagree with inject. (A
				// disagreement only ever fails safe - it never accepts a wrong MAC.)
				const size_t qbound = ((const unsigned char *)pheader >= msg &&
				    (size_t)((const unsigned char *)pheader - msg) <= msglen)
				    ? (size_t)((const unsigned char *)pheader - msg) : msglen;
				unsigned char want[DOTDOH_MAC_LEN];
				dotdoh_addr_mac(code, p + 1, addrlen, msg + 12,
				                dotdoh_question_len(msg, qbound), want);
				for(size_t i = 0; i < DOTDOH_MAC_LEN; i++)
					tdiff |= (unsigned char)(p[1 + addrlen + i] ^ want[i]);
			}
			if(af != 0 && tdiff == 0)
			{
				char ipaddr[ADDRSTRLEN] = { 0 };
				inet_ntop(af, &paddr, ipaddr, sizeof(ipaddr));
				// Store in a dedicated field, NOT the shared client[] the ECS
				// parser uses, so this option cannot influence ECS attribution.
				if(code == EDNS0_OPTION_PIHOLE_CLIENT)
				{
					strncpy(edns.private_client, ipaddr, ADDRSTRLEN);
					edns.private_client[ADDRSTRLEN - 1] = '\0';
					edns.private_client_set = true;
					log_debug(DEBUG_EDNS0, "PIHOLE CLIENT: %s (IPv%u)", ipaddr, pfam);
				}
				else
				{
					strncpy(edns.private_dest, ipaddr, ADDRSTRLEN);
					edns.private_dest[ADDRSTRLEN - 1] = '\0';
					edns.private_dest_set = true;
					log_debug(DEBUG_EDNS0, "PIHOLE DEST: %s (IPv%u)", ipaddr, pfam);
				}
			}
			// Neutralise the option in place so the real downstream client IP is
			// not forwarded to the upstream resolver (dnsmasq preserves unknown
			// EDNS options on the forward path). We keep the option length - only
			// zero the payload - because shortening it would require changing the
			// caller's plen at the dnsmasq call sites (a core patch).
			memset(p, 0, optlen);
			p += optlen; // advance to the next option
		}
		else if(code == EDNS0_COOKIE && optlen == 8)
		{
			// EDNS(0) COOKIE client
			unsigned char client_cookie[8];
			memcpy(client_cookie, p, 8);
			if(config.debug.edns0.v.b)
			{
				char pretty_client_cookie[8*2 + 1]; // client: fixed length
				char *pp = pretty_client_cookie;
				for(unsigned int j = 0; j < 8; j++)
					pp += sprintf(pp, "%02X", client_cookie[j]);
				log_debug(DEBUG_EDNS0, "COOKIE (client-only): %s",
				     pretty_client_cookie);
			}

			// Advance working pointer
			p += 8;
		}
		else if(code == EDNS0_COOKIE && optlen >= 16 && optlen <= 40)
		{
			// EDNS(0) COOKIE client + server
			if(config.debug.edns0.v.b)
			{
				unsigned char client_cookie[8];
				memcpy(client_cookie, p, 8);

				const unsigned short server_cookie_len = optlen - 8;
				// Server cookie is at most 32 bytes (optlen max 40 - 8)
				unsigned char server_cookie[32];
				memcpy(server_cookie, p + 8u, server_cookie_len);

				char pretty_client_cookie[8*2 + 1]; // client: fixed length
				char *pp = pretty_client_cookie;
				for(unsigned int j = 0; j < 8; j++)
					pp += sprintf(pp, "%02X", client_cookie[j]);
				// Server cookie hex: at most 32*2 + 1 = 65 bytes
				char pretty_server_cookie[32*2 + 1];
				pp = pretty_server_cookie;
				for(unsigned int j = 0; j < server_cookie_len; j++)
					pp += sprintf(pp, "%02X", server_cookie[j]);
				log_debug(DEBUG_EDNS0, "COOKIE (client + server): %s (client), %s (server, %u bytes)",
				     pretty_client_cookie, pretty_server_cookie, server_cookie_len);
			}

			// Advance working pointer
			p += optlen;
		}
		else if(code == EDNS0_MAC_ADDR_BYTE && optlen == 6)
		{
			// EDNS(0) MAC address (BYTE format)
			memcpy(edns.mac_byte, p, sizeof(edns.mac_byte));
			char *buff = print_mac((unsigned char*)edns.mac_byte, sizeof(edns.mac_byte));
			strncpy(edns.mac_text, buff, sizeof(edns.mac_text));
			edns.mac_text[sizeof(edns.mac_text) - 1] = '\0';
			edns.mac_set = true;
			log_debug(DEBUG_EDNS0, "MAC address (BYTE format): %s", edns.mac_text);

			// Advance working pointer
			p += 6;
		}
		else if(code == EDNS0_MAC_ADDR_TEXT && optlen == 17)
		{
			// EDNS(0) MAC address (TEXT format)
			memcpy(edns.mac_text, p, 17);
			edns.mac_text[17] = '\0';
			if(sscanf(edns.mac_text, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			          (unsigned char*)&edns.mac_byte[0],
			          (unsigned char*)&edns.mac_byte[1],
			          (unsigned char*)&edns.mac_byte[2],
			          (unsigned char*)&edns.mac_byte[3],
			          (unsigned char*)&edns.mac_byte[4],
			          (unsigned char*)&edns.mac_byte[5]) == 6)
			{
				edns.mac_set = true;
				log_debug(DEBUG_EDNS0, "MAC address (TEXT format): %s", edns.mac_text);
			}
			else
			{
				log_debug(DEBUG_EDNS0, "Received MAC address has invalid format!");
			}

			// Advance working pointer
			p += 17;
		}
		else if(code == EDNS0_MAC_ADDR_BASE64 && optlen == 8)
		{
			// EDNS(0) MAC address (BASE format)
			log_debug(DEBUG_EDNS0, "MAC address (BASE64 format): NOT IMPLEMENTED");

			// Advance working pointer
			p += 8;
		}
		else if(code == EDNS0_CPE_ID && optlen < 256)
		{
			// EDNS(0) CPE-ID, 256 byte arbitrary limit
			unsigned char *payload = calloc(optlen + 1u, sizeof(unsigned char));
			memcpy(payload, p, optlen);
			payload[optlen] = '\0';
			if(config.debug.edns0.v.b)
			{
				char *pretty_payload = calloc(optlen*5 + 1u, sizeof(char));
				char *pp = pretty_payload;
				for(unsigned int j = 0; j < optlen; j++)
					pp += sprintf(pp, "0x%02X ", payload[j]);

				// Truncate away the trailing whitespace
				if(optlen)
					pretty_payload[optlen*5 - 1] = '\0';

				log_debug(DEBUG_EDNS0, "CPE-ID (payload size %u): \"%s\" (%s)",
				     optlen, payload, pretty_payload);
				free(pretty_payload);
			}
			free(payload);

			// Advance working pointer
			p += optlen;
		}
		else if(code == EDNS0_OPTION_EDE && optlen >= 2)
		{
			// EDNS(0) EDE
			// https://datatracker.ietf.org/doc/rfc8914/
			//
			//                                                1   1   1   1   1   1
			//        0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//   0: |                            OPTION-CODE                        |
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//   2: |                           OPTION-LENGTH                       |
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//   4: | INFO-CODE                                                     |
			edns.ede = (p[0] << 8) | p[1];
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//   6: / EXTRA-TEXT ...                                                /
			//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			//
			// The INFO-CODE from the EDE EDNS option is used to
			// serve as an index into the "Extended DNS Error" IANA
			// registry, the initial values for which are defined in
			// this document. The value of the INFO-CODE is encoded
			// as a two-octet unsigned integer in network byte
			// order.

			// Debug output
			log_debug(DEBUG_EDNS0, "EDE: %s (code %d)", edestr(edns.ede), edns.ede);

			if(optlen > 2)
			{
				// Debug output
				log_debug(DEBUG_EDNS0, "EDE: EXTRA-TEXT: %.*s", optlen - 2, p + 2);
			}

			// Advance working pointer
			p += optlen;
		}
		else
		{
			log_debug(DEBUG_EDNS0, "Unknown option %u with length %u", code, optlen);
			// Not implemented, skip this record

			// Advance working pointer
			p += optlen;
		}
	}

	// Debug dump AFTER the parse loop: if our private-client option was present
	// it has been neutralised above, so its per-run MAC is never written to
	// the log (which any log reader could otherwise use to forge attribution).
	if(config.debug.edns0.v.b)
	{
		char *payload = calloc(3*plen + 1, sizeof(char));
		if(payload != NULL)
		{
			for(size_t i = 0; i < plen; i++)
				sprintf(&payload[3*i], "%02X ", pheader[i]);
			log_debug(DEBUG_EDNS0, "pheader: %s (%zu bytes)", payload, plen);
			free(payload);
		}
	}
}
