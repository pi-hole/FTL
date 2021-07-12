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
#include "config/config.h"
#include "datastructure.h"
#include "shmem.h"

// EDNS(0) Client Subnet [Optional, RFC7871]
#define EDNS0_ECS EDNS0_OPTION_CLIENT_SUBNET

// EDN(0) COOKIE [Standard, RFC7873]
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

void FTL_parse_pseudoheaders(struct dns_header *header, size_t n, union mysockaddr *peer, ednsData *edns)
{
	int is_sign;
	size_t plen;
	unsigned char *pheader, *sizep;

	// Extract additional record A.K.A. pseudoheader
	if (!(pheader = find_pseudoheader(header, n, &plen, &sizep, &is_sign, NULL)))
		return;

	// Debug logging
	if(config.debug & DEBUG_EDNS0)
		for(unsigned int i = 0; i < plen; i++)
			log_debug(DEBUG_EDNS0, "EDNS(0) pheader[%i] = 0x%02x", i, pheader[i]);

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
	log_debug(DEBUG_EDNS0, "EDNS(0) requestor's UDP payload size: %u bytes", class);
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
	unsigned char edns0_version = (ttl >> 16) % 0xFF;
	if(edns0_version != 0x00)
		return;

	size_t offset; // The header is 11 bytes before the beginning of OPTION-DATA
	while ((offset = (p - pheader - 11u)) < rdlen)
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
		log_debug(DEBUG_EDNS0, "EDNS(0) code %u, optlen %u (bytes %zu - %zu of %u)",
		          code, optlen, offset, offset + optlen, rdlen);

		if (code == EDNS0_ECS && config.edns0_ecs)
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
			union all_addr addr = {{ 0 }};
			if(family == 1 && optlen == 4 + sizeof(addr.addr4.s_addr)) // IPv4
				memcpy(&addr.addr4.s_addr, p, sizeof(addr.addr4.s_addr));
			else if(family == 2 && optlen == 4 + sizeof(addr.addr6.s6_addr)) // IPv6
				memcpy(addr.addr6.s6_addr, p, sizeof(addr.addr6.s6_addr));
			else
				continue;

			// Advance working pointer (we already walked 4 bytes above)
			p += optlen - 4;

			char ipaddr[ADDRSTRLEN] = { 0 };
			inet_ntop(family == 1 ? AF_INET : AF_INET6, &addr.addr4.s_addr, ipaddr, sizeof(ipaddr));

			// Only use /32 (IPv4) and /128 (IPv6) addresses
			if(!(family == 1 && source_netmask == 32) &&
			   !(family == 2 && source_netmask == 128))
				continue;

			// Copy data to edns struct
			strncpy(edns->client, ipaddr, ADDRSTRLEN);
			edns->client[ADDRSTRLEN-1] = '\0';

			// Only set the address as useful when it is not the
			// loopback address of the distant machine (127.0.0.0/8 or ::1)
			if((family == 1 && (ntohl(addr.addr4.s_addr) & 0xFF000000) == 0x7F000000) ||
			   (family == 2 && IN6_IS_ADDR_LOOPBACK(&addr.addr6)))
			{
				log_debug(DEBUG_EDNS0, "EDNS(0) CLIENT SUBNET: Skipped %s/%u (IPv%u loopback address)",
				          ipaddr, source_netmask, family == 1 ? 4 : 6);
			}
			else
			{
				edns->client_set = true;
				log_debug(DEBUG_EDNS0, "EDNS(0) CLIENT SUBNET: %s/%u - OK (IPv%u)",
				          ipaddr, source_netmask, family == 1 ? 4 : 6);
			}
		}
		else if(code == EDNS0_COOKIE && optlen == 8)
		{
			// EDNS(0) COOKIE client
			unsigned char client_cookie[8];
			memcpy(client_cookie, p, 8);
			if(config.debug & DEBUG_EDNS0)
			{
				char pretty_client_cookie[8*2 + 1]; // client: fixed length
				char *pp = pretty_client_cookie;
				for(unsigned int j = 0; j < 8; j++)
					pp += sprintf(pp, "%02X", client_cookie[j]);
				log_debug(DEBUG_EDNS0, "EDNS(0) COOKIE (client-only): %s",
				     pretty_client_cookie);
			}

			// Advance working pointer
			p += 8;
		}
		else if(code == EDNS0_COOKIE && optlen >= 16 && optlen <= 40)
		{
			// EDNS(0) COOKIE client + server
			unsigned char client_cookie[8];
			memcpy(client_cookie, p, 8);

			unsigned short server_cookie_len = optlen - 8;
			unsigned char server_cookie[server_cookie_len];
			memcpy(server_cookie, p + 8u, server_cookie_len);
			if(config.debug & DEBUG_EDNS0)
			{
				char pretty_client_cookie[8*2 + 1]; // client: fixed length
				char *pp = pretty_client_cookie;
				for(unsigned int j = 0; j < 8; j++)
					pp += sprintf(pp, "%02X", client_cookie[j]);
				char pretty_server_cookie[server_cookie_len*2 + 1u]; // server: variable length
				pp = pretty_server_cookie;
				for(unsigned int j = 0; j < server_cookie_len; j++)
					pp += sprintf(pp, "%02X", server_cookie[j]);
				log_debug(DEBUG_EDNS0, "EDNS(0) COOKIE (client + server): %s (client), %s (server, %u bytes)",
				     pretty_client_cookie, pretty_server_cookie, server_cookie_len);
			}

			// Advance working pointer
			p += optlen;
		}
		else if(code == EDNS0_MAC_ADDR_BYTE && optlen == 6)
		{
			// EDNS(0) MAC address (BYTE format)
			memcpy(edns->mac_byte, p, sizeof(edns->mac_byte));
			print_mac(edns->mac_text, (unsigned char*)edns->mac_byte, sizeof(edns->mac_byte));
			edns->mac_set = true;
			log_debug(DEBUG_EDNS0, "EDNS(0) MAC address (BYTE format): %s", edns->mac_text);

			// Advance working pointer
			p += 6;
		}
		else if(code == EDNS0_MAC_ADDR_TEXT && optlen == 17)
		{
			// EDNS(0) MAC address (TEXT format)
			memcpy(edns->mac_text, p, 17);
			edns->mac_text[17] = '\0';
			if(sscanf(edns->mac_text, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			          &edns->mac_byte[0],
			          &edns->mac_byte[1],
			          &edns->mac_byte[2],
			          &edns->mac_byte[3],
			          &edns->mac_byte[4],
			          &edns->mac_byte[5]) == 6)
			{
				edns->mac_set = true;
				log_debug(DEBUG_EDNS0, "EDNS(0) MAC address (TEXT format): %s", edns->mac_text);
			}
			else
			{
				log_debug(DEBUG_EDNS0, "         Received MAC address has invalid format!");
			}

			// Advance working pointer
			p += 17;
		}
		else if(code == EDNS0_MAC_ADDR_BASE64 && optlen == 8)
		{
			// EDNS(0) MAC address (BASE format)
			log_debug(DEBUG_EDNS0, "EDNS(0) MAC address (BASE64 format): NOT IMPLEMENTED");

			// Advance working pointer
			p += 8;
		}
		else if(code == EDNS0_CPE_ID)
		{
			// EDNS(0) CPE-ID
			unsigned char payload[optlen + 1u]; // variable length
			memcpy(payload, p, optlen);
			payload[optlen] = '\0';
			if(config.debug & DEBUG_EDNS0)
			{
				char pretty_payload[optlen*5 + 1u];
				char *pp = pretty_payload;
				for(unsigned int j = 0; j < optlen; j++)
					pp += sprintf(pp, "0x%02X ", payload[j]);
				pretty_payload[optlen*5 - 1] = '\0'; // Truncate away the trailing whitespace
				log_debug(DEBUG_EDNS0, "EDNS(0) CPE-ID (payload size %u): \"%s\" (%s)",
				     optlen, payload, pretty_payload);
			}

			// Advance working pointer
			p += optlen;
		}
		else
		{
			log_debug(DEBUG_EDNS0, "EDNS(0):n option %u with length %u", code, optlen);
			// Not implemented, skip this record

			// Advance working pointer
			p += optlen;
		}
	}
}