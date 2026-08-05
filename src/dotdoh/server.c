/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Inbound DoT/DoH server
*
*  Accepts encrypted DNS from downstream clients, decrypts it, resolves it
*  through dnsmasq while preserving the real client address, and returns the
*  encrypted answer. DoH is served by the front TLS terminator (which already
*  terminates TLS for HTTP/1.1, /2 and /3), so there is no parallel TLS server
*  for it - only DoT (not HTTP) needs its own raw-TLS listener.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "server.h"
// DNS_MSG_MAX
#include "framing.h"
// config.dns.port for the loopback DNS connection
#include "config/config.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
// dotdoh_source_allowed_mode()
#include "source_filter.h"
// edns_pad_response(), edns_has_padding_option()
#include "edns_pad.h"
// get_gateway_name(), MAXIFACESTRLEN
#include "tools/netlink.h"
#include "FTL.h"


// Whether an inbound encrypted-DNS connection from client_ip may be served,
// honouring dns.listeningMode so an on-by-default DoT/DoH server does not turn
// the host into an open resolver. Thin wrapper over the (config-independent,
// unit-tested) predicate in source_filter.c; shared by the DoH handler and the
// DoT listener, both of which launder the real source through a loopback
// handoff so dnsmasq can no longer apply this itself.
bool __attribute__((pure)) dotdoh_doh_enabled(void)
{
	return config.dns.doh.v.b;
}

// The default-gateway interface name for SINGLE/BIND mode with an empty
// dns.interface, resolved exactly once. dotdoh_source_allowed() runs on many
// threads (the DoT reactor, the terminator's detached handler threads, the h3
// workers), so the one-time fill goes through pthread_once - both to avoid a data
// race on the shared buffer and for the happens-before that publishes the write.
static char resolved_iface[MAXIFACESTRLEN] = "";
static pthread_once_t resolved_iface_once = PTHREAD_ONCE_INIT;
static void resolve_gateway_iface(void)
{
	get_gateway_name(resolved_iface);
}

bool dotdoh_source_allowed(const char *client_ip)
{
	const enum listening_mode mode = config.dns.listeningMode.v.listeningMode;
	const char *iface = config.dns.interface.v.s;

	// SINGLE/BIND scope to one interface; with an empty dns.interface dnsmasq binds
	// to the default gateway's interface (see get_gateway_name() in
	// generate_dnsmasq_config()), so resolve the same one here rather than matching
	// every attached subnet. Resolved once - the set is RESTART_FTL, so it cannot
	// change without a restart.
	if((mode == LISTEN_SINGLE || mode == LISTEN_BIND) && iface[0] == '\0')
	{
		pthread_once(&resolved_iface_once, resolve_gateway_iface);
		if(resolved_iface[0] != '\0')
			iface = resolved_iface;
	}

	return dotdoh_source_allowed_mode(mode, client_ip, iface);
}

// Assemble the loopback handoff for one decrypted query. See server.h. Shared by
// the blocking DoH path here and the non-blocking DoT reactor (dot_server.c), so
// the attribution + framing rule lives in exactly one place.
ssize_t dotdoh_prepare_query(const uint8_t *query, size_t qlen,
                             const char *client, const char *dest,
                             uint8_t *framed, size_t framed_cap)
{
	if(qlen == 0 || framed_cap < 2 || qlen > framed_cap - 2)
		return -1;
	// Inject in place after the 2-byte length prefix, so no separate scratch or
	// self-overlapping copy is needed to frame the result.
	memcpy(framed + 2, query, qlen);
	const size_t blen = dotdoh_inject_client(framed + 2, qlen, framed_cap - 2, client, dest);
	// dotdoh_inject_client returns the length unchanged when the client option did
	// not fit (e.g. a query padded to the maximum size). Fail closed rather than
	// forward it unattributed: dnsmasq would otherwise record the loopback handoff
	// source (127.0.0.1) as the client and the real client would bypass its
	// per-client rate limits, groups and logging.
	if(blen <= qlen)
		return -1;
	framed[0] = (uint8_t)(blen >> 8);
	framed[1] = (uint8_t)(blen & 0xFFu);
	return (ssize_t)(2 + blen);
}

// Write an already-framed query (2-byte length prefix + body) on fd and read back
// the length-prefixed answer. Returns the answer length or -1; bounded by the
// socket timeouts set on fd by the caller.
static ssize_t loopback_exchange(int fd, const uint8_t *framed, size_t flen,
                                 uint8_t *answer, size_t answer_sz)
{
	// Write the framed query to dnsmasq, with error checking
	for(size_t off = 0; off < flen;)
	{
		const ssize_t w = write(fd, framed + off, flen - off);
		if(w < 0)
		{
			if(errno == EINTR)
				continue;
			log_debug(DEBUG_RESOLVER, "dotdoh: write to loopback DNS failed: %s", strerror(errno));
			return -1;
		}
		if(w == 0)
		{
			log_debug(DEBUG_RESOLVER, "dotdoh: write to loopback DNS returned 0");
			return -1;
		}
		off += (size_t)w;
	}

	// Read the response length prefix
	uint8_t lenbuf[2];
	for(size_t got = 0; got < 2;)
	{
		const ssize_t r = read(fd, lenbuf + got, 2 - got);
		if(r < 0)
		{
			if(errno == EINTR)
				continue;
			log_debug(DEBUG_RESOLVER, "dotdoh: read length from loopback DNS failed: %s", strerror(errno));
			return -1;
		}
		if(r == 0)
		{
			log_debug(DEBUG_RESOLVER, "dotdoh: loopback DNS connection closed");
			return -1;
		}
		got += (size_t)r;
	}

	const size_t alen = ((size_t)lenbuf[0] << 8) | (size_t)lenbuf[1];
	if(alen == 0 || alen > answer_sz)
	{
		log_debug(DEBUG_RESOLVER, "dotdoh: invalid answer length from loopback DNS: %zu", alen);
		return -1;
	}

	// Read exactly alen bytes. The read size is expressed against the buffer's
	// remaining space (answer_sz - got, with alen <= answer_sz checked above) so
	// the bounds checker can see it never overruns; only alen bytes are ever
	// available on this connection, so got settles at alen.
	for(size_t got = 0; got < alen;)
	{
		const ssize_t r = read(fd, answer + got, answer_sz - got);
		if(r < 0)
		{
			if(errno == EINTR)
				continue;
			log_debug(DEBUG_RESOLVER, "dotdoh: read answer from loopback DNS failed: %s", strerror(errno));
			return -1;
		}
		if(r == 0)
		{
			log_debug(DEBUG_RESOLVER, "dotdoh: loopback DNS closed before sending full answer");
			return -1;
		}
		got += (size_t)r;
	}
	return (ssize_t)alen;
}

// Open a blocking loopback TCP connection to dnsmasq's own DNS listener, with
// send/recv timeouts so a stall cannot pin the worker (the loopback connect
// itself is effectively instant, so no separate connect timeout is needed).
// Returns the connected fd or -1.
static int loopback_connect(void)
{
	const int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if(fd < 0)
		return -1;

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(config.dns.port.v.u16);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	const struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||
	   setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0 ||
	   connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		close(fd);
		return -1;
	}
	return fd;
}

// The reused loopback fd is thread-local. It is closed on a thread-exit
// destructor so it does not outlive its owning thread: native DoH is served from
// the terminator's per-connection detached handler threads (and from restartable
// h3 workers), neither of which lives for the whole life of the process, so
// without this each such thread would leak its loopback fd.
static _Thread_local int up_fd = -1;
static pthread_key_t up_fd_key;
static pthread_once_t up_fd_once = PTHREAD_ONCE_INIT;
static void up_fd_close(void *arg)
{
	(void)arg;
	if(up_fd >= 0) { close(up_fd); up_fd = -1; }
}
static void up_fd_key_init(void)
{
	pthread_key_create(&up_fd_key, up_fd_close);
}

// Resolve the decrypted query through dnsmasq by handing it to our own DNS
// listener over loopback TCP: dnsmasq accepts it as an ordinary TCP DNS query,
// so nothing unsafe (a direct tcp_request()/fork) happens from the calling DoH
// handler thread. `client` (the real downstream client) is carried into dnsmasq
// via a private EDNS option so the query is attributed to it rather than to
// loopback (see dotdoh_inject_client and FTL_parse_pseudoheaders). Returns the
// answer length or -1.
ssize_t dotdoh_server_resolve(const char *client, const char *dest,
                              const uint8_t *query, size_t qlen,
                              uint8_t *answer, size_t answer_sz)
{
	// Assemble the client-attributed, framed query once. dnsmasq then attributes
	// it to that client and answers pi.hole with the reachable address (both
	// trusted only when the query source is loopback; see the EDNS parser and
	// FTL_new_query). Off-stack (a musl thread stack is only 128 KiB, so a 64 KiB
	// frame on it would erase most of the safety margin).
	static _Thread_local uint8_t framed[2 + DNS_MSG_MAX];
	const ssize_t flen = dotdoh_prepare_query(query, qlen, client, dest, framed, sizeof(framed));
	if(flen < 0)
		return -1;

	// Reuse a per-thread loopback connection so dnsmasq forks one child per thread
	// rather than one per query. dnsmasq closes it after its keep-alive limit or an
	// idle period; a stale connection makes the exchange fail, so drop it and retry
	// once with a fresh one. The fd (up_fd) is thread-local and closed by a
	// thread-exit destructor (see above).
	ssize_t alen = -1;
	for(int attempt = 0; attempt < 2; attempt++)
	{
		if(up_fd < 0)
		{
			up_fd = loopback_connect();
			if(up_fd < 0)
				return -1;
			// Arm the thread-exit close for this thread's fd (idempotent).
			pthread_once(&up_fd_once, up_fd_key_init);
			pthread_setspecific(up_fd_key, &up_fd);
		}
		alen = loopback_exchange(up_fd, framed, (size_t)flen, answer, answer_sz);
		if(alen > 0)
			break;
		close(up_fd);
		up_fd = -1;
	}

	// RFC 8467 Sec. 4: pad the answer to a 468-octet boundary so its ciphertext
	// length leaks less, but only when the client's query asked for padding (a
	// server MUST NOT pad otherwise). The original query is checked, not the
	// client-injected copy.
	if(alen > 0 && edns_has_padding_option(query, qlen))
		alen = (ssize_t)edns_pad_response(answer, (size_t)alen, answer_sz);
	return alen;
}

// Decode base64url (RFC 4648 Sec. 5, unpadded; trailing '=' padding tolerated)
// from in[0..inlen) into out (capacity outcap). Returns the decoded length, or
// -1 on an invalid character or overflow.
ssize_t base64url_decode(const char *in, size_t inlen, uint8_t *out, size_t outcap)
{
	uint32_t acc = 0;
	int bits = 0;
	size_t outlen = 0;
	for(size_t i = 0; i < inlen; i++)
	{
		const char c = in[i];
		int v;
		if(c >= 'A' && c <= 'Z') v = c - 'A';
		else if(c >= 'a' && c <= 'z') v = c - 'a' + 26;
		else if(c >= '0' && c <= '9') v = c - '0' + 52;
		else if(c == '-') v = 62;
		else if(c == '_') v = 63;
		else if(c == '=') break; // tolerate trailing padding
		else return -1;
		acc = (acc << 6) | (uint32_t)v;
		bits += 6;
		if(bits >= 8)
		{
			bits -= 8;
			if(outlen >= outcap)
				return -1;
			out[outlen++] = (uint8_t)((acc >> bits) & 0xFFu);
		}
	}
	return (ssize_t)outlen;
}

// Smallest TTL among the Answer-section records of a DNS reply, for the DoH
// Cache-Control max-age (RFC 8484 Sec. 5.1). Bounds-checked walk of the message
// (names may be compressed). Returns 0 - "do not cache" - for a reply with no
// answer records or one that does not parse cleanly.
__attribute__((pure)) uint32_t doh_answer_min_ttl(const uint8_t *msg, size_t len)
{
	if(len < 12)
		return 0;
	const unsigned qdcount = ((unsigned)msg[4] << 8) | msg[5];
	const unsigned ancount = ((unsigned)msg[6] << 8) | msg[7];
	size_t pos = 12;

	// Skip the question section.
	for(unsigned i = 0; i < qdcount; i++)
	{
		while(pos < len)
		{
			const uint8_t l = msg[pos];
			if(l == 0) { pos += 1; break; }
			if((l & 0xC0) == 0xC0) { pos += 2; break; } // compression pointer
			if(l & 0xC0) return 0;                      // reserved label type
			pos += 1 + (size_t)l;
		}
		pos += 4; // QTYPE + QCLASS
		if(pos > len) return 0;
	}

	uint32_t min = 0;
	bool have = false;
	for(unsigned i = 0; i < ancount; i++)
	{
		while(pos < len)
		{
			const uint8_t l = msg[pos];
			if(l == 0) { pos += 1; break; }
			if((l & 0xC0) == 0xC0) { pos += 2; break; }
			if(l & 0xC0) return 0;
			pos += 1 + (size_t)l;
		}
		// TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) then RDATA
		if(pos + 10 > len) return 0;
		uint32_t ttl = ((uint32_t)msg[pos + 4] << 24) | ((uint32_t)msg[pos + 5] << 16) |
		               ((uint32_t)msg[pos + 6] << 8) | (uint32_t)msg[pos + 7];
		const unsigned rdlen = ((unsigned)msg[pos + 8] << 8) | msg[pos + 9];
		pos += 10 + rdlen;
		if(pos > len) return 0;
		if(ttl & 0x80000000u) ttl = 0; // RFC 2181 Sec. 8: MSB-set TTL means 0
		if(!have || ttl < min) { min = ttl; have = true; }
	}
	return have ? min : 0;
}
