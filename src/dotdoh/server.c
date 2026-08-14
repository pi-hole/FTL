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
#include <time.h>

// Defined in dnsmasq_interface.c. Declared here rather than including
// dnsmasq_interface.h, which is not self-contained: its prototypes reference
// dnsmasq types this module deliberately does not pull in.
unsigned int dnsmasq_max_tcp_children(void) __attribute__ ((pure));
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
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

// Shared pool of connected loopback sockets for the DoT and DoQ reactors.
//
// dnsmasq forks a child per TCP connection, so tying one loopback socket to each
// inbound connection (DoT) or to each in-flight stream (DoQ) makes the number of
// dnsmasq children scale with client behaviour: a client that opens a connection
// per query forks one child per query, and a burst of them exhausts dnsmasq's
// child slots, at which point queries are read but never answered. Pooling the
// sockets decouples the two: a keep-alive socket is reused across unrelated
// client connections and streams, so a client that opens a connection per query
// no longer forks a child per query. Note this bounds the IDLE cache, not the
// number of sockets in flight - concurrency is capped by the reactors' own
// stream/connection limits, not by the pool size.
//
// The sockets are non-blocking because both reactors drive them from their poll
// set. Both are single-threaded but they are two different threads, so the pool
// is mutex-guarded; contention is a couple of pointer moves per query.
// Upper bound on the array; the number actually retained follows the derived
// concurrency cap (see pool_keep_max()). Keeping the pool as large as the cap
// means a query at full concurrency always finds a warm socket, so no fork
// churn: the children the cap allows are simply resident rather than being
// created and destroyed.
// Bound on a blocking loopback exchange, so a slow dnsmasq child cannot pin a
// webserver worker (and a concurrency slot) for its full 300 s lifetime.
#define LOOPBACK_IO_TIMEOUT_S 5
#define LOOPBACK_POOL_SLOTS 64
static pthread_mutex_t pool_lock = PTHREAD_MUTEX_INITIALIZER;
static int pool_fds[LOOPBACK_POOL_SLOTS];
static int pool_n = 0;

// Children to leave dnsmasq for plain TCP queries and DNSSEC fallback, which
// draw on the same pool. Encrypted listeners get the rest.
#define LOOPBACK_RESERVE 20
// Queries currently handed to dnsmasq and not yet finished, across both reactors.
static unsigned int inflight = 0;
// Refusals since the last summary; logged at most once a minute so a sustained
// overload cannot flood the log with one line per query.
static unsigned int refused_total = 0;
static time_t refused_since = 0;

// Concurrent in-flight queries the encrypted listeners may hand to dnsmasq.
// Derived rather than configured, so raising dnsmasq's --max-tcp-connections
// raises this too, with no second setting to keep in step.
static unsigned int loopback_cap(void)
{
	const unsigned int max = dnsmasq_max_tcp_children();
	return max > LOOPBACK_RESERVE ? max - LOOPBACK_RESERVE : 1;
}

// How many idle sockets to keep warm. Matching the cap removes the churn window
// a smaller pool would leave, and costs nothing extra: a warm socket and an
// in-flight one each hold exactly one dnsmasq child, so both are already
// accounted for by the cap.
static unsigned int pool_keep_max(void)
{
	const unsigned int cap = loopback_cap();
	return cap < LOOPBACK_POOL_SLOTS ? cap : LOOPBACK_POOL_SLOTS;
}

int dotdoh_loopback_take(void)
{
	int fd = -1;
	pthread_mutex_lock(&pool_lock);

	// Every in-flight query occupies one dnsmasq TCP child, pooled or freshly
	// opened, so admission is counted here rather than at the pool boundary.
	const unsigned int cap = loopback_cap();
	if(inflight >= cap)
	{
		const time_t now = time(NULL);
		refused_total++;
		// Report the first refusal at once, then summarise per minute.
		if(refused_since == 0 || now - refused_since >= 60)
		{
			log_warn("dotdoh: refused %u encrypted quer%s - concurrency limit %u of "
			         "dnsmasq's %u TCP children reached",
			         refused_total, refused_total == 1 ? "y" : "ies",
			         cap, dnsmasq_max_tcp_children());
			refused_since = now;
			refused_total = 0;
		}
		pthread_mutex_unlock(&pool_lock);
		return -2;
	}
	inflight++;
	while(pool_n > 0)
	{
		fd = pool_fds[--pool_n];
		// A quiescent socket has nothing to read: dnsmasq only ever writes an
		// answer to a query we sent. So ANY readable byte means the previous
		// borrower did not consume its answer and the byte stream is out of
		// step - reusing it would hand that answer to the next caller as if it
		// were their own. Readable, EOF and error are therefore all fatal here;
		// only "nothing pending" is reusable. A poll() interrupted by a signal
		// tells us nothing either way, so keep the socket rather than bin it.
		struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
		const int pr = poll(&pfd, 1, 0);
		if(pr == 0 || (pr < 0 && errno == EINTR))
			break; // nothing pending: still healthy as far as we can tell
		close(fd);
		fd = -1;
	}
	pthread_mutex_unlock(&pool_lock);
	return fd;
}

void dotdoh_loopback_give(int fd)
{
	if(fd < 0)
		return;
	pthread_mutex_lock(&pool_lock);
	if(inflight > 0)
		inflight--;
	if(pool_n < (int)pool_keep_max())
		pool_fds[pool_n++] = fd;
	else
		close(fd);
	pthread_mutex_unlock(&pool_lock);
}

// Release a socket that must not be reused - a failed or half-written exchange.
// Pairs with dotdoh_loopback_take() exactly as give() does, so the in-flight
// count is released on the error paths too.
void dotdoh_loopback_drop(int fd)
{
	pthread_mutex_lock(&pool_lock);
	if(inflight > 0)
		inflight--;
	pthread_mutex_unlock(&pool_lock);
	if(fd >= 0)
		close(fd);
}

// Open a blocking loopback TCP connection to dnsmasq's own DNS listener, with
// send/recv timeouts so a stall cannot pin the worker (the loopback connect
// itself is effectively instant, so no separate connect timeout is needed).
// Returns the connected fd or -1.
// Pooled sockets are non-blocking because the DoT and DoQ reactors drive them
// from a poll() set. The DoH path below does a blocking exchange instead, so it
// toggles the flag around its use and always hands the socket back non-blocking.
static bool set_blocking(int fd, bool blocking)
{
	const int fl = fcntl(fd, F_GETFL, 0);
	if(fl < 0)
		return false;
	const int want = blocking ? (fl & ~O_NONBLOCK) : (fl | O_NONBLOCK);
	if(fcntl(fd, F_SETFL, want) != 0)
		return false;
	if(!blocking)
		return true;

	// Arm the stall timeouts here rather than trusting where the socket came
	// from: the reactors create theirs without any, correctly, as they never
	// block on them. A blocking exchange on such a socket would otherwise be
	// bounded only by dnsmasq's 300 s child lifetime, pinning a webserver worker
	// and one of the concurrency slots for that whole time.
	const struct timeval tv = { .tv_sec = LOOPBACK_IO_TIMEOUT_S, .tv_usec = 0 };
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
	       setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
}

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

	const struct timeval tv = { .tv_sec = LOOPBACK_IO_TIMEOUT_S, .tv_usec = 0 };
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

	// Borrow a loopback connection for the duration of this query, exactly as the
	// DoT and DoQ reactors do, so all three share one accounted pool of dnsmasq
	// children. Holding one per webserver thread instead would pin a child for the
	// thread's whole life, outside that accounting. dnsmasq closes a connection
	// after its keep-alive limit or an idle period; a stale one makes the exchange
	// fail, so drop it and retry once with a fresh one.
	ssize_t alen = -1;
	for(int attempt = 0; attempt < 2; attempt++)
	{
		bool pooled = true;
		int fd = dotdoh_loopback_take();
		if(fd == -2)
			return -1; // at the concurrency limit; server logs the summary
		if(fd < 0)
		{
			// Pool empty; take() has still reserved our slot in the cap.
			pooled = false;
			fd = loopback_connect();
			if(fd < 0)
			{
				dotdoh_loopback_drop(-1);
				return -1;
			}
		}
		// The exchange below blocks; a pooled socket arrives non-blocking.
		if(pooled && !set_blocking(fd, true))
		{
			dotdoh_loopback_drop(fd);
			continue;
		}
		alen = loopback_exchange(fd, framed, (size_t)flen, answer, answer_sz);
		if(alen <= 0)
		{
			dotdoh_loopback_drop(fd);
			continue; // stale or failed: retry once on a fresh connection
		}
		// Hand it back the way the reactors expect to find it.
		if(set_blocking(fd, false))
			dotdoh_loopback_give(fd);
		else
			dotdoh_loopback_drop(fd);
		break;
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
