/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Encrypted-upstream forward proxy
*
*  FTL forwards plaintext DNS to a per-process random loopback tuple in 127.0.0.0/8; this
*  module re-encrypts it to the real resolver over DoT/DoH and hands the answer
*  back. A pool of worker threads shares the armed listeners; each borrows a
*  connection from the per-upstream pool for the exchange, so many queries run
*  concurrently and one slow upstream cannot stall the others. On any TLS failure
*  the query is dropped, not answered, so FTL fails over to the next server
*  instead of ever downgrading to plaintext.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
// killed, thread_names
#include "signals.h"

#include "proxy.h"
#include "registry.h"
#include "tls_client.h"
#include "quic_client.h"
#include "framing.h"
#include "edns_pad.h"
// global config
#include "config/config.h"
// upstream list iteration
#include "webserver/cJSON/cJSON.h"

#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>

// Per-upstream state, one entry per encrypted upstream. Plaintext entries are
// not tracked here - dnsmasq talks to those directly.
struct proxy_up {
	bool active;                    // armed: listener bound and pool ready
	struct upstream_uri uri;        // parsed descriptor
	struct proxy_listener listener; // bound UDP+TCP pair
	struct tls_pool *pool;          // per-upstream TCP pool (DoT/DoH over TLS)
	struct quic_pool *qpool;        // per-upstream QUIC pool (DoH3 only)
	char target[INET_ADDRSTRLEN + 8]; // "127.47.11.N#P", for logging
};

// Transport name for logging. An if-ladder (not a switch) dodges -Wswitch-enum;
// UST_PLAIN never reaches the proxy.
static const char *ustype_name(enum ustype t)
{
	if(t == UST_DOT)  return "DoT";
	if(t == UST_DOH)  return "DoH";
	if(t == UST_DOH3) return "DoH3";
	return "?";
}

// Route one exchange to this upstream's transport: DoH3 over QUIC, else the TCP
// TLS pool. Returns the answer length or -1.
static ssize_t up_exchange(struct proxy_up *up, const uint8_t *query, size_t qlen,
                           uint8_t *answer, size_t answer_sz)
{
	if(up->uri.type == UST_DOH3)
		return quic_pool_exchange(up->qpool, query, qlen, answer, answer_sz);
	return tls_pool_exchange(up->pool, query, qlen, answer, answer_sz);
}

static struct proxy_up g_ups[DOTDOH_MAX_UPSTREAMS];
static int g_nups = 0;       // number of encrypted upstreams recorded
static int g_nactive = 0;    // number of those successfully armed
static bool g_armed = false; // init runs once per process

// Auto-scaled worker pool. Workers are I/O-bound, so we run more than one per
// core; each per-upstream connection pool is capped separately. Both are derived
// once from the hardware in compute_scale(), never user-configured.
#define WORKERS_MIN   4
#define WORKERS_MAX   64
#define POOLCONN_MIN   2
#define POOLCONN_MAX  32
static pthread_t g_workers[WORKERS_MAX];
static int g_nworkers = 0;
static int g_pool_k = POOLCONN_MIN;

// TCP connections currently pinning a worker in handle_tcp(). Any local process
// can open the loopback listener and hold its worker up to PROXY_CONN_TIMEOUT_MS,
// so cap concurrent TCP at g_tcp_cap and drop the rest (dnsmasq reconnects),
// keeping slow peers from starving the UDP fast path.
static _Atomic int g_tcp_inflight = 0;
static int g_tcp_cap = WORKERS_MIN;

// Tuple -> upstream lookup, precomputed once at arm time so the per-query hot
// path (findUpstreamID) is an O(1) array access, not a config walk + URI parse.
static char g_uri_map[DOTDOH_MAX_UPSTREAMS][256];
static int  g_uri_port[DOTDOH_MAX_UPSTREAMS];
static int  g_uri_count = 0;

// Monotonic clock in milliseconds, for the per-request deadline and the stats
// summary interval.
static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

// Derive the worker count and per-upstream connection cap from the hardware,
// with a RAM guard: each connection costs ~170 KiB (buffers + OpenSSL state), so
// keep the total budget under ~5% of physical RAM lest a low-memory box swap.
static void compute_scale(int nupstreams)
{
	int ncpu = get_nprocs();
	if(ncpu < 1)
		ncpu = 1;

	int w = 4 * ncpu;
	if(w < WORKERS_MIN) w = WORKERS_MIN;
	if(w > WORKERS_MAX) w = WORKERS_MAX;

	int k = 2 * ncpu;
	if(k < POOLCONN_MIN) k = POOLCONN_MIN;
	if(k > POOLCONN_MAX) k = POOLCONN_MAX;

	struct sysinfo si;
	if(nupstreams > 0 && sysinfo(&si) == 0)
	{
		const uint64_t ram = (uint64_t)si.totalram * si.mem_unit;
		const uint64_t budget = (ram / 20u) / (170u * 1024u); // 5% / ~170 KiB
		int kmax = (int)(budget / (uint64_t)nupstreams);
		if(kmax < POOLCONN_MIN)
			kmax = POOLCONN_MIN;
		if(k > kmax)
			k = kmax;
	}

	g_nworkers = w;
	g_pool_k = k;
}

// Put a listener fd in non-blocking mode so many workers can share the poll set:
// after poll() wakes them all, the losers of the recvfrom()/accept4() race get
// EAGAIN instead of blocking.
static void set_nonblock(int fd)
{
	const int flags = fcntl(fd, F_GETFL, 0);
	if(flags >= 0)
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void *worker_main(void *val);

// Arm one loopback listener pair per encrypted upstream, build its pool, and
// start the shared workers. Runs once per process, after dnsmasq startup so the
// fresh listener fds cannot collide with dnsmasq's.
void dotdoh_init(void)
{
	// Arm exactly once per process (upstreams are RESTART_FTL, so the set
	// cannot change without a full restart).
	if(g_armed)
		return;
	g_armed = true;

	cJSON *ups = config.dns.upstreams.v.json;
	if(ups == NULL || cJSON_GetArraySize(ups) <= 0)
		return;

	// Count encrypted upstreams first: the TLS stack is only brought up if at
	// least one exists, and the count feeds the RAM guard in compute_scale().
	int n_encrypted = 0;
	cJSON *it = NULL;
	cJSON_ArrayForEach(it, ups)
		if(it != NULL && cJSON_IsString(it) && it->valuestring != NULL &&
		   (strncmp(it->valuestring, "tls://", 6) == 0 ||
		    strncmp(it->valuestring, "https://", 8) == 0 ||
		    strncmp(it->valuestring, "h3://", 5) == 0))
			n_encrypted++;
	if(n_encrypted == 0)
		return; // fail-closed: nothing to arm, no plaintext fallback

	const bool tls_ok = tls_client_global_init(config.dns.upstreamCA.v.s);
	if(!tls_ok)
		log_err("dotdoh: TLS init failed - encrypted upstreams are disabled");

	// Bring up the QUIC context for h3:// (separate OpenSSL ctx, same trust store).
	// Failure fails closed: h3:// pools stay un-armed, DoT/DoH keep working. No-op
	// stub without QUIC/nghttp3.
	quic_client_global_init(config.dns.upstreamCA.v.s);

	compute_scale(n_encrypted);

	// Walk the upstreams in order. Each encrypted entry consumes one slot (enc)
	// matching the tuple the config layer emitted, so a disabled entry keeps later
	// ones aligned.
	int enc = 0;
	cJSON_ArrayForEach(it, ups)
	{
		if(it == NULL || !cJSON_IsString(it) || it->valuestring == NULL)
			continue;

		struct upstream_uri u;
		if(!parse_upstream_uri(it->valuestring, &u) || u.type == UST_PLAIN)
			continue; // plaintext -> dnsmasq handles it directly

		if(g_nups >= DOTDOH_MAX_UPSTREAMS)
			break;

		// Record the tuple->upstream mapping (slot enc's randomised tuple) so the
		// API can resolve it without re-walking the config per query.
		strncpy(g_uri_map[enc], it->valuestring, sizeof(g_uri_map[enc]) - 1);
		g_uri_map[enc][sizeof(g_uri_map[enc]) - 1] = '\0';
		g_uri_port[enc] = u.port;
		g_uri_count = enc + 1;

		struct proxy_up *up = &g_ups[g_nups++];
		memset(up, 0, sizeof(*up));
		up->uri = u;

		// Bind the same randomised tuple dnsmasq was pointed at (shared table). If we
		// cannot own it the upstream stays disabled and the forward gate skips it -
		// queries fail over, never downgrade to plaintext.
		if(tls_ok && proxy_listener_bind(enc, &up->listener))
		{
			// DoH3 uses the QUIC pool; DoT/DoH share the TCP pool - only one is non-NULL.
			bool pool_ok;
			if(u.type == UST_DOH3)
			{
				up->qpool = quic_pool_new(&u, g_pool_k);
				pool_ok = (up->qpool != NULL);
			}
			else
			{
				up->pool = tls_pool_new(&u, g_pool_k);
				pool_ok = (up->pool != NULL);
			}
			if(pool_ok)
			{
				snprintf(up->target, sizeof(up->target), "%s#%d",
				         up->listener.ip, up->listener.port);
				up->active = true;
				g_nactive++;
				log_info("dotdoh: %s upstream %s armed on %s",
				         ustype_name(u.type), u.verify_name, up->target);
			}
			else
				proxy_listener_close(&up->listener);
		}
		if(!up->active)
		{
			char ip[INET_ADDRSTRLEN];
			dotdoh_tuple_ip(enc, ip, sizeof(ip));
			log_warn("dotdoh: encrypted upstream %s could not be armed (%s#%d)",
			         u.verify_name, ip, dotdoh_tuple_port(enc));
		}
		enc++;
	}

	if(g_nactive == 0)
	{
		// compute_scale() set an intended worker count; with nothing armed we spawn
		// none, so clear it or dotdoh_cleanup() would pthread_join() zeroed handles.
		g_nworkers = 0;
		return;
	}

	// Share the armed listeners across the worker pool: make them non-blocking
	// and spawn the workers. If a spawn fails we still run with the workers we
	// have (or none, in which case queries fail closed).
	for(int i = 0; i < g_nups; i++)
	{
		if(!g_ups[i].active)
			continue;
		set_nonblock(g_ups[i].listener.udp_fd);
		set_nonblock(g_ups[i].listener.tcp_fd);
	}

	// Reserve roughly a quarter of the workers for the UDP fast path; the
	// remainder may serve TCP concurrently (see g_tcp_inflight). Publish this
	// before any worker is created so a worker cannot read it mid-write.
	g_tcp_cap = g_nworkers - (g_nworkers / 4 > 0 ? g_nworkers / 4 : 1);
	if(g_tcp_cap < 1)
		g_tcp_cap = 1;

	for(int i = 0; i < g_nworkers; i++)
	{
		if(pthread_create(&g_workers[i], NULL, worker_main, NULL) != 0)
		{
			log_err("dotdoh: could not start worker %d/%d", i + 1, g_nworkers);
			g_nworkers = i; // only the ones we actually started
			break;
		}
	}

	log_info("dotdoh: %d encrypted upstream(s) armed, %d worker(s), up to %d conn(s) each",
	         g_nactive, g_nworkers, g_pool_k);
}

int dotdoh_count(void)
{
	return g_nactive;
}

bool dotdoh_uri_for_listener(const char *ip, int port, char *out, size_t outlen, int *real_port)
{
	if(ip == NULL || out == NULL || outlen == 0)
		return false;

	// Cheap prefix reject first, so plaintext upstreams (the common case) cost
	// almost nothing on the per-query hot path: only our 127.0.0.0/8 tuples match.
	if(strncmp(ip, "127.", 4) != 0)
		return false;
	struct in_addr a4;
	if(inet_pton(AF_INET, ip, &a4) != 1)
		return false;
	const uint32_t addr = ntohl(a4.s_addr);

	// Find the slot whose randomised tuple matches (ip,port); the numbering is the
	// same the dnsmasq.conf emission and proxy bind use.
	for(int i = 0; i < g_uri_count; i++)
	{
		if(dotdoh_tuple_addr(i) != addr || dotdoh_tuple_port(i) != port)
			continue;
		strncpy(out, g_uri_map[i], outlen - 1);
		out[outlen - 1] = '\0';
		if(real_port != NULL)
			*real_port = g_uri_port[i];
		return true;
	}
	return false;
}

// Called from dnsmasq's forward path (via FTL_is_forward_available) for every
// prospective forward. Only our own encrypted-upstream tuples are gated - allowed
// only when that upstream is armed; anything else is always available. This is
// what makes forwarding fail-closed: no plaintext to a tuple the proxy does not own.
bool dotdoh_forward_available(uint32_t addr_h, int port)
{
	for(int i = 0; i < g_nups; i++)
		if(dotdoh_tuple_addr(i) == addr_h && dotdoh_tuple_port(i) == port)
			return g_ups[i].active;
	return true;
}

// True for an IPv4 loopback source (127.0.0.0/8). Everything else is rejected:
// only dnsmasq on this host is a legitimate client, and this also closes any
// exposure via net.ipv4.conf.*.route_localnet.
static bool is_loopback_v4(const struct sockaddr_in *sa)
{
	return sa->sin_family == AF_INET &&
	       (ntohl(sa->sin_addr.s_addr) >> 24) == 127;
}

// Overall budget (ms) for one TCP request cycle (read query + write answer).
#define PROXY_REQUEST_TIMEOUT_MS 10000

// Per-connection caps so one accepted TCP connection cannot monopolize a worker
// (any local process can reach the loopback listener). Generous for dnsmasq's
// pipelining; on hitting either, the connection is closed and dnsmasq reconnects.
#define PROXY_CONN_MAX_QUERIES 64
#define PROXY_CONN_TIMEOUT_MS  60000

// Read exactly len bytes (or fail), giving up once deadline passes.
static bool read_full(int fd, uint8_t *buf, size_t len, uint64_t deadline)
{
	size_t off = 0;
	while(off < len)
	{
		if(now_ms() >= deadline)
			return false;
		const ssize_t r = read(fd, buf + off, len - off);
		if(r < 0 && errno == EINTR)
			continue;
		if(r <= 0)
			return false;
		off += (size_t)r;
	}
	return true;
}

// Write exactly len bytes (or fail), giving up once deadline passes.
static bool write_full(int fd, const uint8_t *buf, size_t len, uint64_t deadline)
{
	size_t off = 0;
	while(off < len)
	{
		if(now_ms() >= deadline)
			return false;
		const ssize_t w = write(fd, buf + off, len - off);
		if(w < 0 && errno == EINTR)
			continue;
		if(w <= 0)
			return false;
		off += (size_t)w;
	}
	return true;
}

// IPv4 UDP payload cap (65535 - 20 IP - 8 UDP). A DNS answer above this cannot be
// sent in a single loopback UDP datagram.
#define UDP4_MAX_PAYLOAD 65507u

// Build a minimal TC=1 (truncated) response - the DNS header plus the question
// section, with the answer/authority/additional counts cleared - from a full
// answer too large for a UDP datagram, so dnsmasq retries the query over TCP.
// Returns the length written, or 0 if the answer is too short/malformed to parse.
static size_t dns_truncated_response(const uint8_t *ans, size_t alen,
                                     uint8_t *out, size_t out_sz)
{
	if(alen < 12)
		return 0;
	const unsigned qd = ((unsigned)ans[4] << 8) | ans[5];
	size_t off = 12;
	for(unsigned q = 0; q < qd && off < alen; q++)
	{
		// Walk the QNAME labels; compression is not legal in a question.
		while(off < alen && ans[off] != 0)
		{
			if((ans[off] & 0xC0) != 0)
				return 0;
			off += (size_t)ans[off] + 1;
		}
		off += 1 + 4; // root label + QTYPE + QCLASS
	}
	if(off > alen || off > out_sz)
		return 0;
	memcpy(out, ans, off);
	out[2] |= 0x02;                      // set TC
	out[6] = out[7] = 0;                 // ANCOUNT = 0
	out[8] = out[9] = 0;                 // NSCOUNT = 0
	out[10] = out[11] = 0;               // ARCOUNT = 0
	return off;
}

// A single UDP query from dnsmasq: receive, forward over TLS, send the answer
// back to the same source. On failure we drop it (see the file header).
static void handle_udp(struct proxy_up *up)
{
	// 64 KiB each - too large for the worker's thread stack, declared
	// thread-local instead (one set per worker thread).
	static _Thread_local uint8_t query[DNS_MSG_MAX];
	static _Thread_local uint8_t answer[DNS_MSG_MAX];
	struct sockaddr_in src;
	socklen_t sl = sizeof(src);
	// Non-blocking listener: another worker may have taken the datagram, in
	// which case recvfrom() returns EAGAIN (n < 0) and we simply return.
	const ssize_t n = recvfrom(up->listener.udp_fd, query, sizeof(query), 0,
	                           (struct sockaddr *)&src, &sl);
	if(n <= 0)
		return;
	if(!is_loopback_v4(&src))
		return;

	// The requestor's advertised UDP payload size, read before padding. A stream
	// upstream (DoT/DoH/DoH3) is not bound by it (RFC 7766) and may return a full
	// answer, but we are emulating a DNS server to dnsmasq and must honour it: an
	// answer above it (capped at the IP datagram limit) is TC-truncated so dnsmasq
	// retries over TCP, rather than sent whole and silently byte-chopped by
	// dnsmasq's receive buffer (breaking DNSSEC and large answers).
	const uint16_t udp_max = edns_query_udp_size(query, (size_t)n);
	const size_t max_reply = udp_max < UDP4_MAX_PAYLOAD ? udp_max : UDP4_MAX_PAYLOAD;

	// Pad the query to a block boundary (RFC 8467) before it is encrypted, so the
	// ciphertext size no longer leaks the query. Only this encrypted leg is
	// padded; the plaintext dnsmasq spoke to us over loopback is left untouched.
	const size_t qlen = edns_pad_query(query, (size_t)n, sizeof(query));
	const ssize_t a = up_exchange(up, query, qlen, answer, sizeof(answer));
	if(a < 0)
		return; // drop -> dnsmasq times out and fails over

	if((size_t)a > max_reply)
	{
		// Reply TC=1 so dnsmasq retries over TCP, where the length-prefixed leg
		// carries the whole answer.
		uint8_t tc[512];
		const size_t tlen = dns_truncated_response(answer, (size_t)a, tc, sizeof(tc));
		if(tlen > 0)
			sendto(up->listener.udp_fd, tc, tlen, 0, (struct sockaddr *)&src, sl);
		return;
	}
	sendto(up->listener.udp_fd, answer, (size_t)a, 0, (struct sockaddr *)&src, sl);
}

// A TCP connection from dnsmasq: length-prefixed queries in, length-prefixed
// answers out, until the peer closes or something fails.
static void handle_tcp(struct proxy_up *up)
{
	struct sockaddr_in peer;
	socklen_t pl = sizeof(peer);
	// accept4() with SOCK_CLOEXEC (not inherited from the listener), so the accepted
	// fd does not leak across FTL's execvp() self-restart. A non-blocking listener
	// may return EAGAIN if another worker won the accept - just return.
	const int cfd = accept4(up->listener.tcp_fd, (struct sockaddr *)&peer, &pl, SOCK_CLOEXEC);
	if(cfd < 0)
	{
		// On fd exhaustion the connection stays queued and poll() would wake us
		// again at once, so back off briefly to avoid a busy-spin.
		if(errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM)
			poll(NULL, 0, 100);
		return;
	}
	if(!is_loopback_v4(&peer))
	{
		close(cfd);
		return;
	}

	// Admission control: keep TCP-pinned workers under a ceiling so a burst of slow
	// (but valid) loopback peers cannot occupy the whole pool. Over the limit we
	// close immediately; dnsmasq reconnects or falls back to UDP.
	if(atomic_fetch_add_explicit(&g_tcp_inflight, 1, memory_order_relaxed) >= g_tcp_cap)
	{
		atomic_fetch_sub_explicit(&g_tcp_inflight, 1, memory_order_relaxed);
		close(cfd);
		return;
	}

	// Bound how long we wait on this connection so a stalled peer cannot pin a
	// worker thread. Both directions are bounded: without SO_SNDTIMEO a peer that
	// stops reading would block write_full() forever.
	const struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	// See handle_udp(): keep these 64 KiB buffers off the thread stack.
	static _Thread_local uint8_t query[DNS_MSG_MAX];
	static _Thread_local uint8_t answer[DNS_MSG_MAX];
	static _Thread_local uint8_t out[2 + DNS_MSG_MAX];
	// Bound one connection's hold on a worker: any local process can reach the
	// listener, so cap both total lifetime and query count or a peer could stream
	// valid queries forever and starve other work. dnsmasq simply reconnects.
	const uint64_t conn_deadline = now_ms() + PROXY_CONN_TIMEOUT_MS;
	int served = 0;
	for(;;)
	{
		// A long-lived-but-valid connection must not delay shutdown by up to
		// PROXY_CONN_TIMEOUT_MS: bail out as soon as terminate is signalled.
		BREAK_IF_KILLED();
		if(served >= PROXY_CONN_MAX_QUERIES || now_ms() >= conn_deadline)
			break;

		// Separate read and write budgets, each fresh: the upstream exchange
		// between them has its own deadline, so sharing one budget could let a
		// slow-but-valid exchange expire it before the answer is even written.
		const uint64_t rdeadline = now_ms() + PROXY_REQUEST_TIMEOUT_MS;

		uint8_t lenbuf[2];
		if(!read_full(cfd, lenbuf, 2, rdeadline))
			break;
		const size_t qlen = ((size_t)lenbuf[0] << 8) | (size_t)lenbuf[1];
		if(qlen == 0 || qlen > DNS_MSG_MAX)
			break;

		if(!read_full(cfd, query, qlen, rdeadline))
			break;

		// Pad before encrypting (see handle_udp()); the loopback leg stays plain.
		const size_t plen = edns_pad_query(query, qlen, sizeof(query));
		const ssize_t a = up_exchange(up, query, plen, answer, sizeof(answer));
		if(a < 0)
			break; // drop: closing the connection makes dnsmasq retry/fail over

		out[0] = (uint8_t)(((size_t)a >> 8) & 0xff);
		out[1] = (uint8_t)((size_t)a & 0xff);
		memcpy(out + 2, answer, (size_t)a);
		const uint64_t wdeadline = now_ms() + PROXY_REQUEST_TIMEOUT_MS;
		if(!write_full(cfd, out, (size_t)a + 2, wdeadline))
			break;
		served++;
	}
	close(cfd);
	atomic_fetch_sub_explicit(&g_tcp_inflight, 1, memory_order_relaxed);
}

// Periodic per-upstream keep-alive/resumption summary, emitted only under
// debug.dotdoh. Single-flighted so exactly one worker prints per interval. The
// interval is short because it only fires when the (verbose) debug flag is on.
#define SUMMARY_INTERVAL_MS 10000
static pthread_mutex_t g_summary_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_last_summary_ms = 0;

static void emit_summary(void)
{
	for(int i = 0; i < g_nups; i++)
	{
		if(!g_ups[i].active)
			continue;
		struct dotdoh_stats s;
		if(g_ups[i].uri.type == UST_DOH3)
		{
			if(g_ups[i].qpool == NULL)
				continue;
			quic_pool_get_stats(g_ups[i].qpool, &s);
		}
		else
		{
			if(g_ups[i].pool == NULL)
				continue;
			tls_pool_get_stats(g_ups[i].pool, &s);
		}
		const double avg = s.sessions_closed > 0
		                 ? (double)s.queries_per_session_sum / (double)s.sessions_closed : 0.0;
		log_debug(DEBUG_DOTDOH,
		          "dotdoh[%s]: queries=%llu sessions=%llu avg_reuse=%.1f max_reuse=%llu "
		          "resumed=%llu fresh_cold=%llu full_fallback=%llu opened=%llu reaped=%llu dead_on_reuse=%llu",
		          g_ups[i].uri.verify_name, s.queries_total, s.sessions_closed, avg,
		          s.queries_per_session_max, s.handshakes_resumed, s.handshakes_fresh_cold,
		          s.handshakes_full_fallback, s.conns_opened, s.conns_reaped_idle,
		          s.conns_dead_on_reuse);
	}
}

static void maybe_emit_summary(void)
{
	if(!debug_flags[DEBUG_DOTDOH])
		return;
	if(pthread_mutex_trylock(&g_summary_lock) != 0)
		return; // another worker is handling this tick
	const uint64_t now = now_ms();
	if(now - g_last_summary_ms >= SUMMARY_INTERVAL_MS)
	{
		g_last_summary_ms = now;
		emit_summary();
	}
	pthread_mutex_unlock(&g_summary_lock);
}

// Worker entry: poll every armed listener and service whatever is ready, sharing
// the listeners with the other workers. The armed set never changes after init,
// so the poll set is built once.
static void *worker_main(void *val)
{
	(void)val;
	prctl(PR_SET_NAME, thread_names[DOTDOH], 0, 0, 0);

	struct pollfd fds[2 * DOTDOH_MAX_UPSTREAMS];
	struct proxy_up *owner[2 * DOTDOH_MAX_UPSTREAMS];
	bool is_tcp[2 * DOTDOH_MAX_UPSTREAMS];
	nfds_t n = 0;
	for(int i = 0; i < g_nups; i++)
	{
		if(!g_ups[i].active)
			continue;
		fds[n].fd = g_ups[i].listener.udp_fd; fds[n].events = POLLIN; owner[n] = &g_ups[i]; is_tcp[n] = false; n++;
		fds[n].fd = g_ups[i].listener.tcp_fd; fds[n].events = POLLIN; owner[n] = &g_ups[i]; is_tcp[n] = true;  n++;
	}

	while(!killed)
	{
		const int r = poll(fds, n, 1000);
		if(r <= 0)
		{
			maybe_emit_summary(); // timeout or interrupt: housekeeping, re-check killed
			continue;
		}
		for(nfds_t k = 0; k < n; k++)
		{
			if(!(fds[k].revents & POLLIN))
				continue;
			if(is_tcp[k])
				handle_tcp(owner[k]);
			else
				handle_udp(owner[k]);
		}
	}
	return NULL;
}

void dotdoh_cleanup(void)
{
	// Stop the worker pool first. terminate_threads() already set `killed`, so the
	// workers are on their way out; break them from a blocking poll by shutting the
	// listeners, then join. Plain join is safe as every blocking point is
	// deadline-bounded (poll 1 s, in-flight exchange <=10 s), so no pthread_cancel -
	// which could re-lock a pool mutex mid-wait and deadlock the teardown below.
	killed = true;
	for(int i = 0; i < g_nups; i++)
		if(g_ups[i].active)
		{
			shutdown(g_ups[i].listener.udp_fd, SHUT_RDWR);
			shutdown(g_ups[i].listener.tcp_fd, SHUT_RDWR);
		}
	for(int i = 0; i < g_nworkers; i++)
		pthread_join(g_workers[i], NULL);
	g_nworkers = 0;

	// A final statistics summary on the way out, if anyone is watching.
	if(debug_flags[DEBUG_DOTDOH])
		emit_summary();

	// Now no worker touches the pools; tear them down.
	for(int i = 0; i < g_nups; i++)
	{
		if(g_ups[i].pool != NULL)
			tls_pool_free(g_ups[i].pool);
		if(g_ups[i].qpool != NULL)
			quic_pool_free(g_ups[i].qpool);
		if(g_ups[i].active)
			proxy_listener_close(&g_ups[i].listener);
		memset(&g_ups[i], 0, sizeof(g_ups[i]));
	}
	g_nups = 0;
	g_nactive = 0;
	g_armed = false;
	g_uri_count = 0;
	tls_client_global_free();
	quic_client_global_free();
}
