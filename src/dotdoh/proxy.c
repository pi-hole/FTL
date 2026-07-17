/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Encrypted-upstream forward proxy
*
*  FTL forwards plaintext DNS to a loopback address in 127.47.11.0/24; this
*  module re-encrypts it to the real resolver over DoT/DoH and hands the answer
*  back. A single worker thread poll()s every armed listener. On any TLS failure
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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// Per-upstream state, one entry per encrypted upstream. Plaintext entries are
// not tracked here - dnsmasq talks to those directly.
struct proxy_up {
	bool active;                    // armed: listener bound and connection ready
	struct upstream_uri uri;        // parsed descriptor
	struct proxy_listener listener; // bound UDP+TCP pair
	struct tls_conn *conn;          // pooled TLS connection
	char target[INET_ADDRSTRLEN + 8]; // "127.47.11.N#P", for logging
};

static struct proxy_up g_ups[DOTDOH_MAX_UPSTREAMS];
static int g_nups = 0;       // number of encrypted upstreams recorded
static int g_nactive = 0;    // number of those successfully armed
static bool g_armed = false; // init runs once per process

// Tuple -> upstream lookup, precomputed once at arm time so the per-query hot
// path (findUpstreamID) is an O(1) array access, not a config walk + URI parse.
// Index enc holds the upstream that owns tuple 127.47.11.(enc+1)#(5300+enc+1).
static char g_uri_map[DOTDOH_MAX_UPSTREAMS][256];
static int  g_uri_port[DOTDOH_MAX_UPSTREAMS];
static int  g_uri_count = 0;

// Arm one loopback listener pair per encrypted upstream and record the
// per-upstream proxy state. Runs exactly once per process, after dnsmasq
// startup so the freshly bound listener fds cannot collide with dnsmasq's.
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

	// Bring the TLS stack up only if at least one upstream is encrypted; if
	// it fails, every encrypted upstream stays disabled (fail-closed)
	// rather than silently falling back to plaintext.
	bool any_encrypted = false;
	cJSON *it = NULL;
	cJSON_ArrayForEach(it, ups)
		if(it != NULL && cJSON_IsString(it) && it->valuestring != NULL &&
		   (strncmp(it->valuestring, "tls://", 6) == 0 || strncmp(it->valuestring, "https://", 8) == 0))
			any_encrypted = true;
	if(!any_encrypted)
		return;

	const bool tls_ok = tls_client_global_init(config.dns.upstreamCA.v.s);
	if(!tls_ok)
		log_err("dotdoh: TLS init failed - encrypted upstreams are disabled");

	// Walk the upstreams in order. Each encrypted entry consumes one slot
	// in the 127.47.11.N addressing (enc), matching the deterministic tuple
	// the config layer already emitted for it - so a disabled entry still
	// keeps subsequent ones aligned.
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

		// Record the tuple->upstream mapping (tuple 127.47.11.(enc+1)) so the
		// API can resolve it without re-walking the config per query.
		strncpy(g_uri_map[enc], it->valuestring, sizeof(g_uri_map[enc]) - 1);
		g_uri_map[enc][sizeof(g_uri_map[enc]) - 1] = '\0';
		g_uri_port[enc] = u.port;
		g_uri_count = enc + 1;

		struct proxy_up *up = &g_ups[g_nups++];
		memset(up, 0, sizeof(*up));
		up->uri = u;

		// Deterministic tuple; no iteration, since dnsmasq is already
		// pointed at exactly this address. If we cannot own it, the
		// upstream is left disabled and queries to it fail closed
		// (dnsmasq fails over).
		if(tls_ok && proxy_listener_bind(enc, &up->listener))
		{
			up->conn = tls_conn_new();
			if(up->conn != NULL)
			{
				snprintf(up->target, sizeof(up->target), "%s#%d",
				         up->listener.ip, up->listener.port);
				up->active = true;
				g_nactive++;
				log_info("dotdoh: %s upstream %s armed on %s",
				         u.type == UST_DOT ? "DoT" : "DoH", u.verify_name, up->target);
			}
			else
				proxy_listener_close(&up->listener);
		}
		if(!up->active)
			log_warn("dotdoh: encrypted upstream %s could not be armed (127.47.11.%d#%d)",
			         u.verify_name, enc + 1, DOTDOH_PORT_BASE + enc + 1);
		enc++;
	}
}

int dotdoh_count(void)
{
	return g_nactive;
}

bool dotdoh_uri_for_listener(const char *ip, int port, char *out, size_t outlen, int *real_port)
{
	if(ip == NULL || out == NULL || outlen == 0)
		return false;

	// Cheap prefix check first, so plaintext upstreams (the common case) cost
	// almost nothing on the per-query hot path.
	const size_t plen = strlen(DOTDOH_NET_PREFIX);
	if(strncmp(ip, DOTDOH_NET_PREFIX, plen) != 0)
		return false;
	char *end = NULL;
	const long n = strtol(ip + plen, &end, 10);
	if(end == NULL || *end != '\0' || n < 1 || n > g_uri_count ||
	   port != DOTDOH_PORT_BASE + (int)n)
		return false;

	// O(1) lookup in the table dotdoh_init() precomputed - tuple N maps to the
	// N-th encrypted upstream, the same numbering the dnsmasq.conf emission uses.
	strncpy(out, g_uri_map[n - 1], outlen - 1);
	out[outlen - 1] = '\0';
	if(real_port != NULL)
		*real_port = g_uri_port[n - 1];
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
// The socket's per-op SO_RCVTIMEO/SO_SNDTIMEO bound a fully idle peer, but not
// one that trickles a byte just before each timeout; this deadline does, so a
// local peer cannot pin the single worker thread across every other upstream.
#define PROXY_REQUEST_TIMEOUT_MS 10000

// Per-connection caps so a single accepted TCP connection cannot monopolize the
// sole worker thread (the loopback listener is reachable by any local process,
// not just dnsmasq). Generous enough for dnsmasq's pipelining; on hitting either
// the connection is closed and dnsmasq reconnects.
#define PROXY_CONN_MAX_QUERIES 64
#define PROXY_CONN_TIMEOUT_MS  60000

// Monotonic clock in milliseconds, for the per-request deadline.
static uint64_t now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

// Read exactly len bytes (or fail), giving up once deadline passes. Returns
// true on success.
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

// Write exactly len bytes (or fail), giving up once deadline passes. Returns
// true on success.
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

// A single UDP query from dnsmasq: receive, forward over TLS, send the answer
// back to the same source. On failure we drop it (see the file header).
static void handle_udp(struct proxy_up *up)
{
	// 64 KiB each - too large for the worker's thread stack,
	// declared thread-local instead
	static _Thread_local uint8_t query[DNS_MSG_MAX];
	static _Thread_local uint8_t answer[DNS_MSG_MAX];
	struct sockaddr_in src;
	socklen_t sl = sizeof(src);
	const ssize_t n = recvfrom(up->listener.udp_fd, query, sizeof(query), 0,
	                           (struct sockaddr *)&src, &sl);
	if(n <= 0)
		return;
	if(!is_loopback_v4(&src))
		return;

	// Pad the query to a block boundary (RFC 8467) before it is encrypted, so the
	// ciphertext size no longer leaks the query. Only this encrypted leg is
	// padded; the plaintext dnsmasq spoke to us over loopback is left untouched.
	const size_t qlen = edns_pad_query(query, (size_t)n, sizeof(query));
	const ssize_t a = tls_exchange(up->conn, &up->uri, query, qlen, answer, sizeof(answer));
	if(a < 0)
		return; // drop -> dnsmasq times out and fails over

	sendto(up->listener.udp_fd, answer, (size_t)a, 0, (struct sockaddr *)&src, sl);
}

// A TCP connection from dnsmasq: length-prefixed queries in, length-prefixed
// answers out, until the peer closes or something fails.
static void handle_tcp(struct proxy_up *up)
{
	struct sockaddr_in peer;
	socklen_t pl = sizeof(peer);
	// accept4() with SOCK_CLOEXEC: the flag is not inherited from the listening
	// socket, so without it the accepted fd would leak across FTL's execvp()
	// self-restart and keep the client connection alive in the new process.
	const int cfd = accept4(up->listener.tcp_fd, (struct sockaddr *)&peer, &pl, SOCK_CLOEXEC);
	if(cfd < 0)
		return;
	if(!is_loopback_v4(&peer))
	{
		close(cfd);
		return;
	}

	// Bound how long we wait on this connection so a stalled peer cannot pin
	// the single worker thread. Both directions are bounded: without
	// SO_SNDTIMEO a peer that stops reading would block write_full() forever.
	const struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
	setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	// See handle_udp(): keep these 64 KiB buffers off the thread stack.
	static _Thread_local uint8_t query[DNS_MSG_MAX];
	static _Thread_local uint8_t answer[DNS_MSG_MAX];
	static _Thread_local uint8_t out[2 + DNS_MSG_MAX];
	// Bound one connection's hold on the sole worker thread: any local process
	// can reach the loopback listener, so without this a peer could stream
	// valid queries forever and starve every other upstream. Cap both the total
	// lifetime and the query count; dnsmasq simply reconnects.
	const uint64_t conn_deadline = now_ms() + PROXY_CONN_TIMEOUT_MS;
	int served = 0;
	for(;;)
	{
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
		const ssize_t a = tls_exchange(up->conn, &up->uri, query, plen, answer, sizeof(answer));
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
}

void *dotdoh_thread(void *val)
{
	(void)val;
	prctl(PR_SET_NAME, thread_names[DOTDOH], 0, 0, 0);

	// The armed listeners never change after init, so build the poll set
	// once.
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
			continue; // timeout or interrupted; re-check killed
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
	for(int i = 0; i < g_nups; i++)
	{
		if(g_ups[i].conn != NULL)
			tls_conn_free(g_ups[i].conn);
		if(g_ups[i].active)
			proxy_listener_close(&g_ups[i].listener);
		memset(&g_ups[i], 0, sizeof(g_ups[i]));
	}
	g_nups = 0;
	g_nactive = 0;
	g_armed = false;
	g_uri_count = 0;
	tls_client_global_free();
}
