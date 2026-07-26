/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Standalone regression harness for the dotdoh leaf units
*
*  #includes the self-contained implementation .c files directly (URI parser,
*  DoT/DoH framing). Built only on request via -DBUILD_DOTDOH_REGRESSION=ON.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "dotdoh/upstream_uri.c"
#include "dotdoh/framing.c"
#include "dotdoh/registry.c"
#include "dotdoh/edns_pad.c"

static int failures = 0;

// Does haystack[hn] contain the C-string needle?
static bool contains(const uint8_t *hay, size_t hn, const char *needle)
{
	size_t nn = strlen(needle);
	if(nn == 0 || nn > hn) return false;
	for(size_t i = 0; i + nn <= hn; i++)
		if(memcmp(hay + i, needle, nn) == 0) return true;
	return false;
}

#define EXPECT(cond, ...) do { \
	if(!(cond)) { \
		failures++; \
		fprintf(stderr, "  FAIL: "); \
		fprintf(stderr, __VA_ARGS__); \
		fprintf(stderr, " (%s:%d)\n", __FILE__, __LINE__); \
	} \
} while(0)

// Assert a URI parses to the expected fields.
static void ok(const char *in, enum ustype type, const char *connect,
               const char *verify, int port, const char *path)
{
	struct upstream_uri u;
	memset(&u, 0xAA, sizeof(u));
	bool r = parse_upstream_uri(in, &u);
	EXPECT(r, "\"%s\" expected to parse", in);
	if(!r) return;
	EXPECT(u.type == type, "\"%s\" type %d != %d", in, u.type, type);
	EXPECT(strcmp(u.connect_host, connect) == 0,
	       "\"%s\" connect_host \"%s\" != \"%s\"", in, u.connect_host, connect);
	if(type != UST_PLAIN)
	{
		EXPECT(strcmp(u.verify_name, verify) == 0,
		       "\"%s\" verify_name \"%s\" != \"%s\"", in, u.verify_name, verify);
		EXPECT(u.port == port, "\"%s\" port %d != %d", in, u.port, port);
	}
	if(type == UST_DOH)
		EXPECT(strcmp(u.doh_path, path) == 0,
		       "\"%s\" doh_path \"%s\" != \"%s\"", in, u.doh_path, path);
}

// Assert a URI is rejected.
static void bad(const char *in)
{
	struct upstream_uri u;
	bool r = parse_upstream_uri(in, &u);
	EXPECT(!r, "\"%s\" expected to be rejected", in);
}

static void test_plain(void)
{
	ok("9.9.9.9",       UST_PLAIN, "9.9.9.9",  "", 0, "");
	ok("9.9.9.9#5335",  UST_PLAIN, "9.9.9.9#5335", "", 0, "");
	ok("docker-resolver", UST_PLAIN, "docker-resolver", "", 0, "");
}

static void test_dot(void)
{
	ok("tls://one.one.one.one",        UST_DOT, "one.one.one.one", "one.one.one.one", 853, "");
	ok("tls://dns.quad9.net#853",      UST_DOT, "dns.quad9.net",   "dns.quad9.net",   853, "");
	ok("tls://dns.quad9.net#8853",     UST_DOT, "dns.quad9.net",   "dns.quad9.net",   8853, "");
	ok("tls://one.one.one.one@1.1.1.1", UST_DOT, "1.1.1.1",        "one.one.one.one", 853, "");
	ok("tls://1.1.1.1",                UST_DOT, "1.1.1.1",         "1.1.1.1",         853, "");
	ok("tls://[2606:4700:4700::1111]#853", UST_DOT, "2606:4700:4700::1111", "2606:4700:4700::1111", 853, "");
	// sni@[ipv6] pinning, as emitted for the suggested DoT servers
	ok("tls://dns.google@[2001:4860:4860::8888]", UST_DOT, "2001:4860:4860::8888", "dns.google", 853, "");
}

static void test_doh(void)
{
	ok("https://cloudflare-dns.com/dns-query", UST_DOH, "cloudflare-dns.com", "cloudflare-dns.com", 443, "/dns-query");
	ok("https://cloudflare-dns.com",           UST_DOH, "cloudflare-dns.com", "cloudflare-dns.com", 443, "/dns-query");
	ok("https://one.one.one.one@1.1.1.1/dns-query", UST_DOH, "1.1.1.1", "one.one.one.one", 443, "/dns-query");
	// sni@[ipv6] pinning, as emitted for the suggested DoH servers
	ok("https://dns.google@[2001:4860:4860::8888]/dns-query", UST_DOH, "2001:4860:4860::8888", "dns.google", 443, "/dns-query");
	ok("https://doh.example#8443/q",           UST_DOH, "doh.example", "doh.example", 8443, "/q");
}

static void test_reject(void)
{
	bad("tls://"); // empty host
	bad("https://"); // empty host
	bad("tls://host\r\nx"); // CRLF injection
	bad("tls://ho st"); // space
	bad("tls://host#0"); // port 0
	bad("tls://host#99999"); // port out of range
	bad("tls://host#abc"); // non-numeric port
	bad("http://x"); // unknown scheme (not https)
	bad("ftp://x"); // unknown scheme
	bad("tls://@1.1.1.1"); // empty verify name
	bad("tls://name@"); // empty connect host
	bad(NULL); // NULL input
	bad(""); // empty input
}

static void test_dot_framing(void)
{
	uint8_t out[16];
	ssize_t n = dot_frame((const uint8_t *)"abc", 3, out, sizeof(out));
	EXPECT(n == 5, "dot_frame len");
	EXPECT(out[0] == 0 && out[1] == 3, "dot_frame prefix");
	EXPECT(memcmp(out + 2, "abc", 3) == 0, "dot_frame body");
	EXPECT(dot_frame((const uint8_t *)"abc", 3, out, 4) == -1, "dot_frame out too small");
	EXPECT(dot_frame((const uint8_t *)"x", 65536, out, sizeof(out)) == -1, "dot_frame oversized");
	EXPECT(dot_frame((const uint8_t *)"", 0, out, sizeof(out)) == -1, "dot_frame empty");

	uint8_t b[8] = { 0, 3, 'a', 'b', 'c' };
	size_t off = 0;
	EXPECT(dot_deframe(b, 5, &off) == 3 && off == 2, "dot_deframe full");
	EXPECT(dot_deframe(b, 4, &off) == 0, "dot_deframe partial body");
	EXPECT(dot_deframe(b, 1, &off) == 0, "dot_deframe partial prefix");
	uint8_t z[4] = { 0, 0, 9, 9 };
	EXPECT(dot_deframe(z, 4, &off) == -1, "dot_deframe zero length");
}

static void test_doh_request(void)
{
	uint8_t req[512];
	ssize_t n = doh_build_request("cloudflare-dns.com", "/dns-query",
	                              (const uint8_t *)"xy", 2, req, sizeof(req));
	EXPECT(n > 0, "doh_build_request ok");
	if(n > 0)
	{
		EXPECT(contains(req, (size_t)n, "POST /dns-query HTTP/1.1\r\n"), "doh request line");
		EXPECT(contains(req, (size_t)n, "Host: cloudflare-dns.com\r\n"), "doh host header");
		EXPECT(contains(req, (size_t)n, "Content-Type: application/dns-message\r\n"), "doh content-type");
		EXPECT(contains(req, (size_t)n, "Content-Length: 2\r\n"), "doh content-length");
		EXPECT((size_t)n >= 6 && memcmp(req + n - 6, "\r\n\r\nxy", 6) == 0, "doh body appended");
	}
	EXPECT(doh_build_request("h", "/p", (const uint8_t *)"xy", 2, req, 10) == -1, "doh out too small");
	EXPECT(doh_build_request("h\r\nX", "/p", (const uint8_t *)"xy", 2, req, sizeof(req)) == -1, "doh CRLF host rejected");
	EXPECT(doh_build_request("h", "/p\r\nx", (const uint8_t *)"xy", 2, req, sizeof(req)) == -1, "doh CRLF path rejected");
	EXPECT(doh_build_request("h", "/dns query", (const uint8_t *)"xy", 2, req, sizeof(req)) == -1, "doh space in path rejected");
}

static void test_doh_response(void)
{
	size_t bo = 0, bl = 0;
	const char *r1 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nAB";
	ssize_t c = doh_parse_response((const uint8_t *)r1, strlen(r1), &bo, &bl);
	EXPECT(c == (ssize_t)strlen(r1), "doh resp consumed");
	EXPECT(bl == 2 && memcmp(r1 + bo, "AB", 2) == 0, "doh resp body");

	EXPECT(doh_parse_response((const uint8_t *)"HTTP/1.1 200 OK\r\n", 17, &bo, &bl) == 0, "doh resp partial headers");
	const char *r2 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r2, strlen(r2), &bo, &bl) == 0, "doh resp partial body");
	const char *r3 = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
	EXPECT(doh_parse_response((const uint8_t *)r3, strlen(r3), &bo, &bl) == -1, "doh resp non-200");
	const char *r4 = "HTTP/1.1 200 OK\r\nFoo: bar\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r4, strlen(r4), &bo, &bl) == -1, "doh resp missing content-length");
	const char *r5 = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r5, strlen(r5), &bo, &bl) == (ssize_t)strlen(r5), "doh resp case-insensitive");
	const char *r6 = "HTTP/1.1 200 OK\r\nContent-Length: 70000\r\n\r\n";
	EXPECT(doh_parse_response((const uint8_t *)r6, strlen(r6), &bo, &bl) == -1, "doh resp oversized");
	const char *r7 = "HTTP/1.1 200 OK\r\nX-Content-Length: 9\r\nContent-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r7, strlen(r7), &bo, &bl) == (ssize_t)strlen(r7) && bl == 2, "doh resp ignores X-Content-Length prefix");
	const char *r8 = "HTTP/1.1 200 OK\r\nX-Content-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r8, strlen(r8), &bo, &bl) == -1, "doh resp X-Content-Length is not Content-Length");
	// Stricter status-line and Content-Length parsing (locked in against regressions).
	const char *r9 = "HTTP/1.1 2000 OK\r\nContent-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r9, strlen(r9), &bo, &bl) == -1, "doh resp rejects 4-digit status code");
	const char *r10 = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
	EXPECT(doh_parse_response((const uint8_t *)r10, strlen(r10), &bo, &bl) == -1, "doh resp rejects zero Content-Length");
	const char *r11 = "HTTP/1.1 200 OK\r\nContent-Length: 2x\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r11, strlen(r11), &bo, &bl) == -1, "doh resp rejects trailing junk in Content-Length");
	const char *r12 = "220 smtp ready\r\nContent-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r12, strlen(r12), &bo, &bl) == -1, "doh resp rejects non-HTTP status line");
	const char *r13 = "HTTP/1.1 200 OK\r\nContent-Length: 2 \r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r13, strlen(r13), &bo, &bl) == (ssize_t)strlen(r13), "doh resp tolerates trailing OWS in Content-Length");
	// Message-smuggling shapes must be rejected so leftover bytes cannot desync
	// the pooled connection for later queries.
	const char *r14 = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 300\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r14, strlen(r14), &bo, &bl) == -1, "doh resp rejects duplicate Content-Length");
	const char *r15 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\nAB";
	EXPECT(doh_parse_response((const uint8_t *)r15, strlen(r15), &bo, &bl) == -1, "doh resp rejects Transfer-Encoding");
}

// Occupy ip:port with a socket of the given type; returns fd or -1.
static int occupy(const char *ip, int port, int socktype)
{
	int fd = socket(AF_INET, socktype, 0);
	if(fd < 0) return -1;
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons((uint16_t)port);
	inet_pton(AF_INET, ip, &sa.sin_addr);
	if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0)
	{
		close(fd);
		return -1;
	}
	if(socktype == SOCK_STREAM)
		listen(fd, 1);
	return fd;
}

static void test_registry(void)
{
	struct proxy_listener l0, l1;

	// Tuples are randomised per process but stable across queries.
	const uint32_t a0 = dotdoh_tuple_addr(0);
	EXPECT((a0 >> 24) == 127, "slot 0 address in 127.0.0.0/8 (%08x)", a0);
	EXPECT((a0 & 0xff) != 0 && (a0 & 0xff) != 255, "slot 0 address avoids .0/.255");
	EXPECT(a0 != 0x7f000001u && a0 != 0x7f000035u, "slot 0 address avoids 127.0.0.1/.53");
	EXPECT(dotdoh_tuple_addr(0) == a0, "slot 0 address stable");
	EXPECT(dotdoh_tuple_addr(1) != a0, "slots 0 and 1 have distinct addresses");
	EXPECT(dotdoh_tuple_port(0) > 1023 && dotdoh_tuple_port(0) <= 65535, "slot 0 port %d in range", dotdoh_tuple_port(0));
	EXPECT(dotdoh_tuple_addr(-1) == 0 && dotdoh_tuple_port(-1) == -1, "out-of-range -> 0 / -1");

	// A fresh slot is bindable and binds exactly the tuple the table records.
	EXPECT(dotdoh_tuple_ensure_bindable(0), "slot 0 tuple is bindable");
	EXPECT(proxy_listener_bind(0, &l0), "bind slot 0");
	char ip0[INET_ADDRSTRLEN];
	dotdoh_tuple_ip(0, ip0, sizeof(ip0));
	EXPECT(strcmp(l0.ip, ip0) == 0, "slot 0 bound its table address %s", l0.ip);
	// The dotted-quad the config/bind use must round-trip to the host-order uint32
	// the FTL_is_forward_available() gate matches on, or the gate would misjudge.
	struct in_addr rt;
	EXPECT(inet_pton(AF_INET, ip0, &rt) == 1 && ntohl(rt.s_addr) == a0, "ip string round-trips to addr");
	EXPECT(l0.port == dotdoh_tuple_port(0), "slot 0 bound its table port %d", l0.port);
	EXPECT(l0.udp_fd >= 0 && l0.tcp_fd >= 0, "slot 0 fds");

	// Squat slot 1's current tuple; ensure_bindable() must redraw a fresh tuple
	// and still succeed, leaving the table on the new (bindable) tuple.
	char ip1[INET_ADDRSTRLEN];
	dotdoh_tuple_ip(1, ip1, sizeof(ip1));
	const uint32_t a1_before = dotdoh_tuple_addr(1);
	const int p1_before = dotdoh_tuple_port(1);
	int occ_udp = occupy(ip1, p1_before, SOCK_DGRAM);
	int occ_tcp = occupy(ip1, p1_before, SOCK_STREAM);
	EXPECT(occ_udp >= 0 && occ_tcp >= 0, "occupy slot 1's tuple");
	EXPECT(dotdoh_tuple_ensure_bindable(1), "ensure_bindable retries past a squatted tuple");
	EXPECT(dotdoh_tuple_addr(1) != a1_before || dotdoh_tuple_port(1) != p1_before, "slot 1 tuple was redrawn");
	EXPECT(proxy_listener_bind(1, &l1), "bind slot 1 on the redrawn tuple");

	// Exclusivity: our owned tuple cannot be co-bound.
	int again = occupy(l0.ip, l0.port, SOCK_STREAM);
	EXPECT(again < 0, "owned tuple is exclusive (no SO_REUSEADDR)");
	if(again >= 0) close(again);

	proxy_listener_close(&l0);
	proxy_listener_close(&l1);
	if(occ_udp >= 0) close(occ_udp);
	if(occ_tcp >= 0) close(occ_tcp);
}

// "example.com" IN A: a 17-byte question section (13-byte QNAME + QTYPE + QCLASS).
static const uint8_t QUESTION[] = {
	0x07, 'e','x','a','m','p','l','e', 0x03, 'c','o','m', 0x00, // QNAME
	0x00, 0x01, // QTYPE  A
	0x00, 0x01, // QCLASS IN
};

// Write a 12-byte DNS header into buf with the given section counts.
static void put_header(uint8_t *buf, uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar)
{
	buf[0] = 0x12; buf[1] = 0x34;   // ID
	buf[2] = 0x01; buf[3] = 0x00;   // flags: standard query, RD
	buf[4] = (uint8_t)(qd >> 8); buf[5] = (uint8_t)qd;
	buf[6] = (uint8_t)(an >> 8); buf[7] = (uint8_t)an;
	buf[8] = (uint8_t)(ns >> 8); buf[9] = (uint8_t)ns;
	buf[10] = (uint8_t)(ar >> 8); buf[11] = (uint8_t)ar;
}

// Assert every byte in buf[from..to) is zero (the padding octets).
static void expect_zeros(const uint8_t *buf, size_t from, size_t to, const char *what)
{
	for(size_t i = from; i < to; i++)
		if(buf[i] != 0)
		{
			EXPECT(false, "%s: buf[%zu]=0x%02x != 0", what, i, buf[i]);
			return;
		}
}

static void test_edns_pad(void)
{
	// 1) Query with no OPT record: a fresh OPT RR carrying the Padding option is
	//    appended and ARCOUNT is bumped, rounding the message up to 128 octets.
	{
		uint8_t buf[512];
		memset(buf, 0, sizeof(buf));
		put_header(buf, 1, 0, 0, 0);
		memcpy(buf + 12, QUESTION, sizeof(QUESTION));
		const size_t len = 12 + sizeof(QUESTION); // 29

		const size_t out = edns_pad_query(buf, len, sizeof(buf));
		EXPECT(out == 128, "no-OPT padded length %zu != 128", out);
		EXPECT(out % 128 == 0, "no-OPT length not a multiple of 128");
		EXPECT(buf[10] == 0x00 && buf[11] == 0x01, "no-OPT ARCOUNT not bumped to 1");
		EXPECT(memcmp(buf + 12, QUESTION, sizeof(QUESTION)) == 0, "no-OPT question corrupted");
		// OPT RR at offset 29
		EXPECT(buf[29] == 0x00, "OPT name not root");
		EXPECT(buf[30] == 0x00 && buf[31] == 0x29, "OPT type != 41");
		EXPECT(buf[32] == 0x04 && buf[33] == 0xD0, "OPT UDP size != 1232");
		EXPECT(buf[34] == 0 && buf[35] == 0 && buf[36] == 0 && buf[37] == 0, "OPT TTL not zero");
		EXPECT(buf[38] == 0x00 && buf[39] == 0x58, "OPT RDLEN != 88");
		// Padding option (code 12, length 84) + 84 zero octets
		EXPECT(buf[40] == 0x00 && buf[41] == 0x0C, "padding option code != 12");
		EXPECT(buf[42] == 0x00 && buf[43] == 0x54, "padding option length != 84");
		expect_zeros(buf, 44, 128, "no-OPT padding octets");
	}

	// 2) Query that already has an OPT record (no options): the Padding option is
	//    appended to its RDATA and ARCOUNT stays 1.
	{
		uint8_t buf[512];
		memset(buf, 0, sizeof(buf));
		put_header(buf, 1, 0, 0, 1);
		memcpy(buf + 12, QUESTION, sizeof(QUESTION));
		size_t p = 12 + sizeof(QUESTION); // 29
		buf[p++] = 0x00;                       // root name
		buf[p++] = 0x00; buf[p++] = 0x29;      // type OPT
		buf[p++] = 0x10; buf[p++] = 0x00;      // UDP size 4096
		buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00; // TTL
		buf[p++] = 0x00; buf[p++] = 0x00;      // RDLEN 0
		const size_t len = p; // 40

		const size_t out = edns_pad_query(buf, len, sizeof(buf));
		EXPECT(out == 128, "with-OPT padded length %zu != 128", out);
		EXPECT(buf[10] == 0x00 && buf[11] == 0x01, "with-OPT ARCOUNT changed");
		EXPECT(buf[32] == 0x10 && buf[33] == 0x00, "with-OPT existing UDP size clobbered");
		EXPECT(buf[38] == 0x00 && buf[39] == 0x58, "with-OPT RDLEN not grown to 88");
		EXPECT(buf[40] == 0x00 && buf[41] == 0x0C, "with-OPT padding option code != 12");
		EXPECT(buf[42] == 0x00 && buf[43] == 0x54, "with-OPT padding option length != 84");
		expect_zeros(buf, 44, 128, "with-OPT padding octets");
	}

	// 3) Idempotent: a query that already carries a Padding option is left as-is.
	{
		uint8_t buf[512];
		memset(buf, 0, sizeof(buf));
		put_header(buf, 1, 0, 0, 1);
		memcpy(buf + 12, QUESTION, sizeof(QUESTION));
		size_t p = 12 + sizeof(QUESTION);
		buf[p++] = 0x00;                       // root name
		buf[p++] = 0x00; buf[p++] = 0x29;      // type OPT
		buf[p++] = 0x10; buf[p++] = 0x00;      // UDP size
		buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00; // TTL
		buf[p++] = 0x00; buf[p++] = 0x04;      // RDLEN 4
		buf[p++] = 0x00; buf[p++] = 0x0C;      // Padding option code
		buf[p++] = 0x00; buf[p++] = 0x00;      // Padding option length 0
		const size_t len = p; // 44

		const size_t out = edns_pad_query(buf, len, sizeof(buf));
		EXPECT(out == len, "already-padded query changed (%zu != %zu)", out, len);
	}

	// 4) Fail-open: the padded message would not fit in the caller's buffer.
	{
		uint8_t buf[512];
		memset(buf, 0, sizeof(buf));
		put_header(buf, 1, 0, 0, 0);
		memcpy(buf + 12, QUESTION, sizeof(QUESTION));
		const size_t len = 12 + sizeof(QUESTION); // 29, needs 128
		const size_t out = edns_pad_query(buf, len, 100);
		EXPECT(out == len, "oversized should fail open (%zu != %zu)", out, len);
	}

	// 5) Fail-open: truncated / malformed messages are returned unchanged.
	{
		uint8_t buf[512];
		memset(buf, 0, sizeof(buf));
		EXPECT(edns_pad_query(buf, 5, sizeof(buf)) == 5, "short-header should fail open");
		put_header(buf, 1, 0, 0, 0); // claims a question that isn't present
		EXPECT(edns_pad_query(buf, 12, sizeof(buf)) == 12, "missing question should fail open");
	}
}

int main(void)
{
	test_plain();
	test_dot();
	test_doh();
	test_reject();
	test_dot_framing();
	test_doh_request();
	test_doh_response();
	test_registry();
	test_edns_pad();

	if(failures == 0)
		printf("dotdoh_regression: all tests passed\n");
	else
		printf("dotdoh_regression: %d failure(s)\n", failures);
	return failures ? 1 : 0;
}
