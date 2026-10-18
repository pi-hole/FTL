// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine - auxiliary files
// Regression test for cache_make_stat()'s TXT_STAT_SERVERS / TXT_API_*
// buffer bookkeeping (GHSA-8fc6-q9x4-892v)
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

// Compiles the real cache.c a second time, together with a stand-in for
// get_api_string() and the small set of other externals cache.c needs that
// this standalone harness does not otherwise provide. See webserver.h for
// get_api_string()'s documented contract (grow the shared buffer as needed,
// report the resulting size through *bufflen, never shrink it).
//
// get_api_string() is faked rather than linked for real: the production
// implementation lives in webserver.c, which pulls in the embedded CivetWeb
// server and is not something a narrow regression harness should drag in.
// The fake deliberately reallocates to a size smaller than the incoming
// *bufflen (mirroring what the real one does once more ports have been
// skipped than were present on an earlier call) so a servers.bind reply
// right afterwards is the one thing this test actually exercises: whether
// cache_make_stat() sizes that reply from an up to date buffer length.

#include "dnsmasq.h"
#include "webserver/webserver.h"

// dnsmasq.h redirects free() to free_real() so dnsmasq's own code can log
// the call site; undo that here so free_real() itself, and this file's own
// cleanup calls, reach the real libc free() instead of recursing forever.
#undef free

struct daemon *dnsmasq_daemon;

void *whine_malloc_real(const char *func, unsigned int line, size_t size)
{
	(void)func;
	(void)line;
	return malloc(size);
}

void *whine_realloc_real(const char *wrapper, const char *func, unsigned int line, void *ptr, size_t size)
{
	(void)wrapper;
	(void)func;
	(void)line;
	return realloc(ptr, size);
}

void free_real(const char *func, unsigned int line, void *ptr)
{
	(void)func;
	(void)line;
	free(ptr);
}

int sockaddr_isequal(const union mysockaddr *s1, const union mysockaddr *s2)
{
	return memcmp(s1, s2, sizeof(*s1)) == 0;
}

int prettyprint_addr(union mysockaddr *addr, char *buf)
{
	return sprintf(buf, "10.%u.%u.%u", (addr->in.sin_addr.s_addr >> 16) & 0xff,
	               (addr->in.sin_addr.s_addr >> 8) & 0xff, addr->in.sin_addr.s_addr & 0xff);
}

// Shrinks the buffer to a fixed small size that stays well under what the
// servers.bind reply built up in this test, then reports that size back
// through *bufflen - the behavior cache_make_stat() must tolerate.
#define FAKE_API_BUFSZ 100
unsigned short get_api_string(char **buf, int *bufflen, const bool domain)
{
	(void)domain;
	char *tmp = realloc(*buf, FAKE_API_BUFSZ);
	if(tmp == NULL)
		return 0;
	*buf = tmp;
	*bufflen = FAKE_API_BUFSZ;
	memset(*buf, 0, FAKE_API_BUFSZ);
	return 0;
}

// Unused by the TXT_STAT_SERVERS / TXT_API_* paths this test exercises, only
// here to satisfy the linker for the rest of cache.c.
void FTL_hook(unsigned int flags, const char *name, const union all_addr *addr, char *arg, int id, unsigned short type, const char *file, const int line) { (void)flags; (void)name; (void)addr; (void)arg; (void)id; (void)type; (void)file; (void)line; }
int add_to_ipset(const char *setname, const union all_addr *ipaddr, int flags, int remove) { (void)setname; (void)ipaddr; (void)flags; (void)remove; return 0; }
struct blockdata *blockdata_alloc(char *data, size_t len) { (void)data; (void)len; return NULL; }
void blockdata_free(struct blockdata *blocks) { (void)blocks; }
struct blockdata *blockdata_read(int fd, size_t len) { (void)fd; (void)len; return NULL; }
void blockdata_report(void) { }
void blockdata_write(struct blockdata *block, size_t len, int fd) { (void)block; (void)len; (void)fd; }
char *canonicalise(char *in, int *nomem) { (void)nomem; return in; }
int expand_buf_real(const char *func, unsigned int line, struct iovec *iov, size_t size) { (void)func; (void)line; (void)iov; (void)size; return 0; }
struct hostsfile *expand_filelist(struct hostsfile *list) { return list; }
char *get_domain(struct in_addr addr) { (void)addr; return NULL; }
char *get_domain6(struct in6_addr *addr) { (void)addr; return NULL; }
int hostname_isequal(const char *a, const char *b) { return strcasecmp(a, b) == 0; }
void my_syslog(int priority, const char *format, ...) { (void)priority; (void)format; }
void pop_and_retry_query(struct frec *forward, int status, time_t now) { (void)forward; (void)status; (void)now; }
int read_write(int fd, unsigned char *packet, int size, int rw) { (void)fd; (void)packet; (void)size; (void)rw; return 0; }
void return_reply(time_t now, struct frec *forward, struct dns_header *header, ssize_t n, int status) { (void)now; (void)forward; (void)header; (void)n; (void)status; }
void *safe_malloc(size_t size) { return malloc(size); }
void set_dynamic_inotify(int flag, int total_size, struct crec **rhash, int revhashsz) { (void)flag; (void)total_size; (void)rhash; (void)revhashsz; }

// Builds daemon->servers with "count" distinct entries, enough that the
// servers.bind reply has to grow buff/bufflen well past FAKE_API_BUFSZ.
static void make_servers(unsigned int count)
{
	dnsmasq_daemon = calloc(1, sizeof(*dnsmasq_daemon));
	dnsmasq_daemon->addrbuff = calloc(ADDRSTRLEN, sizeof(char));

	struct server *prev = NULL;
	for(unsigned int i = 0; i < count; i++)
	{
		struct server *serv = calloc(1, sizeof(*serv));
		serv->addr.in.sin_family = AF_INET;
		serv->addr.in.sin_addr.s_addr = htonl(0x0a000000u | i);
		serv->addr.in.sin_port = htons(53);
		serv->queries = 1;
		serv->failed_queries = 0;
		if(prev)
			prev->next = serv;
		else
			dnsmasq_daemon->servers = serv;
		prev = serv;
	}
}

int main(void)
{
	make_servers(80);

	struct txt_record t = { 0 };
	t.stat = TXT_STAT_SERVERS;
	if(!cache_make_stat(&t))
	{
		printf("TXT_STAT_SERVERS (1st): FAIL\n");
		return EXIT_FAILURE;
	}
	const unsigned short first_len = t.len;
	unsigned char *first_txt = malloc(first_len);
	memcpy(first_txt, t.txt, first_len);
	printf("TXT_STAT_SERVERS (1st): %u bytes\n", first_len);

	t = (struct txt_record){ 0 };
	t.stat = TXT_API_DOMAIN;
	if(!cache_make_stat(&t))
	{
		printf("TXT_API_DOMAIN: FAIL\n");
		return EXIT_FAILURE;
	}
	printf("TXT_API_DOMAIN: %u bytes (shrunk shared buffer to %d)\n", t.len, FAKE_API_BUFSZ);

	// The dangerous repeat: if bufflen was left stale and larger than the
	// buffer get_api_string() just shrank, this writes out of bounds.
	t = (struct txt_record){ 0 };
	t.stat = TXT_STAT_SERVERS;
	if(!cache_make_stat(&t))
	{
		printf("TXT_STAT_SERVERS (2nd): FAIL\n");
		return EXIT_FAILURE;
	}
	printf("TXT_STAT_SERVERS (2nd): %u bytes\n", t.len);

	const bool matched = t.len == first_len && memcmp(t.txt, first_txt, first_len) == 0;
	free(first_txt);
	if(!matched)
	{
		printf("TXT_STAT_SERVERS_REGRESSION=FAIL (reply changed across the shrink)\n");
		return EXIT_FAILURE;
	}

	printf("TXT_STAT_SERVERS_REGRESSION=PASS\n");
	return EXIT_SUCCESS;
}
