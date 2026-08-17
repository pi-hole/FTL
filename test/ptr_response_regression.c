#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "config/config.h"
#include "log.h"
#include "syscalls/syscalls.h"

#define TEST_MAXDOMAINLEN 256
#define DNS_HEADER_LEN 12
#define DNS_TYPE_PTR 12
#define DNS_CLASS_IN 1

bool resolveHostname(const int sock, const bool tcp, struct sockaddr_in *dest,
                     char hostn[TEST_MAXDOMAINLEN], const char *addr,
                     const bool force, bool *truncated);

struct config config = { 0 };
bool debug_flags[DEBUG_MAX] = { false };
bool only_testing = true;

bool get_secure_randomness(uint8_t *buffer, const size_t length)
{
	// The production resolver obtains cryptographically secure query IDs.
	// This standalone regression harness only needs distinct, reproducible
	// IDs so stale replies can be correlated deterministically.
	static uint8_t next = 1;

	if(buffer == NULL)
		return false;

	for(size_t i = 0; i < length; i++)
		buffer[i] = next++;

	return true;
}


void _FTL_log(const int priority, const enum debug_flag flag, const char *format, ...)
{
	(void)priority;
	(void)flag;
	(void)format;
}

char *escape_string(const char *input)
{
	if(input == NULL)
		return NULL;
	const size_t len = strlen(input) + 1;
	char *copy = malloc(len);
	if(copy != NULL)
		memcpy(copy, input, len);
	return copy;
}

void log_hostname_warning(const char *ip, const char *name, const unsigned int pos)
{
	(void)ip;
	(void)name;
	(void)pos;
}

void *FTLcalloc(size_t n, size_t size, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return calloc(n, size);
}

bool FTLfree(void *ptr, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	free(ptr);
	return true;
}

size_t FTLstrlen(const char *s, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strlen(s);
}

char *FTLstrncpy(char *dest, const char *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strncpy(dest, src, n);
}

char *FTLstrncat(char *dest, const char *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strncat(dest, src, n);
}

void *FTLmemcpy(void *dest, const void *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memcpy(dest, src, n);
}

void *FTLmemset(void *s, const int c, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memset(s, c, n);
}

char *FTLstrstr(const char *haystack, const char *needle, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strstr(haystack, needle);
}

int FTLstrcmp(const char *s1, const char *s2, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strcmp(s1, s2);
}

int FTLstrcasecmp(const char *s1, const char *s2, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strcasecmp(s1, s2);
}

int FTLsnprintf(const char *file, const char *func, const int line,
                char *buffer, const size_t maxlen, const char *format, ...)
{
	(void)file;
	(void)func;
	(void)line;
	va_list args;
	va_start(args, format);
	const int result = vsnprintf(buffer, maxlen, format, args);
	va_end(args);
	return result;
}

ssize_t FTLsendto(int sockfd, void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen,
                  const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t FTLrecvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen,
                    const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t FTLrecv(int sockfd, void *buf, size_t len, int flags, const bool warn,
                const char *file, const char *func, const int line)
{
	(void)warn;
	(void)file;
	(void)func;
	(void)line;
	return recv(sockfd, buf, len, flags);
}

struct server_context {
	int sock;
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	bool release_delayed_a;
	bool success;
};

static bool dns_question_end(const uint8_t *query, const size_t query_len, size_t *end)
{
	if(query_len < DNS_HEADER_LEN + 1)
		return false;

	size_t pos = DNS_HEADER_LEN;
	while(pos < query_len)
	{
		const uint8_t label_len = query[pos++];
		if(label_len == 0)
			break;
		if(label_len > 63 || pos + label_len > query_len)
			return false;
		pos += label_len;
	}

	if(pos + 4 > query_len)
		return false;

	*end = pos + 4;
	return true;
}

static bool encode_dns_name(uint8_t *out, const size_t out_len, const char *name, size_t *encoded_len)
{
	size_t used = 0;
	const char *label = name;
	while(*label != '\0')
	{
		const char *dot = strchr(label, '.');
		const size_t len = dot == NULL ? strlen(label) : (size_t)(dot - label);
		if(len == 0 || len > 63 || used + 1 + len >= out_len)
			return false;
		out[used++] = (uint8_t)len;
		memcpy(out + used, label, len);
		used += len;
		if(dot == NULL)
			break;
		label = dot + 1;
	}
	if(used >= out_len)
		return false;
	out[used++] = 0;
	*encoded_len = used;
	return true;
}

static bool build_ptr_response(const uint8_t *query, const size_t query_len,
                               const char *target, uint8_t *response,
                               const size_t response_size, size_t *response_len)
{
	size_t question_end = 0;
	if(!dns_question_end(query, query_len, &question_end) || question_end + 12 >= response_size)
		return false;

	memset(response, 0, response_size);
	memcpy(response, query, question_end);
	response[2] = 0x81;
	response[3] = 0x80;
	response[4] = 0x00;
	response[5] = 0x01;
	response[6] = 0x00;
	response[7] = 0x01;
	response[8] = 0x00;
	response[9] = 0x00;
	response[10] = 0x00;
	response[11] = 0x00;

	size_t pos = question_end;
	response[pos++] = 0xc0;
	response[pos++] = 0x0c;
	response[pos++] = 0x00;
	response[pos++] = DNS_TYPE_PTR;
	response[pos++] = 0x00;
	response[pos++] = DNS_CLASS_IN;
	response[pos++] = 0x00;
	response[pos++] = 0x00;
	response[pos++] = 0x00;
	response[pos++] = 0x00;

	uint8_t encoded[256] = { 0 };
	size_t encoded_len = 0;
	if(!encode_dns_name(encoded, sizeof(encoded), target, &encoded_len) ||
	   encoded_len > UINT16_MAX || pos + 2 + encoded_len > response_size)
		return false;

	response[pos++] = (uint8_t)(encoded_len >> 8);
	response[pos++] = (uint8_t)(encoded_len & 0xffu);
	memcpy(response + pos, encoded, encoded_len);
	pos += encoded_len;
	*response_len = pos;
	return true;
}

static void *server_main(void *arg)
{
	struct server_context *ctx = arg;
	uint8_t query_a[512] = { 0 };
	uint8_t query_b[512] = { 0 };
	uint8_t response[512] = { 0 };
	struct sockaddr_in client = { 0 };
	socklen_t client_len = sizeof(client);

	const ssize_t a_len = recvfrom(ctx->sock, query_a, sizeof(query_a), 0,
	                               (struct sockaddr *)&client, &client_len);
	if(a_len <= 0)
		return NULL;

	pthread_mutex_lock(&ctx->mutex);
	while(!ctx->release_delayed_a)
		pthread_cond_wait(&ctx->condition, &ctx->mutex);
	pthread_mutex_unlock(&ctx->mutex);

	size_t response_len = 0;
	if(!build_ptr_response(query_a, (size_t)a_len, "late-a.example",
	                       response, sizeof(response), &response_len))
		return NULL;
	if(sendto(ctx->sock, response, response_len, 0,
	          (const struct sockaddr *)&client, client_len) != (ssize_t)response_len)
		return NULL;

	client_len = sizeof(client);
	const ssize_t b_len = recvfrom(ctx->sock, query_b, sizeof(query_b), 0,
	                               (struct sockaddr *)&client, &client_len);
	if(b_len <= 0)
		return NULL;

	if(!build_ptr_response(query_b, (size_t)b_len, "answer-b.example",
	                       response, sizeof(response), &response_len))
		return NULL;
	if(sendto(ctx->sock, response, response_len, 0,
	          (const struct sockaddr *)&client, client_len) != (ssize_t)response_len)
		return NULL;

	ctx->success = true;
	return NULL;
}

int main(void)
{
	int server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(server_sock < 0)
	{
		perror("server socket");
		return EXIT_FAILURE;
	}

	struct sockaddr_in server = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	if(bind(server_sock, (const struct sockaddr *)&server, sizeof(server)) != 0)
	{
		perror("server bind");
		close(server_sock);
		return EXIT_FAILURE;
	}

	socklen_t server_len = sizeof(server);
	if(getsockname(server_sock, (struct sockaddr *)&server, &server_len) != 0)
	{
		perror("getsockname");
		close(server_sock);
		return EXIT_FAILURE;
	}

	int client_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(client_sock < 0)
	{
		perror("client socket");
		close(server_sock);
		return EXIT_FAILURE;
	}

	const struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
	if(setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
	{
		perror("setsockopt");
		close(client_sock);
		close(server_sock);
		return EXIT_FAILURE;
	}

	config.dns.port.v.u16 = ntohs(server.sin_port);
	struct server_context ctx = {
		.sock = server_sock,
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.condition = PTHREAD_COND_INITIALIZER,
		.release_delayed_a = false,
		.success = false,
	};
	pthread_t thread;
	if(pthread_create(&thread, NULL, server_main, &ctx) != 0)
	{
		perror("pthread_create");
		close(client_sock);
		close(server_sock);
		return EXIT_FAILURE;
	}

	char host_a[TEST_MAXDOMAINLEN] = { 0 };
	char host_b[TEST_MAXDOMAINLEN] = { 0 };
	bool truncated = false;
	const bool first_ok = resolveHostname(client_sock, false, &server, host_a,
	                                      "192.0.2.10", true, &truncated);
	pthread_mutex_lock(&ctx.mutex);
	ctx.release_delayed_a = true;
	pthread_cond_signal(&ctx.condition);
	pthread_mutex_unlock(&ctx.mutex);
	const bool second_ok = resolveHostname(client_sock, false, &server, host_b,
	                                       "192.0.2.11", true, &truncated);

	pthread_join(thread, NULL);
	pthread_cond_destroy(&ctx.condition);
	pthread_mutex_destroy(&ctx.mutex);
	close(client_sock);
	close(server_sock);

	printf("FIRST_LOOKUP_TIMEOUT=%s\n", !first_ok ? "PASS" : "FAIL");
	printf("SECOND_LOOKUP_RESULT=%s\n", second_ok ? host_b : "<failed>");
	printf("SERVER_SEQUENCE=%s\n", ctx.success ? "PASS" : "FAIL");

	if(first_ok || !second_ok || !ctx.success || strcmp(host_b, "answer-b.example") != 0)
	{
		printf("PTR_RESPONSE_REGRESSION=FAIL\n");
		return EXIT_FAILURE;
	}

	printf("PTR_RESPONSE_REGRESSION=PASS\n");
	return EXIT_SUCCESS;
}
