/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Minimal native journal protocol implementation
*
*  Protocol: https://systemd.io/JOURNAL_NATIVE_PROTOCOL
*
*  We cannot use libsystemd's sd_journal_send(), it opens a lazy
*  connection to the socket, but without a way for us to retrieve
*  the file descriptor, nor initialize a reopen. One of those is
*  needed in the context of dnsmasq closing all file descriptors
*  during startup or internal reload. Letting dnsmasq close all FDs
*  will break sd_journal_* with -EINVAL and removing the closure will
*  cause side effects, like port conflicts with itself during internal
*  reloads.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "journal.h"
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#define JOURNAL_SNDBUF (8ULL * 1024 * 1024)
#define JOURNAL_PATH "/run/systemd/journal/socket"
#define JOURNAL_MAX_ENTRY (16 * 1024)

static pthread_once_t journal_once = PTHREAD_ONCE_INIT;
static int journal_fd = -1;

static int journal_get_fd(void)
{
	return journal_fd;
}

static void journal_init_once(void)
{
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return;

	int snd = JOURNAL_SNDBUF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, sizeof(snd));

	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	memcpy(sa.sun_path, JOURNAL_PATH, sizeof(JOURNAL_PATH));
	const socklen_t sa_len = offsetof(struct sockaddr_un, sun_path) +
	                         sizeof(JOURNAL_PATH) - 1;

	if (connect(fd, (struct sockaddr *)&sa, sa_len) < 0)
	{
		close(fd);
		return;
	}

	journal_fd = fd;
}

int journal_send_fields(const struct journal_field *fields, size_t n)
{
	char buf[JOURNAL_MAX_ENTRY];
	size_t pos = 0;

	for (size_t i = 0; i < n; i++)
	{
		const struct journal_field *f = &fields[i];

		if (!f->key || !f->value)
			continue;

		size_t key_len = strlen(f->key);

		size_t needed = key_len + 1 + f->value_len + 1;
		if (pos + needed > sizeof(buf))
			return -EMSGSIZE;

		memcpy(buf + pos, f->key, key_len);
		pos += key_len;

		buf[pos++] = '=';

		const unsigned char *src = f->value;
		for (size_t j = 0; j < f->value_len; j++)
		{
			char c = (char)src[j];
			buf[pos++] = (c == '\n') ? ' ' : c;
		}

		buf[pos++] = '\n';
	}

	if (pos == 0)
		return 0;

	const int fd = journal_get_fd();
	if (fd < 0)
		return fd;

	ssize_t k = send(fd, buf, pos, MSG_NOSIGNAL);
	if (k >= 0)
		return 0;

	if (errno == EBADF || errno == ENOENT || errno == ECONNREFUSED)
		return 0;
	return -errno;
}

// Return 1 if this fd is associated with the journal socket to avoid
// dnsmasq closing it during initialization or on reload
int __attribute__((pure)) is_journal_fd(const int fd)
{
	return fd >= 0 && fd == journal_get_fd();
}

int journal_init(void)
{
	pthread_once(&journal_once, journal_init_once);

	const int fd = journal_get_fd();
	if (fd < 0)
		return -ENOTCONN;

	return 0;
}
