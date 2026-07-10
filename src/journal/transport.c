// SPDX-License-Identifier: BSD-3-Clause

#include "transport.h"

#include <errno.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#define JOURNAL_SOCKET_PATH "/run/systemd/journal/socket"
#define JOURNAL_SNDBUF_SIZE (256U * 1024U)
#define JOURNAL_MAX_DGRAM (128U * 1024U)

static _Atomic int g_fd = -1;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static int socket_create(void)
{
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	int sndbuf = JOURNAL_SNDBUF_SIZE;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

	return fd;
}

static int socket_connect(int fd)
{
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	size_t path_len = sizeof(JOURNAL_SOCKET_PATH) - 1;
	if (path_len >= sizeof(addr.sun_path))
	{
		return -ENAMETOOLONG;
	}
	memcpy(addr.sun_path, JOURNAL_SOCKET_PATH, path_len);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -errno;

	return 0;
}

static int create_memfd(void)
{
	return (int)syscall(SYS_memfd_create, "libjournal", MFD_CLOEXEC);
}

static int transport_send_memfd(int fd, const struct iovec *iov, int iov_len, size_t total)
{
	int memfd = create_memfd();
	if (memfd < 0)
		return -errno;

	ssize_t written;
	do
	{
		written = writev(memfd, iov, iov_len);
	} while (written < 0 && errno == EINTR);

	if (written < 0 || (size_t)written != total)
	{
		int err = (written < 0) ? errno : EIO;
		close(memfd);
		return -err;
	}

	if (lseek(memfd, 0, SEEK_SET) == -1)
	{
		int err = errno;
		close(memfd);
		return -err;
	}

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));

	char dummy = 0;
	struct iovec dummy_iov;
	dummy_iov.iov_base = &dummy;
	dummy_iov.iov_len = 1;
	msg.msg_iov = &dummy_iov;
	msg.msg_iovlen = 1;

	char cmsg_buf[CMSG_SPACE(sizeof(int))];
	msg.msg_control = cmsg_buf;
	msg.msg_controllen = sizeof(cmsg_buf);

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &memfd, sizeof(memfd));
	msg.msg_controllen = cmsg->cmsg_len;

	ssize_t r;
	do
	{
		r = sendmsg(fd, &msg, MSG_NOSIGNAL);
	} while (r < 0 && errno == EINTR);

	int err = r < 0 ? errno : 0;
	close(memfd);
	return err ? -err : 0;
}

int transport_init(void)
{
	if (atomic_load_explicit(&g_fd, memory_order_acquire) >= 0)
		return 0;

	pthread_mutex_lock(&g_init_mutex);

	if (atomic_load_explicit(&g_fd, memory_order_relaxed) >= 0)
	{
		pthread_mutex_unlock(&g_init_mutex);
		return 0;
	}

	int fd = socket_create();
	if (fd < 0)
	{
		int err = errno;
		pthread_mutex_unlock(&g_init_mutex);
		return -err;
	}

	int r = socket_connect(fd);
	if (r < 0)
	{
		close(fd);
		pthread_mutex_unlock(&g_init_mutex);
		return r;
	}

	if (r == 0)
	{
		atomic_store_explicit(&g_fd, fd, memory_order_release);
	}

	pthread_mutex_unlock(&g_init_mutex);
	return 0;
}

void transport_close(void)
{
	int fd = atomic_exchange_explicit(&g_fd, -1, memory_order_acq_rel);
	if (fd >= 0)
		close(fd);
}

int transport_get_fd(void)
{
	return atomic_load_explicit(&g_fd, memory_order_acquire);
}

int transport_send(const struct iovec *iov, int iov_len)
{
	size_t total = 0;
	for (int i = 0; i < iov_len; i++)
		total += iov[i].iov_len;

	int fd = atomic_load_explicit(&g_fd, memory_order_acquire);
	if (fd < 0)
		return -ENOTCONN;

	if (total > JOURNAL_MAX_DGRAM)
		return transport_send_memfd(fd, iov, iov_len, total);

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = (struct iovec *)iov;
	msg.msg_iovlen = iov_len;

	ssize_t r;
	do
	{
		r = sendmsg(fd, &msg, MSG_NOSIGNAL);
	} while (r < 0 && errno == EINTR);

	if (r >= 0)
		return 0;

	int err = errno;

	if (err == EMSGSIZE)
		return transport_send_memfd(fd, iov, iov_len, total);

	if (err == ECONNREFUSED || err == ENOTCONN || err == EPIPE)
	{
		pthread_mutex_lock(&g_init_mutex);

		if (atomic_load_explicit(&g_fd, memory_order_relaxed) == fd)
		{
			close(fd);
			atomic_store_explicit(&g_fd, -1, memory_order_release);

			int new_fd = socket_create();
			if (new_fd >= 0)
			{
				int cr = socket_connect(new_fd);
				if (cr == 0)
				{
					atomic_store_explicit(&g_fd, new_fd, memory_order_release);
					fd = new_fd;
					err = 0;
				}
				else
				{
					err = -cr;
					close(new_fd);
				}
			}
			else
			{
				err = errno;
			}
		}
		else
		{
			fd = atomic_load_explicit(&g_fd, memory_order_relaxed);
			if (fd >= 0)
				err = 0;
		}

		pthread_mutex_unlock(&g_init_mutex);

		if (err)
			return -err;

		if (total > JOURNAL_MAX_DGRAM)
			return transport_send_memfd(fd, iov, iov_len, total);

		msg.msg_iov = (struct iovec *)iov;
		msg.msg_iovlen = iov_len;

		do
		{
			r = sendmsg(fd, &msg, MSG_NOSIGNAL);
		} while (r < 0 && errno == EINTR);

		if (r >= 0)
			return 0;

		err = errno;
		if (err == EMSGSIZE)
			return transport_send_memfd(fd, iov, iov_len, total);

		return -err;
	}

	return -err;
}
