// SPDX-License-Identifier: BSD-3-Clause

#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <sys/uio.h>

int transport_init(void);

void transport_close(void);

int transport_get_fd(void) __attribute__((pure));

int transport_send(const struct iovec *iov, int iov_len);

#endif
