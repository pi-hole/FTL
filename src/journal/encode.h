// SPDX-License-Identifier: BSD-3-Clause

#ifndef ENCODE_H
#define ENCODE_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

int encode_validate_key(const char *key, size_t len);

int encode_needs_binary(const void *data, size_t len);

int encode_text(char *buf, size_t buf_size, const char *key, size_t key_len, const void *value,
				size_t value_len);

int encode_binary(struct iovec *iov, int iov_cap, int *idx, const char *key, size_t key_len,
				  const void *value, size_t value_len, char key_buf[/* key_len + 1 */],
				  unsigned char le_buf[static 8]);

size_t encode_trim_trailing_whitespace(char *s, size_t len);

#endif
