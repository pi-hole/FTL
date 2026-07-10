// SPDX-License-Identifier: BSD-3-Clause

#include "encode.h"

#include "util.h"

#include <errno.h>
#include <string.h>

int encode_validate_key(const char *key, size_t len)
{
	if (!key || len == 0)
		return -EINVAL;

	if (key[0] == '_')
		return -EINVAL;

	for (size_t i = 0; i < len; i++)
	{
		unsigned char c = (unsigned char)key[i];
		if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
			return -EINVAL;
	}

	return 0;
}

int encode_needs_binary(const void *data, size_t len)
{
	if (!data)
		return 0;

	const unsigned char *p = (const unsigned char *)data;

	for (size_t i = 0; i < len; i++)
	{
		if (p[i] == '\n' || p[i] == '\0')
			return 1;
	}

	return 0;
}

int encode_text(char *buf, size_t buf_size, const char *key, size_t key_len, const void *value,
				size_t value_len)
{
	if (!buf || !buf_size || !key || !key_len)
		return -EINVAL;

	if (!value)
		value_len = 0;

	size_t needed = key_len + 1 + value_len + 1;
	if (needed > buf_size)
		return -ENOSPC;

	memcpy(buf, key, key_len);
	buf[key_len] = '=';
	if (value_len > 0)
		memcpy(buf + key_len + 1, value, value_len);
	buf[key_len + 1 + value_len] = '\n';

	if (needed < buf_size)
		buf[needed] = '\0';

	return (int)needed;
}

int encode_binary(struct iovec *iov, int iov_cap, int *idx, const char *key, size_t key_len,
				  const void *value, size_t value_len, char key_buf[/* key_len + 1 */],
				  unsigned char le_buf[static 8])
{
	if (!iov || !idx || !key || !key_len || !key_buf)
		return -EINVAL;

	if (*idx + 4 > iov_cap)
		return -ENOSPC;

	if (!value)
		value_len = 0;

	memcpy(key_buf, key, key_len);
	key_buf[key_len] = '\n';

	util_write_le64(le_buf, (uint64_t)value_len);

	static const char newline = '\n';

	iov[*idx].iov_base = key_buf;
	iov[*idx].iov_len = key_len + 1;
	(*idx)++;

	iov[*idx].iov_base = le_buf;
	iov[*idx].iov_len = 8;
	(*idx)++;

	iov[*idx].iov_base = (void *)value;
	iov[*idx].iov_len = value_len;
	(*idx)++;

	iov[*idx].iov_base = (void *)&newline;
	iov[*idx].iov_len = 1;
	(*idx)++;

	return 0;
}

size_t encode_trim_trailing_whitespace(char *s, size_t len)
{
	if (!s || len == 0)
		return len;

	while (len > 0)
	{
		unsigned char c = (unsigned char)s[len - 1];
		if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
			len--;
		else
			break;
	}

	s[len] = '\0';
	return len;
}
