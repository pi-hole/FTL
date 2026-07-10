// SPDX-License-Identifier: BSD-3-Clause

#include "journal.h"

#include "encode.h"
#include "transport.h"
#include "util.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define MAX_IOV 64
#define FIELD_BUF 4096
#define MAX_KEY 256

static int send_impl(const char *format, va_list ap)
{
	if (!format)
		return -EINVAL;

	struct iovec iov[MAX_IOV * 4];
	char values[MAX_IOV][FIELD_BUF];
	char text_fields[MAX_IOV][FIELD_BUF + MAX_KEY + 2];
	char key_bufs[MAX_IOV][MAX_KEY + 1];
	unsigned char le_bufs[MAX_IOV][8];
	int n_iov = 0;
	int n_fields = 0;

	const char *f = format;
	while (f && n_fields < MAX_IOV)
	{
		const char *eq = strchr(f, '=');
		if (!eq)
			break;

		size_t key_len = (size_t)(eq - f);
		if (key_len == 0 || key_len > MAX_KEY)
		{
			util_consume_va_args(ap, f);
			f = va_arg(ap, const char *);
			continue;
		}

		if (encode_validate_key(f, key_len) < 0)
		{
			util_consume_va_args(ap, f);
			f = va_arg(ap, const char *);
			continue;
		}

		const char *value_fmt = eq + 1;
		int n_args = util_count_printf_conversions(value_fmt);

		char *value_buf = values[n_fields];
		int value_len;

		if (n_args > 0)
		{
			va_list copy;
			va_copy(copy, ap);
			value_len = vsnprintf(value_buf, FIELD_BUF, value_fmt, copy);
			va_end(copy);

			if (value_len < 0)
			{
				util_consume_va_args(ap, f);
				f = va_arg(ap, const char *);
				continue;
			}
			if ((size_t)value_len >= FIELD_BUF)
				value_len = FIELD_BUF - 1;
			value_buf[value_len] = '\0';
		}
		else
		{
			size_t vlen = strlen(value_fmt);
			if (vlen >= FIELD_BUF)
				vlen = FIELD_BUF - 1;
			memcpy(value_buf, value_fmt, vlen);
			value_buf[vlen] = '\0';
			value_len = (int)vlen;
		}

		value_len = (int)encode_trim_trailing_whitespace(value_buf, (size_t)value_len);

		if (encode_needs_binary(value_buf, (size_t)value_len))
		{
			int idx = n_iov;
			int r = encode_binary(iov, MAX_IOV * 4, &idx, f, key_len, value_buf, (size_t)value_len,
								  key_bufs[n_fields], le_bufs[n_fields]);
			if (r < 0)
			{
				util_consume_va_args(ap, f);
				f = va_arg(ap, const char *);
				continue;
			}
			n_iov = idx;
		}
		else
		{
			char *field_buf = text_fields[n_fields];
			int len = encode_text(field_buf, sizeof(text_fields[n_fields]), f, key_len, value_buf,
								  (size_t)value_len);
			if (len < 0)
			{
				util_consume_va_args(ap, f);
				f = va_arg(ap, const char *);
				continue;
			}
			iov[n_iov].iov_base = field_buf;
			iov[n_iov].iov_len = (size_t)len;
			n_iov++;
		}

		n_fields++;

		util_consume_va_args(ap, value_fmt);
		f = va_arg(ap, const char *);
	}

	if (n_iov == 0)
		return -EINVAL;

	return transport_send(iov, n_iov);
}

int journal_init(void)
{
	return transport_init();
}

void journal_close(void)
{
	transport_close();
}

int journal_get_fd(void)
{
	return transport_get_fd();
}

int journal_print(int priority, const char *format, ...)
{
	if (!format)
		return -EINVAL;

	char msg[FIELD_BUF];
	char msg_field[64 + FIELD_BUF];
	char prio_val[16];
	char prio_field[32];
	unsigned char le_buf[8];
	char key_buf[8];
	struct iovec iov[8];
	int n_iov = 0;

	va_list ap;
	va_start(ap, format);
	int msg_len = vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);

	if (msg_len < 0)
		return -EINVAL;
	if ((size_t)msg_len >= sizeof(msg))
		msg_len = (int)sizeof(msg) - 1;

	msg_len = (int)encode_trim_trailing_whitespace(msg, (size_t)msg_len);

	if (encode_needs_binary(msg, (size_t)msg_len))
	{
		int idx = n_iov;
		int r = encode_binary(iov, 8, &idx, "MESSAGE", 7, msg, (size_t)msg_len, key_buf, le_buf);
		if (r < 0)
			return r;
		n_iov = idx;
	}
	else
	{
		int len = encode_text(msg_field, sizeof(msg_field), "MESSAGE", 7, msg, (size_t)msg_len);
		if (len < 0)
			return -EINVAL;
		iov[n_iov].iov_base = msg_field;
		iov[n_iov].iov_len = (size_t)len;
		n_iov++;
	}

	int prio_len = snprintf(prio_val, sizeof(prio_val), "%d", priority);
	if (prio_len < 0)
		return -EINVAL;

	int pfl =
		encode_text(prio_field, sizeof(prio_field), "PRIORITY", 8, prio_val, (size_t)prio_len);
	if (pfl < 0)
		return -EINVAL;
	iov[n_iov].iov_base = prio_field;
	iov[n_iov].iov_len = (size_t)pfl;
	n_iov++;

	return transport_send(iov, n_iov);
}

int journal_send(const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	int r = send_impl(format, ap);
	va_end(ap);
	return r;
}

int journal_sendv(const struct iovec *iov, int n)
{
	if (n < 0)
		return -EINVAL;
	if (n == 0)
		return 0;
	return transport_send(iov, n);
}
