/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Minimal native journal protocol implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef JOURNAL_H
#define JOURNAL_H

#include <stddef.h>
#include <string.h>
#include <stdio.h>

struct journal_field {
	const char *key;
	const void *value;
	size_t value_len;
};

#define J_FIELD_STR(k, val) \
	{ \
		.key = (k), \
		.value = (val), \
		.value_len = strlen(val) \
	}

#define J_FIELD_INT(k, val) _jfield_int((k), (val))

int journal_init(void);
int journal_send_fields(const struct journal_field *fields, size_t n);
int is_journal_fd(const int fd);

static inline struct journal_field _jfield_int(const char *k, int val)
{
	enum { _JF_BUF = 16, _JF_POOL = 4 };
	static __thread char buf[_JF_POOL][_JF_BUF];
	static __thread unsigned idx;
	unsigned i = idx;
	idx = (idx + 1) % _JF_POOL;
	int n = snprintf(buf[i], _JF_BUF, "%d", val);
	return (struct journal_field){
		.key = k,
		.value = buf[i],
		.value_len = n < 0 ? 0 : (size_t)n
	};
}

#endif
