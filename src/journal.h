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

// Each expansion of J_FIELD_INT creates its own static __thread buffer
// uniquely named via __COUNTER__. This avoids shared mutable state
// between multiple J_FIELD_INT calls in the same compound literal
// initializer, whose evaluation order is unspecified (C11 6.7.9p23).
#define CONCAT2_(x, y) x ## y
#define CONCAT_(x, y) CONCAT2_(x, y)
#define J_FIELD_INT(k, val) J_FIELD_INT2_(k, val, __COUNTER__)
#define J_FIELD_INT2_(k, val, ctr) \
	({ \
		static __thread char CONCAT_(_jf_buf_, ctr)[16]; \
		int CONCAT_(_jf_n_, ctr) = snprintf(CONCAT_(_jf_buf_, ctr), sizeof(CONCAT_(_jf_buf_, ctr)), "%d", (val)); \
		(struct journal_field){ \
			.key = (k), \
			.value = CONCAT_(_jf_buf_, ctr), \
			.value_len = CONCAT_(_jf_n_, ctr) < 0 ? 0 : (size_t)CONCAT_(_jf_n_, ctr) \
		}; \
	})

int journal_init(void);
int journal_send_fields(const struct journal_field *fields, size_t n);
int is_journal_fd(const int fd);

#endif
