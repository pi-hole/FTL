// SPDX-License-Identifier: BSD-3-Clause

#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

void util_write_le64(unsigned char buf[static 8], uint64_t val);

int util_count_printf_conversions(const char *fmt);

#endif
