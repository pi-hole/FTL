/*
 * tre-filter.h - Histogram filter definitions
 *
 * This software is released under a BSD-style license.
 * See the file LICENSE for details and copyright.
 */

#ifndef TRE_FILTER_H
#define TRE_FILTER_H

typedef struct {
  unsigned char ch;
  unsigned char count;
} tre_filter_profile_t;

typedef struct {
  /* Length of the window where the character counts are kept. */
  int window_len;
  /* Required character counts table. */
  tre_filter_profile_t *profile;
} tre_filter_t;

int
tre_filter_find(const unsigned char *str, size_t len, tre_filter_t *filter);

#endif /* TRE_FILTER_H */

/* EOF */
