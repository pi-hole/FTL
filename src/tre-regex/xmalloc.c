/*
  xmalloc.c - Simple malloc debugging library implementation

  This software is released under a BSD-style license.
  See the file LICENSE for details and copyright.

*/

/*
  TODO:
   - red zones
   - group dumps by source location
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#define XMALLOC_INTERNAL 1
#include "xmalloc.h"


/*
  Internal stuff.
*/

typedef struct hashTableItemRec {
  uintptr_t addr;
  size_t size;
  const char *file;
  int line;
  const char *func;
  struct hashTableItemRec *next;
} hashTableItem;

typedef struct {
  hashTableItem **table;
} hashTable;

static unsigned int xmalloc_peak;
static unsigned int xmalloc_current;
static unsigned int xmalloc_peak_blocks;
static unsigned int xmalloc_current_blocks;
static unsigned int xmalloc_nins;
static unsigned int xmalloc_ndel;
static unsigned int xmalloc_ncoll;
static int xmalloc_fail_after;

#define TABLE_SIZE 8191

static hashTable *
hash_table_new(void)
{
  hashTable *tbl;

  tbl = malloc(sizeof(*tbl));

  if (tbl != NULL)
    {
      tbl->table = calloc(TABLE_SIZE, sizeof(*tbl->table));

      if (tbl->table == NULL)
	{
	  free(tbl);
	  return NULL;
	}
    }

  return tbl;
}

static uint32_t
adler32(const void *data, size_t len)
{
  const uint8_t *bytes;
  uint32_t c0, c1;

  for (bytes = data, c0 = 1, c1 = 0; len > 0; len--, bytes++)
    {
      c0 = (c0 + *bytes) % 65521;
      c1 = (c1 + c0) % 65521;
    }
  return c1 << 16 | c0;
}

static unsigned int
hash_addr(uintptr_t addr)
{
  return adler32(&addr, sizeof(addr)) % TABLE_SIZE;
}

static void
hash_table_add(hashTable *tbl, uintptr_t addr, size_t size,
	       const char *file, int line, const char *func)
{
  unsigned int i;
  hashTableItem *item, *new;

  i = hash_addr(addr);

  item = tbl->table[i];
  if (item != NULL)
    while (item->next != NULL)
      item = item->next;

  new = malloc(sizeof(*new));
  assert(new != NULL);
  new->addr = addr;
  new->size = size;
  new->file = file;
  new->line = line;
  new->func = func;
  new->next = NULL;
  if (item != NULL)
    {
      item->next = new;
      xmalloc_nins++;
      xmalloc_ncoll++;
    }
  else
    {
      tbl->table[i] = new;
      xmalloc_nins++;
    }

  xmalloc_current += size;
  if (xmalloc_current > xmalloc_peak)
    xmalloc_peak = xmalloc_current;
  xmalloc_current_blocks++;
  if (xmalloc_current_blocks > xmalloc_peak_blocks)
    xmalloc_peak_blocks = xmalloc_current_blocks;
}

static void
hash_table_del(hashTable *tbl, uintptr_t addr)
{
  hashTableItem *item, *prev;
  int i;

  i = hash_addr(addr);

  for (prev = NULL, item = tbl->table[i];
       item != NULL && item->addr != addr;
       prev = item, item = item->next)
    /* nothing */ ;
  if (item == NULL)
    {
      printf("xfree: invalid address %#lx\n", addr);
      abort();
    }

  xmalloc_current -= item->size;
  xmalloc_current_blocks--;

  if (prev != NULL)
    {
      prev->next = item->next;
      free(item);
    }
  else
    {
      tbl->table[i] = item->next;
      free(item);
    }
  xmalloc_ndel++;
}

static hashTable *xmalloc_table = NULL;

static void
xmalloc_init(void)
{
  if (xmalloc_table == NULL)
    {
      xmalloc_table = hash_table_new();
      xmalloc_peak = 0;
      xmalloc_peak_blocks = 0;
      xmalloc_current = 0;
      xmalloc_current_blocks = 0;
      xmalloc_nins = 0;
      xmalloc_ndel = 0;
      xmalloc_ncoll = 0;
      xmalloc_fail_after = -1;
    }
  assert(xmalloc_table != NULL);
  assert(xmalloc_table->table != NULL);
}



/*
  Public API.
*/

void
xmalloc_configure(int fail_after)
{
  xmalloc_init();
  xmalloc_fail_after = fail_after;
}

int
xmalloc_dump_leaks(void)
{
  unsigned int i;
  unsigned int num_leaks = 0;
  size_t leaked_bytes = 0;
  hashTableItem *item;

  xmalloc_init();

  for (i = 0; i < TABLE_SIZE; i++)
    {
      item = xmalloc_table->table[i];
      while (item != NULL)
	{
	  printf("%s:%d: %s: %zu bytes at %#lx not freed\n",
		 item->file, item->line, item->func, item->size, item->addr);
	  num_leaks++;
	  leaked_bytes += item->size;
	  item = item->next;
	}
    }
  if (num_leaks == 0)
    printf("No memory leaks.\n");
  else
    printf("%u unfreed memory chuncks, total %zu unfreed bytes.\n",
	   num_leaks, leaked_bytes);
  printf("Peak memory consumption %u bytes (%.1f kB, %.1f MB) in %u blocks ",
	 xmalloc_peak, (double)xmalloc_peak / 1024,
	 (double)xmalloc_peak / (1024*1024), xmalloc_peak_blocks);
  printf("(average ");
  if (xmalloc_peak_blocks)
    printf("%u", ((xmalloc_peak + xmalloc_peak_blocks / 2)
		  / xmalloc_peak_blocks));
  else
    printf("N/A");
  printf(" bytes per block).\n");

  printf("Hash table: %u inserts %u deletes %u collisions",
	 xmalloc_nins, xmalloc_ndel, xmalloc_ncoll);
  if (xmalloc_ncoll > 0)
    printf(" (%.2f%%)", 100.0 * xmalloc_ncoll / xmalloc_nins);
  printf("\n");

  return num_leaks;
}

void *
xmalloc_impl(size_t size, const char *file, int line, const char *func)
{
  void *ptr;

  xmalloc_init();
  assert(size > 0);

  if (xmalloc_fail_after == 0)
    {
      xmalloc_fail_after = -2;
#if 0
      printf("xmalloc: forced failure %s:%d: %s\n", file, line, func);
#endif
      return NULL;
    }
  else if (xmalloc_fail_after == -2)
    {
      printf("xmalloc: called after failure from %s:%d: %s\n",
	     file, line, func);
      assert(0);
    }
  else if (xmalloc_fail_after > 0)
    xmalloc_fail_after--;

  ptr = malloc(size);
  if (ptr != NULL)
    hash_table_add(xmalloc_table, (uintptr_t)ptr, size, file, line, func);
  return ptr;
}

void *
xcalloc_impl(size_t nmemb, size_t size, const char *file, int line,
	     const char *func)
{
  void *ptr;

  xmalloc_init();
  assert(size > 0);

  if (xmalloc_fail_after == 0)
    {
      xmalloc_fail_after = -2;
#if 0
      printf("xcalloc: forced failure %s:%d: %s\n", file, line, func);
#endif
      return NULL;
    }
  else if (xmalloc_fail_after == -2)
    {
      printf("xcalloc: called after failure from %s:%d: %s\n",
	     file, line, func);
      assert(0);
    }
  else if (xmalloc_fail_after > 0)
    xmalloc_fail_after--;

  ptr = calloc(nmemb, size);
  if (ptr != NULL)
    hash_table_add(xmalloc_table, (uintptr_t)ptr, nmemb * size, file, line, func);
  return ptr;
}

void
xfree_impl(void *ptr, const char *file, int line, const char *func)
{
  uintptr_t key = (uintptr_t)ptr;
  /*LINTED*/(void)&file;
  /*LINTED*/(void)&line;
  /*LINTED*/(void)&func;
  xmalloc_init();

  if (ptr != NULL)
    hash_table_del(xmalloc_table, key);
  free(ptr);
}

void *
xrealloc_impl(void *ptr, size_t new_size, const char *file, int line,
	      const char *func)
{
  uintptr_t key = (uintptr_t)ptr;
  void *new_ptr;

  xmalloc_init();
  assert(ptr != NULL);
  assert(new_size > 0);

  if (xmalloc_fail_after == 0)
    {
      xmalloc_fail_after = -2;
      return NULL;
    }
  else if (xmalloc_fail_after == -2)
    {
      printf("xrealloc: called after failure from %s:%d: %s\n",
	     file, line, func);
      assert(0);
    }
  else if (xmalloc_fail_after > 0)
    xmalloc_fail_after--;

  new_ptr = realloc(ptr, new_size);
  if (new_ptr != NULL && new_ptr != ptr)
    {
      hash_table_del(xmalloc_table, key);
      key = (uintptr_t)new_ptr;
      hash_table_add(xmalloc_table, key, new_size, file, line, func);
    }
  return new_ptr;
}



/* EOF */
