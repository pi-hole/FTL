/* Copyright (c) 2024-2026, CK Tan.
 * https://github.com/cktan/tomlc17/blob/main/LICENSE
 */
#include "tomlc17.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const toml_datum_t DATUM_ZERO = {0};

static toml_option_t toml_option = {0, realloc, free};

#define MALLOC(n) toml_option.mem_realloc(0, n)
#define REALLOC(p, n) toml_option.mem_realloc(p, n)
#define FREE(p) toml_option.mem_free(p)

#define DO(x)                                                                  \
  if (x)                                                                       \
    return -1;                                                                 \
  else                                                                         \
    (void)0

// Copy string src to dst where dst is limited to dstsz that includes
// NUL. Return 0 on success, -1 otherwise (because src[] is longer than dst[]).
static inline int copystring(char *dst, int dstsz, const char *src) {
  int srcsz = strlen(src) + 1;
  if (srcsz > dstsz) {
    return -1;
  }
  memcpy(dst, src, srcsz);
  return 0;
}

/*
 *  Error buffer
 */
typedef struct ebuf_t ebuf_t;
struct ebuf_t {
  char *ptr;
  int len;
};

/*
 *  Format an error into ebuf[]. Always return -1.
 */
static int SETERROR(ebuf_t ebuf, int lineno, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char *p = ebuf.ptr;
  char *q = p + ebuf.len;
  if (lineno) {
    snprintf(p, p < q ? q - p : 0, "(line %d) ", lineno);
    p += strlen(p);
  }
  vsnprintf(p, p < q ? q - p : 0, fmt, args);
  va_end(args);
  return -1;
}

/*
 *  Memory pool. A pool is a pair of page_t lists: small allocations
 *  (<= PAGE_LARGE_THRESHOLD bytes) are bump-allocated out of
 *  PAGE_SMALL_SIZE pages, handed out piecemeal until a page fills up
 *  and a fresh one is linked in front. Large allocations get their
 *  own exactly-sized page, used once and never shared. This avoids
 *  ever mallocing one giant block sized for the whole document.
 */
#define PAGE_SMALL_SIZE 4096
#define PAGE_LARGE_THRESHOLD 1024
// Small allocations must always fit in a fresh small page.
static_assert(PAGE_SMALL_SIZE > PAGE_LARGE_THRESHOLD,
              "page/threshold invariant");

#define PAGE_MAGIC 0x50414745u // "PAGE"

typedef struct page_t page_t;
struct page_t {
  uint32_t magic; // PAGE_MAGIC, checked to catch corruption/use-after-free
  int top;        // offset of first free byte in data[]
  int max;        // size of data[]
  page_t *next;   // link to next page in list
  char data[1];   // first byte starts here
};

#define POOL_MAGIC 0x504f4f4cu // "POOL"

typedef struct pool_t pool_t;
struct pool_t {
  uint32_t magic; // POOL_MAGIC, checked to catch corruption/use-after-free
  page_t *small;  // most recent small page, bump-allocated piecemeal
  page_t *large;  // most recent large page, each used for one alloc only
};

/**
 *  Create a page of `size` bytes. Return the page on success, or
 *  NULL if out of memory.
 */
static page_t *page_create(int size) {
  if (!(0 <= size && size <= (1 << 30))) { // [0..1GB]
    return NULL;
  }
  size_t totalsz = (size_t)&((page_t *)0)->data[size];
  page_t *page = MALLOC(totalsz);
  if (!page) {
    return NULL;
  }
  page->magic = PAGE_MAGIC;
  page->top = 0;
  page->max = size;
  page->next = NULL;
  return page;
}

/**
 *  Create an empty memory pool. Return the memory pool on success,
 *  or NULL if out of memory. pool->small is always non-NULL: a
 *  pool holds at least one small page for its whole lifetime.
 */
static pool_t *pool_create(void) {
  pool_t *pool = MALLOC(sizeof(pool_t));
  if (!pool) {
    return NULL;
  }
  pool->magic = POOL_MAGIC;
  pool->small = page_create(PAGE_SMALL_SIZE);
  if (!pool->small) {
    FREE(pool);
    return NULL;
  }
  pool->large = NULL;
  return pool;
}

/**
 *  Destroy a memory pool, freeing every page in it.
 */
static void pool_destroy(pool_t *pool) {
  if (!pool) {
    return;
  }
  assert(pool->magic == POOL_MAGIC);
  pool->magic = 0; // catch use-after-free/double-destroy
  for (page_t *p = pool->small; p;) {
    page_t *next = p->next;
    assert(p->magic == PAGE_MAGIC);
    p->magic = 0; // catch use-after-free/double-destroy
    FREE(p);
    p = next;
  }
  for (page_t *p = pool->large; p;) {
    page_t *next = p->next;
    assert(p->magic == PAGE_MAGIC);
    p->magic = 0; // catch use-after-free/double-destroy
    FREE(p);
    p = next;
  }
  FREE(pool);
}

/**
 *  Allocate n bytes from pool. Return the memory allocated on
 *  success, or NULL if out of memory.
 */
static char *pool_alloc(pool_t *pool, int n) {
  assert(pool->magic == POOL_MAGIC);
  if (n > PAGE_LARGE_THRESHOLD) {
    // Large alloc: own exactly-sized page, used once.
    page_t *page = page_create(n);
    if (!page) {
      return NULL;
    }
    page->next = pool->large;
    pool->large = page;
    page->top = page->max;
    return page->data;
  }

  assert(pool->small->magic == PAGE_MAGIC);
  if (pool->small->top + n > pool->small->max) {
    // Current small page doesn't have room: abandon its leftover
    // space and start a fresh one.
    page_t *page = page_create(PAGE_SMALL_SIZE);
    if (!page) {
      return NULL;
    }
    page->next = pool->small;
    pool->small = page;
  }
  char *ret = pool->small->data + pool->small->top;
  pool->small->top += n;
  return ret;
}

// Cell: expandable buffer that behaves like realloc
typedef struct cell_t cell_t;
struct cell_t {
  uint32_t top, max;
  // first byte of data starts here (i.e. &(*this)[1])
};

static char *cell_realloc(char *p, int size) {
  assert(size >= 0);
  if (p == NULL) {
    // first malloc
    cell_t *tmp = REALLOC(NULL, size + sizeof(cell_t));
    if (!tmp) {
      return 0; // out of memory
    }
    cell_t *cp = tmp;
    cp->max = size;
    cp->top = size;
    return (char *)&cp[1];
  }

  // obtain a handle to cell info
  cell_t *cp = (cell_t *)(p - sizeof(cell_t));
  if ((uint32_t)size <= cp->max) {
    // cell is big enough for the new size. DONE.
    cp->top = size;
    return p;
  }

  // need to expand. add 30% margin.
  int newmax = size * 1.3 + 100;
  cell_t *tmp = REALLOC(cp, newmax + sizeof(cell_t));
  if (!tmp) {
    return 0; // out of memory
  }
  cp = tmp;
  cp->max = newmax;
  cp->top = size;
  return (char *)&cp[1];
}

static void cell_free(char *p) {
  if (p) {
    cell_t *cp = (cell_t *)(p - sizeof(cell_t));
    FREE(cp);
  }
}

/* This is a string view. */
typedef struct span_t span_t;
struct span_t {
  const char *ptr;
  int len;
};

/* Represents a multi-part key */
#define KEYPARTMAX 10
typedef struct keypart_t keypart_t;
struct keypart_t {
  int nspan;
  span_t span[KEYPARTMAX];
};

static int utf8_to_ucs(const char *s, int len, uint32_t *ret);
static int ucs_to_utf8(uint32_t code, char buf[4]);

// Maximum levels of brackets and braces to prevent
// stack overflow during recursive descent of the parser.
#define BRACKET_LEVEL_MAX 30
#define BRACE_LEVEL_MAX 30
#define TABLE_MAX (1 << 14) // 16k
#define ARRAY_MAX (1 << 14) // 16k

// Buffer size for scanning a number or a timestamp. TOML does not limit the
// length of either literal; tomlc17 does, like the limits above: a literal that
// fills the buffer is rejected as too long, so LITBUF_SIZE - 2 bytes is the
// longest one accepted. That accommodates "9_007_199_254_740_991.0",
// picosecond-precision timestamps, and every other spelling of ordinary length.
// The checks test the length of the literal itself, not of the copy, because
// scan_copystr() also copies whatever follows the literal.
#define LITBUF_SIZE 120

enum toktyp_t {
  TOK_DOT = 1,
  TOK_EQUAL,
  TOK_COMMA,
  TOK_LBRACK,  // [
  TOK_LLBRACK, // [[
  TOK_RBRACK,  // ]
  TOK_RRBRACK, // ]]
  TOK_LBRACE,  // {
  TOK_RBRACE,  // }
  TOK_LIT,
  TOK_STRING,      // "string"
  TOK_MLSTRING,    // """multi-line-string"""
  TOK_LITSTRING,   // 'lit-string'
  TOK_MLLITSTRING, // '''multi-line-lit-string'''
  TOK_TIME,
  TOK_DATE,
  TOK_DATETIME,
  TOK_DATETIMETZ,
  TOK_INTEGER,
  TOK_FLOAT,
  TOK_BOOL,
  TOK_ENDL,
  TOK_FIN = -5000, // EOF
};
typedef enum toktyp_t toktyp_t;
typedef struct scanner_t scanner_t;

/* Remember the current state of a scanner */
typedef struct scanner_state_t scanner_state_t;
struct scanner_state_t {
  scanner_t *sp;
  const char *cur; // points into scanner_t::src[]
  int lineno;      // current line number
  const char *line_start;
};

// A scan token
typedef struct token_t token_t;
struct token_t {
  toktyp_t toktyp;
  int lineno;
  int colno;
  span_t str;

  // values represented by str
  union {
    const char *escp; // point to an esc char in str
    int64_t int64;
    double fp64;
    bool b1;
    struct {
      // validity depends on toktyp for TIME, DATE, DATETIME, DATETIMETZ
      int year, month, day, hour, minute, sec, usec;
      int tz; // +- minutes
    } tsval;
  } u;
};

// Scanner object
struct scanner_t {
  const char *src;  // src[]
  const char *endp; // end of src[], i.e. src + len
  const char *cur;  // current char in src[]
  int lineno;       // line number of current char
  const char *line_start;
  char *errmsg; // set to ebuf.ptr if there was an error
  ebuf_t ebuf;  // buffer to store error message

  int bracket_level; // count depth of [ ]
  int brace_level;   // count depth of { }
};
static void scan_init(scanner_t *sp, const char *src, int len, char *errbuf,
                      int errbufsz);
static int scan_key(scanner_t *sp, token_t *tok);
static int scan_value(scanner_t *sp, token_t *tok);
// restore scanner to state before tok was returned
static scanner_state_t scan_mark(scanner_t *sp);
static void scan_restore(scanner_t *sp, scanner_state_t state);

#ifndef min
static inline int min(int a, int b) { return a < b ? a : b; }
#endif

// Copy up to dstsz - 1 chars from the current position of the scanner
// to dst, and always terminate dst[] with a NUL if dstsz > 0.
static void scan_copystr(scanner_t *sp, char *dst, int dstsz) {
  assert(dstsz > 0);
  int len = min(sp->endp - sp->cur, dstsz - 1); // account for NUL
  if (len > 0) {
    memcpy(dst, sp->cur, len);
    dst[len] = '\0';
  }
}

// Parser object
typedef struct parser_t parser_t;
struct parser_t {
  scanner_t scanner;
  toml_datum_t toptab;  // top table
  toml_datum_t *curtab; // current table
  pool_t *pool;         // memory pool for strings
  const char *srcname;  // source name copied into the pool, or NULL
  ebuf_t ebuf;          // buffer to store last error message
};

// Find key in tab and return its index. If not found, return -1.
static int tab_find(toml_datum_t *tab, span_t key) {
  assert(tab->type == TOML_TABLE);
  for (int i = 0, top = tab->u.tab.size; i < top; i++) {
    if (tab->u.tab.len[i] == key.len &&
        0 == memcmp(tab->u.tab.key[i], key.ptr, key.len)) {
      return i;
    }
  }
  return -1;
}

// Put key into tab dictionary. Return a pointer to the datum for the key.
// If the key already exists, returns a pointer to its existing datum (the
// datum is NOT zeroed — callers must check datum->type to detect duplicates).
// If the key is new, appends it with a zero datum and returns a pointer to it.
// Returns NULL on allocation failure.
//
// Dual-use: tab_add() uses the non-zero type to detect and reject duplicates;
// datum_copy/datum_merge() use it to locate or create a slot for writing.
static toml_datum_t *tab_emplace(toml_datum_t *tab, span_t key,
                                 const char **reason) {
  assert(tab->type == TOML_TABLE);
  int i = tab_find(tab, key);
  if (i >= 0) {
    return &tab->u.tab.value[i];
  }

  // Expand pkey[], plen[] and value[].
  int N = tab->u.tab.size;
  if (N >= TABLE_MAX) {
    *reason = "table too large";
    return NULL;
  }

  {
    char **pkey =
        (char **)cell_realloc((char *)tab->u.tab.key, sizeof(*pkey) * (N + 1));
    int *plen =
        (int *)cell_realloc((char *)tab->u.tab.len, sizeof(*plen) * (N + 1));
    toml_datum_t *value = (toml_datum_t *)cell_realloc(
        (char *)tab->u.tab.value, sizeof(*value) * (N + 1));

    // on success, must save new pointers in tab->u.tab because the
    // old memory areas are gone.
    if (pkey) {
      tab->u.tab.key = (const char **)pkey;
    }
    if (plen) {
      tab->u.tab.len = plen;
    }
    if (value) {
      tab->u.tab.value = value;
    }

    // if any fail, it is safe to bail out.
    if (!pkey || !plen || !value) {
      *reason = "out of memory";
      return NULL;
    }
  }

  // There is sufficient space in all the arrays for one more element.
  // Append the new key. The value is set to DATUM_ZERO. Caller will
  // overwrite with a valid datum.
  tab->u.tab.size = N + 1;
  tab->u.tab.key[N] = (char *)key.ptr;
  tab->u.tab.len[N] = key.len;
  tab->u.tab.value[N] = DATUM_ZERO;
  return &tab->u.tab.value[N];
}

// Add a new key in tab. Return 0 on success, -1 otherwise.
// On error, *reason will point to an error message.
static int tab_add(toml_datum_t *tab, span_t newkey, toml_datum_t newvalue,
                   const char **reason) {
  assert(tab->type == TOML_TABLE);
  toml_datum_t *pvalue = tab_emplace(tab, newkey, reason);
  if (!pvalue) {
    return -1;
  }
  if (pvalue->type) {
    *reason = "duplicate key";
    return -1;
  }
  *pvalue = newvalue;
  return 0;
}

// Add a new element into an array. Return 0 on success, -1 otherwise.
// On error, *reason will point to an error message.
static toml_datum_t *arr_emplace(toml_datum_t *arr, const char **reason) {
  assert(arr->type == TOML_ARRAY);
  int n = arr->u.arr.size;
  if (n >= ARRAY_MAX) {
    *reason = "array too large";
    return NULL;
  }
  toml_datum_t *elem = (toml_datum_t *)cell_realloc((char *)arr->u.arr.elem,
                                                    sizeof(*elem) * (n + 1));
  if (!elem) {
    *reason = "out of memory";
    return NULL;
  }
  arr->u.arr.elem = elem;
  arr->u.arr.size = n + 1;
  elem[n] = DATUM_ZERO;
  return &elem[n];
}

// ------------------- parser section
static int parse_norm(parser_t *pp, token_t tok, span_t *ret_span);
static int parse_val(parser_t *pp, token_t tok, toml_datum_t *ret);
static int parse_keyvalue_expr(parser_t *pp, token_t tok);
static int parse_std_table_expr(parser_t *pp, token_t tok);
static int parse_array_table_expr(parser_t *pp, token_t tok);

static toml_datum_t mkdatum(toml_type_t ty) {
  toml_datum_t ret = {0};
  ret.type = ty;
  if (ty == TOML_DATE || ty == TOML_TIME || ty == TOML_DATETIME ||
      ty == TOML_DATETIMETZ) {
    ret.u.ts.year = -1;
    ret.u.ts.month = -1;
    ret.u.ts.day = -1;
    ret.u.ts.hour = -1;
    ret.u.ts.minute = -1;
    ret.u.ts.second = -1;
    ret.u.ts.usec = -1;
    ret.u.ts.tz = -1;
  }
  return ret;
}

static toml_datum_t mkdatum_at(toml_type_t ty, int lineno, int colno) {
  toml_datum_t ret = mkdatum(ty);
  ret.lineno = lineno;
  ret.colno = colno;
  return ret;
}

// Recursively free any dynamically allocated memory in the datum tree
static void datum_free(toml_datum_t *datum) {
  if (datum->type == TOML_TABLE) {
    for (int i = 0, top = datum->u.tab.size; i < top; i++) {
      datum_free(&datum->u.tab.value[i]);
    }
    cell_free((char *)(void *)datum->u.tab.key);
    cell_free((char *)datum->u.tab.len);
    cell_free((char *)datum->u.tab.value);
  } else if (datum->type == TOML_ARRAY) {
    for (int i = 0, top = datum->u.arr.size; i < top; i++) {
      datum_free(&datum->u.arr.elem[i]);
    }
    cell_free((char *)datum->u.arr.elem);
  }
  // other types do not allocate memory
  *datum = DATUM_ZERO;
}

// Maps each distinct source-name pointer to a single copy in the destination
// pool (deduplicated), so the merged pool holds at most one copy per distinct
// source pointer. Dedup is by pointer identity, not string content: every
// datum from one parse shares one source pointer (set_source_recursive), so
// dedup is exact within a tree, but two trees with content-identical source
// names (e.g. the same filename parsed twice) still get separate copies.
typedef struct srcmap_t srcmap_t;
struct srcmap_t {
  pool_t *pool;
  const char **olds; // cell buffer of old pointers
  const char **news; // cell buffer of new (copied) pointers
  int n, cap;
};

// Returns the deduplicated copy of src, or NULL for a NULL input or on
// out-of-memory. Callers distinguish the two: a non-NULL src that yields NULL
// is a hard failure.
static const char *dedup_source(srcmap_t *m, const char *src) {
  if (!src) {
    return NULL;
  }
  // Pointer-identity match (see srcmap_t above). The scan is O(n) in the
  // number of distinct source pointers seen so far, not in the (much
  // larger) number of datums, since repeats short-circuit here.
  for (int i = 0; i < m->n; i++) {
    if (m->olds[i] == src) {
      return m->news[i];
    }
  }
  // Grow the memo first, so an allocation failure aborts cleanly.
  if (m->n == m->cap) {
    int newcap = m->cap ? m->cap * 2 : 4;
    const char **no =
        (const char **)cell_realloc((char *)m->olds, sizeof(*no) * newcap);
    if (!no) {
      return NULL; // out of memory
    }
    m->olds = no;
    const char **nn =
        (const char **)cell_realloc((char *)m->news, sizeof(*nn) * newcap);
    if (!nn) {
      return NULL; // out of memory
    }
    m->news = nn;
    m->cap = newcap;
  }
  int len = (int)strlen(src) + 1;
  char *p = pool_alloc(m->pool, len);
  if (!p) {
    return NULL; // out of memory
  }
  memcpy(p, src, len);
  m->olds[m->n] = src;
  m->news[m->n] = p;
  m->n++;
  return p;
}

// Make a deep copy of src to dst.
// Return 0 on success, -1 otherwise.
static int datum_copy(toml_datum_t *dst, toml_datum_t src, srcmap_t *sm,
                      const char **reason) {
  *dst = mkdatum_at(src.type, src.lineno, src.colno);
  dst->flag = src.flag;
  switch (src.type) {
  case TOML_STRING:
    // String bytes live in src's pool; copy them into dst's pool so dst
    // stays independently owned.
    dst->u.str.ptr = pool_alloc(sm->pool, src.u.str.len + 1);
    if (!dst->u.str.ptr) {
      *reason = "out of memory";
      goto bail;
    }
    dst->u.str.len = src.u.str.len;
    memcpy((char *)dst->u.str.ptr, src.u.str.ptr, src.u.str.len + 1);
    break;
  case TOML_TABLE:
    // Recreate each entry in dst: the key bytes are pool-copied (like a
    // string value), and the value is deep-copied recursively.
    for (int i = 0; i < src.u.tab.size; i++) {
      char *keycopy = pool_alloc(sm->pool, src.u.tab.len[i] + 1);
      if (!keycopy) {
        *reason = "out of memory";
        goto bail;
      }
      memcpy(keycopy, src.u.tab.key[i], src.u.tab.len[i] + 1);
      span_t newkey = {keycopy, src.u.tab.len[i]};
      toml_datum_t *pvalue = tab_emplace(dst, newkey, reason);
      if (!pvalue) {
        goto bail;
      }
      if (datum_copy(pvalue, src.u.tab.value[i], sm, reason)) {
        goto bail;
      }
    }
    break;
  case TOML_ARRAY:
    // Deep-copy each element into a freshly emplaced slot in dst.
    for (int i = 0; i < src.u.arr.size; i++) {
      toml_datum_t *pelem = arr_emplace(dst, reason);
      if (!pelem) {
        goto bail;
      }
      if (datum_copy(pelem, src.u.arr.elem[i], sm, reason)) {
        goto bail;
      }
    }
    break;
  default:
    // Every other type (int, float, bool, timestamp, invalid) is a plain
    // value with no pool-owned pointers, so a struct copy is a full copy.
    *dst = src;
    break;
  }

  dst->source = dedup_source(sm, src.source);
  if (src.source && !dst->source) {
    *reason = "out of memory";
    goto bail;
  }
  return 0;

bail:
  datum_free(dst);
  return -1;
}

// Check if datum is an array of tables. An empty array is deliberately
// excluded: it has no elements to type-check, so treating it as an array
// of tables here would be true only vacuously, and datum_merge's caller
// relies on this to distinguish "override with an empty array" from
// "append zero table elements" (see below).
static inline bool is_array_of_tables(toml_datum_t datum) {
  bool ret = (datum.type == TOML_ARRAY) && (datum.u.arr.size > 0);
  for (int i = 0; ret && i < datum.u.arr.size; i++) {
    ret = (datum.u.arr.elem[i].type == TOML_TABLE);
  }
  return ret;
}

// Merge src into dst. Return 0 on success, -1 otherwise.
static int datum_merge(toml_datum_t *dst, toml_datum_t src, srcmap_t *sm,
                       const char **reason) {
  if (dst->type != src.type) {
    datum_free(dst);
    return datum_copy(dst, src, sm, reason);
  }
  switch (src.type) {
  case TOML_TABLE:
    // for key-value in src:
    //    override key-value in dst.
    for (int i = 0; i < src.u.tab.size; i++) {
      char *keycopy = pool_alloc(sm->pool, src.u.tab.len[i] + 1);
      if (!keycopy) {
        *reason = "out of memory";
        return -1;
      }
      memcpy(keycopy, src.u.tab.key[i], src.u.tab.len[i] + 1);
      span_t key;
      key.ptr = keycopy;
      key.len = src.u.tab.len[i];
      toml_datum_t *pvalue = tab_emplace(dst, key, reason);
      if (!pvalue) {
        return -1;
      }
      if (pvalue->type) {
        DO(datum_merge(pvalue, src.u.tab.value[i], sm, reason));
      } else {
        datum_free(pvalue);
        DO(datum_copy(pvalue, src.u.tab.value[i], sm, reason));
      }
    }
    return 0;
  case TOML_ARRAY:
    if (is_array_of_tables(*dst) && is_array_of_tables(src)) {
      // append src array to dst
      for (int i = 0; i < src.u.arr.size; i++) {
        toml_datum_t *pelem = arr_emplace(dst, reason);
        if (!pelem) {
          return -1;
        }
        DO(datum_copy(pelem, src.u.arr.elem[i], sm, reason));
      }
      return 0;
    }
    // fallthru
  default:
    break;
  }
  datum_free(dst);
  return datum_copy(dst, src, sm, reason);
}

// Compare the content of a and b.
static bool datum_equiv(toml_datum_t a, toml_datum_t b) {
  if (a.type != b.type) {
    return false;
  }
  int N;
  switch (a.type) {
  case TOML_STRING:
    return a.u.str.len == b.u.str.len &&
           0 == memcmp(a.u.str.ptr, b.u.str.ptr, a.u.str.len);
  case TOML_INT64:
    return a.u.int64 == b.u.int64;
  case TOML_FP64:
    return a.u.fp64 == b.u.fp64 || (isnan(a.u.fp64) && isnan(b.u.fp64));
  case TOML_BOOLEAN:
    return !!a.u.boolean == !!b.u.boolean;
  case TOML_DATE:
    return a.u.ts.year == b.u.ts.year && a.u.ts.month == b.u.ts.month &&
           a.u.ts.day == b.u.ts.day;
  case TOML_TIME:
    return a.u.ts.hour == b.u.ts.hour && a.u.ts.minute == b.u.ts.minute &&
           a.u.ts.second == b.u.ts.second && a.u.ts.usec == b.u.ts.usec;
  case TOML_DATETIME:
    return a.u.ts.year == b.u.ts.year && a.u.ts.month == b.u.ts.month &&
           a.u.ts.day == b.u.ts.day && a.u.ts.hour == b.u.ts.hour &&
           a.u.ts.minute == b.u.ts.minute && a.u.ts.second == b.u.ts.second &&
           a.u.ts.usec == b.u.ts.usec;
  case TOML_DATETIMETZ:
    return a.u.ts.year == b.u.ts.year && a.u.ts.month == b.u.ts.month &&
           a.u.ts.day == b.u.ts.day && a.u.ts.hour == b.u.ts.hour &&
           a.u.ts.minute == b.u.ts.minute && a.u.ts.second == b.u.ts.second &&
           a.u.ts.usec == b.u.ts.usec && a.u.ts.tz == b.u.ts.tz;
  case TOML_ARRAY:
    N = a.u.arr.size;
    if (N != b.u.arr.size) {
      return false;
    }
    for (int i = 0; i < N; i++) {
      if (!datum_equiv(a.u.arr.elem[i], b.u.arr.elem[i])) {
        return false;
      }
    }
    return true;
  case TOML_TABLE:
    // Tables are unordered maps: match each key of a against any key of b,
    // not positionally. Equal sizes plus a full one-way key match implies a
    // bijection because keys are unique within a table.
    N = a.u.tab.size;
    if (N != b.u.tab.size) {
      return false;
    }
    for (int i = 0; i < N; i++) {
      int len = a.u.tab.len[i];
      int j = 0;
      for (; j < N; j++) {
        if (len == b.u.tab.len[j] &&
            0 == memcmp(a.u.tab.key[i], b.u.tab.key[j], len)) {
          break;
        }
      }
      if (j == N) {
        return false;
      }
      if (!datum_equiv(a.u.tab.value[i], b.u.tab.value[j])) {
        return false;
      }
    }
    return true;
  default:
    break;
  }
  return false;
}

/**
 *  Override values in r1 using r2. Return a new result. All results
 *  (i.e., r1, r2 and the returned result) must be freed using toml_free()
 *  after use.
 *
 *  LOGIC:
 *   ret = copy of r1
 *   for each item x in r2:
 *     if x is not in ret:
 *          override
 *     elif x in ret is NOT of the same type:
 *         override
 *     elif x is an array of tables:
 *         append r2.x to ret.x
 *     elif x is a table:
 *         merge r2.x to ret.x
 *     else:
 *         override
 */
toml_result_t toml_merge(const toml_result_t *r1, const toml_result_t *r2) {
  const char *reason = "";
  toml_result_t ret = {0};
  pool_t *pool = 0;
  srcmap_t sm = {0};
  if (!r1->ok) {
    reason = "param error: r1 not ok";
    goto bail;
  }
  if (!r2->ok) {
    reason = "param error: r2 not ok";
    goto bail;
  }
  pool = pool_create();
  if (!pool) {
    reason = "out of memory";
    goto bail;
  }
  // sm is scoped to this single merge call: its olds[]/news[] memo arrays
  // are just bookkeeping to dedup source-name pointers while copying below,
  // and are freed once the copy/merge is done. The deduplicated string
  // copies they produced live on in `pool`, which becomes the result's pool.
  sm.pool = pool;

  // Make a copy of r1
  if (datum_copy(&ret.toptab, r1->toptab, &sm, &reason)) {
    goto bail;
  }

  // Merge r2 into the result
  if (datum_merge(&ret.toptab, r2->toptab, &sm, &reason)) {
    goto bail;
  }

  cell_free((char *)(void *)sm.olds);
  cell_free((char *)(void *)sm.news);
  ret.ok = 1;
  ret.__internal = pool;
  return ret;

bail:
  cell_free((char *)(void *)sm.olds);
  cell_free((char *)(void *)sm.news);
  pool_destroy(pool);
  snprintf(ret.errmsg, sizeof(ret.errmsg), "%s", reason);
  return ret;
}

bool toml_equiv(const toml_result_t *r1, const toml_result_t *r2) {
  if (!(r1->ok && r2->ok)) {
    return false;
  }
  return datum_equiv(r1->toptab, r2->toptab);
}

/**
 * Find a key in a toml_table. Return the value of the key if found,
 * or a TOML_UNKNOWN otherwise.
 */
toml_datum_t toml_get(toml_datum_t datum, const char *key) {
  if (datum.type == TOML_TABLE) {
    int n = datum.u.tab.size;
    if (n > 0) {
      int key_len = strlen(key);
      const char **pkey = datum.u.tab.key;
      int *plen = datum.u.tab.len;
      toml_datum_t *pvalue = datum.u.tab.value;
      for (int i = 0; i < n; i++) {
        if (plen[i] == key_len && 0 == memcmp(pkey[i], key, key_len)) {
          return pvalue[i];
        }
      }
    }
  }
  return DATUM_ZERO;
}

/**
 * Locate a value starting from a toml_table. Return the value of the key if
 * found, or a TOML_UNKNOWN otherwise.
 *
 * Note: the multipart-key is separated by DOT, and must not have any escape
 * chars.
 */
toml_datum_t toml_seek(toml_datum_t table, const char *multipart_key) {
  if (table.type != TOML_TABLE) {
    return DATUM_ZERO;
  }

  // Make a mutable copy of the multipart_key for splitting
  char buf[256];
  if (copystring(buf, sizeof(buf), multipart_key)) {
    // if the multipart_key is longer than buffer, just
    // signal a not-found.
    return DATUM_ZERO;
  }

  // Go through the multipart name part by part.
  char *p = buf;
  toml_datum_t datum = table;
  while (datum.type == TOML_TABLE) {
    char *q = strchr(p, '.');
    if (q) {
      // traverse to next key
      *q = 0;
      datum = toml_get(datum, p);
      p = q + 1;
      continue;
    }

    // At end of last keypart.
    // look up p in the final table
    return toml_get(datum, p);
  }

  return DATUM_ZERO;
}

/**
 *  Return the default options.
 */
toml_option_t toml_default_option(void) {
  toml_option_t opt = {0, realloc, free};
  return opt;
}

/**
 *  Override the current options.
 */
void toml_set_option(toml_option_t opt) { toml_option = opt; }

/**
 *  Free the result returned by toml_parse().
 */
void toml_free(toml_result_t result) {
  datum_free(&result.toptab);
  pool_destroy((pool_t *)result.__internal);
}

/**
 *  Parse a toml document.
 */
toml_result_t toml_parse_file_ex(const char *fname) {
  toml_result_t result = {0};
  FILE *fp = fopen(fname, "r");
  if (!fp) {
    snprintf(result.errmsg, sizeof(result.errmsg), "fopen %s: %s", fname,
             strerror(errno));
    return result;
  }
  result = toml_parse_file_named(fp, fname);
  fclose(fp);
  return result;
}

toml_result_t toml_parse_file(FILE *fp) {
  return toml_parse_file_named(fp, NULL);
}

/**
 *  Parse a toml document from a file, tagging datums with name.
 */
toml_result_t toml_parse_file_named(FILE *fp, const char *name) {
  toml_result_t result = {0};
  if (!fp) {
    snprintf(result.errmsg, sizeof(result.errmsg), "fp is NULL");
    return result;
  }
  char *buf = 0;
  int top = 0;                 // number of bytes read into buf[]
  enum { CHUNKSZ = 8 * 1024 }; // bytes to read per iteration

  // Read file into memory. cell_realloc handles capacity growth, so we only
  // need to ask for room for one more chunk each pass. Drive the loop off
  // fread's return value rather than feof(): feof() only reports true after
  // a read has already hit EOF.
  for (;;) {
    if (top > INT_MAX - CHUNKSZ) {
      snprintf(result.errmsg, sizeof(result.errmsg), "file is too big");
      break;
    }
    char *tmp = cell_realloc(buf, top + CHUNKSZ);
    if (!tmp) {
      snprintf(result.errmsg, sizeof(result.errmsg), "out of memory");
      break;
    }
    buf = tmp;

    errno = 0;
    size_t n = fread(buf + top, 1, CHUNKSZ, fp);
    top += n;
    if (n < CHUNKSZ) { // short read => EOF or error
      if (ferror(fp)) {
        snprintf(result.errmsg, sizeof(result.errmsg), "%s",
                 errno ? strerror(errno) : "Error reading file");
        break;
      }
      if (feof(fp)) {
        break;
      }
      // small probability of short read due to signal, etc.
    }
  }
  // error?
  if (result.errmsg[0]) {
    cell_free(buf);
    return result;
  }
  result = toml_parse_named(buf, top, name);
  cell_free(buf);
  return result;
}

static void set_source_recursive(toml_datum_t *datum, const char *source) {
  datum->source = source;
  switch (datum->type) {
  case TOML_ARRAY:
    for (int i = 0, top = datum->u.arr.size; i < top; i++) {
      set_source_recursive(&datum->u.arr.elem[i], source);
    }
    break;
  case TOML_TABLE:
    for (int i = 0, top = datum->u.tab.size; i < top; i++) {
      set_source_recursive(&datum->u.tab.value[i], source);
    }
    break;
  default:
    break;
  }
}

/**
 *  Parse a toml document.
 */
toml_result_t toml_parse(const char *src, int len) {
  return toml_parse_named(src, len, NULL);
}

toml_result_t toml_parse_named(const char *src, int len, const char *name) {
  toml_result_t result = {0};
  parser_t parser = {0};
  parser_t *pp = &parser;

  // Check that src is not NULL.
  if (!src) {
    snprintf(result.errmsg, sizeof(result.errmsg), "src is NULL");
    goto bail;
  }

  // A UTF-8 BOM at the very start is an encoding artifact rather than content,
  // so drop it before scanning. Everywhere else U+FEFF stays exactly as it is
  // and remains an error, which is what bom-not-at-start expects.
  if (len >= 3 && (unsigned char)src[0] == 0xEF &&
      (unsigned char)src[1] == 0xBB && (unsigned char)src[2] == 0xBF) {
    src += 3;
    len -= 3;
  }

  // If user insists, check that src[] is a valid utf8 string.
  if (toml_option.check_utf8) {
    int line = 1; // keeps track of line number
    for (int i = 0; i < len;) {
      uint32_t ch;
      int n = utf8_to_ucs(src + i, len - i, &ch);
      if (n < 0) {
        snprintf(result.errmsg, sizeof(result.errmsg),
                 "invalid UTF8 char on line %d", line);
        goto bail;
      }
      if (0xD800 <= ch && ch <= 0xDFFF) {
        // explicitly prohibit surrogates (non-scalar unicode code point)
        snprintf(result.errmsg, sizeof(result.errmsg),
                 "invalid UTF8 char \\u%04x on line %d", ch, line);
        goto bail;
      }
      line += (ch == '\n' ? 1 : 0);
      i += n;
    }
  }

  // Initialize parser
  pp->toptab = mkdatum_at(TOML_TABLE, 1, 1);
  pp->curtab = &pp->toptab;
  pp->ebuf.ptr = result.errmsg; // parse error will be printed into pp->ebuf
  pp->ebuf.len = sizeof(result.errmsg);

  // Alloc memory pool
  int namelen = name ? (int)strlen(name) + 1 : 0;
  pp->pool = pool_create();
  if (!pp->pool) {
    snprintf(result.errmsg, sizeof(result.errmsg), "out of memory");
    goto bail;
  }
  if (name) {
    char *p = pool_alloc(pp->pool, namelen);
    if (!p) {
      snprintf(result.errmsg, sizeof(result.errmsg), "out of memory");
      goto bail;
    }
    memcpy(p, name, namelen);
    pp->srcname = p;
  }

  // Initialize scanner. Scan error will be printed into pp->ebuf.
  scan_init(&pp->scanner, src, len, pp->ebuf.ptr, pp->ebuf.len);

  // Keep parsing until FIN
  for (;;) {
    token_t tok;
    if (scan_key(&pp->scanner, &tok)) {
      goto bail;
    }
    // break on FIN
    if (tok.toktyp == TOK_FIN) {
      break;
    }
    switch (tok.toktyp) {
    case TOK_ENDL: // skip blank lines
      continue;
    case TOK_LBRACK:
      if (parse_std_table_expr(pp, tok)) {
        goto bail;
      }
      break;
    case TOK_LLBRACK:
      if (parse_array_table_expr(pp, tok)) {
        goto bail;
      }
      break;
    default:
      // non-blank line: parse an expression
      if (parse_keyvalue_expr(pp, tok)) {
        goto bail;
      }
      break;
    }
    // each expression must be followed by newline
    if (scan_key(&pp->scanner, &tok)) {
      goto bail;
    }
    if (tok.toktyp == TOK_FIN || tok.toktyp == TOK_ENDL) {
      continue;
    }
    SETERROR(pp->ebuf, tok.lineno, "ENDL expected");
    goto bail;
  }

  // return result
  result.ok = true;
  set_source_recursive(&pp->toptab, pp->srcname);
  result.toptab = pp->toptab;
  result.__internal = (void *)pp->pool;
  return result;

bail:
  // return error
  datum_free(&pp->toptab);
  pool_destroy(pp->pool);
  result.ok = false;
  if (result.errmsg[0] == '\0') {
    assert(0);
    snprintf(result.errmsg, sizeof(result.errmsg), "Error near line %d\n",
             pp->scanner.lineno);
  }
  return result;
}

// Convert a (LITSTRING, LIT, MLLITSTRING, MLSTRING, or STRING) token to a
// datum.
static int token_to_string(parser_t *pp, token_t tok, toml_datum_t *ret) {
  *ret = mkdatum_at(TOML_STRING, tok.lineno, tok.colno);
  span_t span;
  DO(parse_norm(pp, tok, &span));
  ret->u.str.ptr = (char *)span.ptr;
  ret->u.str.len = span.len;
  return 0;
}

// Convert a TIME/DATE/DATETIME/DATETIMETZ to a datum
static int token_to_timestamp(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  static const toml_type_t map[] = {[TOK_TIME] = TOML_TIME,
                                    [TOK_DATE] = TOML_DATE,
                                    [TOK_DATETIME] = TOML_DATETIME,
                                    [TOK_DATETIMETZ] = TOML_DATETIMETZ};
  switch (tok.toktyp) {
  case TOK_TIME:
  case TOK_DATE:
  case TOK_DATETIME:
  case TOK_DATETIMETZ:
    break;
  default:
    assert(0 && "unexpected token type");
    return -1;
  }

  *ret = mkdatum_at(map[tok.toktyp], tok.lineno, tok.colno);
  ret->u.ts.year = tok.u.tsval.year;
  ret->u.ts.month = tok.u.tsval.month;
  ret->u.ts.day = tok.u.tsval.day;
  ret->u.ts.hour = tok.u.tsval.hour;
  ret->u.ts.minute = tok.u.tsval.minute;
  ret->u.ts.second = tok.u.tsval.sec;
  ret->u.ts.usec = tok.u.tsval.usec;
  ret->u.ts.tz = tok.u.tsval.tz;
  return 0;
}

// Convert an int64 token to a datum.
static int token_to_int64(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  assert(tok.toktyp == TOK_INTEGER);
  *ret = mkdatum_at(TOML_INT64, tok.lineno, tok.colno);
  ret->u.int64 = tok.u.int64;
  return 0;
}

// Convert a fp64 token to a datum.
static int token_to_fp64(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  assert(tok.toktyp == TOK_FLOAT);
  *ret = mkdatum_at(TOML_FP64, tok.lineno, tok.colno);
  ret->u.fp64 = tok.u.fp64;
  return 0;
}

// Convert a boolean token to a datum.
static int token_to_boolean(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  assert(tok.toktyp == TOK_BOOL);
  *ret = mkdatum_at(TOML_BOOLEAN, tok.lineno, tok.colno);
  ret->u.boolean = tok.u.b1;
  return 0;
}

// Parse a multipart key. Return 0 on success, -1 otherwise.
static int parse_key(parser_t *pp, token_t tok, keypart_t *ret_keypart) {
  ret_keypart->nspan = 0;
  // key = simple-key | dotted_key
  // simple-key = STRING | LITSTRING | LIT
  // dotted-key = simple-key (DOT simple-key)+
  if (tok.toktyp != TOK_STRING && tok.toktyp != TOK_LITSTRING &&
      tok.toktyp != TOK_LIT) {
    return SETERROR(pp->ebuf, tok.lineno, "missing key");
  }

  int n = 0;
  span_t *kpspan = ret_keypart->span;

  // Normalize the first keypart
  if (parse_norm(pp, tok, &kpspan[n])) {
    return SETERROR(pp->ebuf, tok.lineno,
                    "unable to normalize string; probably a unicode issue");
  }
  n++;

  // Scan and normalize the second to last keypart
  while (1) {
    scanner_state_t mark = scan_mark(&pp->scanner);

    // Eat the dot if it is there
    DO(scan_key(&pp->scanner, &tok));

    // If not a dot, we are done with keyparts.
    if (tok.toktyp != TOK_DOT) {
      scan_restore(&pp->scanner, mark);
      break;
    }

    // Scan the n-th key
    DO(scan_key(&pp->scanner, &tok));

    if (tok.toktyp != TOK_STRING && tok.toktyp != TOK_LITSTRING &&
        tok.toktyp != TOK_LIT) {
      return SETERROR(pp->ebuf, tok.lineno, "expects a string in dotted-key");
    }

    if (n >= KEYPARTMAX) {
      return SETERROR(pp->ebuf, tok.lineno, "too many key parts");
    }

    // Normalize the n-th key.
    DO(parse_norm(pp, tok, &kpspan[n]));
    n++;
  }

  // This key has n parts.
  ret_keypart->nspan = n;
  return 0;
}

// Starting at toptab, descend following keypart[]. If a key does not
// exist in the current table, create a new table entry for the
// key. Returns the final table represented by the key.
static toml_datum_t *descend_keypart(parser_t *pp, int lineno, int colno,
                                     toml_datum_t *toptab, keypart_t *keypart,
                                     bool stdtabexpr) {
  toml_datum_t *tab = toptab; // current tab

  for (int i = 0; i < keypart->nspan; i++) {
    const char *reason;
    // Find the i-th keypart
    int j = tab_find(tab, keypart->span[i]);
    // Not found: add a new (key, tab) pair.
    if (j < 0) {
      toml_datum_t newtab = mkdatum_at(TOML_TABLE, lineno, colno);
      newtab.flag |= stdtabexpr ? TOML_FLAG_STDEXPR : 0;
      if (tab_add(tab, keypart->span[i], newtab, &reason)) {
        SETERROR(pp->ebuf, lineno, "%s", reason);
        return NULL;
      }
      tab = &tab->u.tab.value[tab->u.tab.size - 1]; // descend
      continue;
    }

    // Found: extract the value of the key.
    toml_datum_t *value = &tab->u.tab.value[j];

    // If the value is a table, descend.
    if (value->type == TOML_TABLE) {
      tab = value; // descend
      continue;
    }

    // If the value is an array: locate the last entry and descend.
    if (value->type == TOML_ARRAY) {
      // If empty: error.
      if (value->u.arr.size <= 0) {
        SETERROR(pp->ebuf, lineno, "array %s has no elements",
                 keypart->span[i].ptr);
        return NULL;
      }

      // Extract the last element of the array.
      value = &value->u.arr.elem[value->u.arr.size - 1];

      // It must be a table!
      if (value->type != TOML_TABLE) {
        SETERROR(pp->ebuf, lineno, "array %s must be array of tables",
                 keypart->span[i].ptr);
        return NULL;
      }
      tab = value; // descend
      continue;
    }

    // key not found
    SETERROR(pp->ebuf, lineno, "cannot locate table at key %s",
             keypart->span[i].ptr);
    return NULL;
  }

  // Return the table corresponding to the keypart[].
  return tab;
}

// Recursively set flags on datum
static void set_flag_recursive(toml_datum_t *datum, uint32_t flag) {
  datum->flag |= flag;
  switch (datum->type) {
  case TOML_ARRAY:
    for (int i = 0, top = datum->u.arr.size; i < top; i++) {
      set_flag_recursive(&datum->u.arr.elem[i], flag);
    }
    break;
  case TOML_TABLE:
    for (int i = 0, top = datum->u.tab.size; i < top; i++) {
      set_flag_recursive(&datum->u.tab.value[i], flag);
    }
    break;
  default:
    break;
  }
}

// Parse an inline array.
static int parse_inline_array(parser_t *pp, token_t tok,
                              toml_datum_t *ret_datum) {
  assert(tok.toktyp == TOK_LBRACK);
  *ret_datum = mkdatum_at(TOML_ARRAY, tok.lineno, tok.colno);
  int need_comma = 0;

  // loop until RBRACK
  for (;;) {
    // skip ENDL
    do {
      DO(scan_value(&pp->scanner, &tok));
    } while (tok.toktyp == TOK_ENDL);

    // If got an RBRACK: done!
    if (tok.toktyp == TOK_RBRACK) {
      break;
    }

    // If got a COMMA: check if it is expected.
    if (tok.toktyp == TOK_COMMA) {
      if (need_comma) {
        need_comma = 0;
        continue;
      }
      return SETERROR(pp->ebuf, tok.lineno,
                      "syntax error while parsing array: unexpected comma");
    }

    // Not a comma, but need a comma: error!
    if (need_comma) {
      return SETERROR(pp->ebuf, tok.lineno,
                      "syntax error while parsing array: missing comma");
    }

    // This is a valid value! Obtain the value.
    toml_datum_t value = DATUM_ZERO;
    if (parse_val(pp, tok, &value)) {
      datum_free(&value);
      return -1;
    }

    // Add the value to the array.
    const char *reason;
    toml_datum_t *pelem = arr_emplace(ret_datum, &reason);
    if (!pelem) {
      datum_free(&value);
      return SETERROR(pp->ebuf, tok.lineno, "while parsing array: %s", reason);
    }
    *pelem = value;

    // Need comma before the next value.
    need_comma = 1;
  }

  // Set the INLINE flag for all things in this array.
  set_flag_recursive(ret_datum, TOML_FLAG_INLINED);
  return 0;
}

// Parse an inline table.
static int parse_inline_table(parser_t *pp, token_t tok,
                              toml_datum_t *ret_datum) {
  assert(tok.toktyp == TOK_LBRACE);
  *ret_datum = mkdatum_at(TOML_TABLE, tok.lineno, tok.colno);
  bool need_comma = 0;
  bool was_comma = 0;

  // loop until RBRACE
  for (;;) {
    DO(scan_key(&pp->scanner, &tok));

    // Got an RBRACE: done!
    if (tok.toktyp == TOK_RBRACE) {
      if (was_comma) {
        /*
        return SETERROR(pp->ebuf, tok.lineno,
                        "extra comma before closing brace");
        */
        // extra comma before RBRACE is allowed for v1.1
        (void)0;
      }
      break;
    }

    // Got a comma: check if it is expected.
    if (tok.toktyp == TOK_COMMA) {
      if (need_comma) {
        need_comma = 0, was_comma = 1;
        continue;
      }
      return SETERROR(pp->ebuf, tok.lineno, "unexpected comma");
    }

    // Newline not allowed in inline table.
    // newline is allowed in v1.1
    if (tok.toktyp == TOK_ENDL) {
      // return SETERROR(pp->ebuf, tok.lineno, "unexpected newline");
      continue;
    }

    // Not a comma, but need a comma: error!
    if (need_comma) {
      return SETERROR(pp->ebuf, tok.lineno, "missing comma");
    }

    // Get the keyparts
    keypart_t keypart = {0};
    int keylineno = tok.lineno;
    int keycolno = tok.colno;
    DO(parse_key(pp, tok, &keypart));

    // Descend to one keypart before last
    assert(keypart.nspan > 0);
    span_t lastkeypart = keypart.span[--keypart.nspan];
    toml_datum_t *tab =
        descend_keypart(pp, keylineno, keycolno, ret_datum, &keypart, false);
    if (!tab) {
      return -1;
    }

    // If tab is a previously declared inline table: error.
    if (tab->flag & TOML_FLAG_INLINED) {
      return SETERROR(pp->ebuf, tok.lineno, "inline table cannot be extended");
    }

    // We are explicitly defining it now.
    tab->flag |= TOML_FLAG_EXPLICIT;

    // match EQUAL
    DO(scan_value(&pp->scanner, &tok));

    if (tok.toktyp != TOK_EQUAL) {
      if (tok.toktyp == TOK_ENDL) {
        return SETERROR(pp->ebuf, tok.lineno, "unexpected newline");
      } else {
        return SETERROR(pp->ebuf, tok.lineno, "missing '='");
      }
    }

    // obtain the value
    DO(scan_value(&pp->scanner, &tok));
    toml_datum_t value = DATUM_ZERO;
    if (parse_val(pp, tok, &value)) {
      datum_free(&value);
      return -1;
    }

    // Add the value to tab.
    const char *reason;
    if (tab_add(tab, lastkeypart, value, &reason)) {
      datum_free(&value);
      return SETERROR(pp->ebuf, tok.lineno, "%s", reason);
    }
    need_comma = 1, was_comma = 0;
  }

  set_flag_recursive(ret_datum, TOML_FLAG_INLINED);
  return 0;
}

// Parse a value.
static int parse_val(parser_t *pp, token_t tok, toml_datum_t *ret) {
  *ret = DATUM_ZERO; // initialize

  // val = string / boolean / array / inline-table / date-time / float / integer
  switch (tok.toktyp) {
  case TOK_STRING:
  case TOK_MLSTRING:
  case TOK_LITSTRING:
  case TOK_MLLITSTRING:
    return token_to_string(pp, tok, ret);
  case TOK_TIME:
  case TOK_DATE:
  case TOK_DATETIME:
  case TOK_DATETIMETZ:
    return token_to_timestamp(pp, tok, ret);
  case TOK_INTEGER:
    return token_to_int64(pp, tok, ret);
  case TOK_FLOAT:
    return token_to_fp64(pp, tok, ret);
  case TOK_BOOL:
    return token_to_boolean(pp, tok, ret);
  case TOK_LBRACK: // inline-array
    return parse_inline_array(pp, tok, ret);
  case TOK_LBRACE: // inline-table
    return parse_inline_table(pp, tok, ret);
  default:
    return SETERROR(pp->ebuf, tok.lineno, "missing value");
  }
}

// Parse a standard table expression, and set the curtab of the parser
// to the table referenced.  A standard table expression is a line
// like [a.b.c.d].
static int parse_std_table_expr(parser_t *pp, token_t tok) {
  // std-table = [ key ]
  // Eat the [
  assert(tok.toktyp == TOK_LBRACK); // [ ate by caller

  // Read the first keypart
  DO(scan_key(&pp->scanner, &tok));

  // Extract the keypart[]
  int keylineno = tok.lineno;
  int keycolno = tok.colno;
  keypart_t keypart;
  DO(parse_key(pp, tok, &keypart));

  // Eat the ]
  DO(scan_key(&pp->scanner, &tok));
  if (tok.toktyp != TOK_RBRACK) {
    return SETERROR(pp->ebuf, tok.lineno, "missing right-bracket");
  }

  // Descend to one keypart before last.
  span_t lastkeypart = keypart.span[--keypart.nspan];

  // Descend keypart from the toptab.
  toml_datum_t *tab =
      descend_keypart(pp, keylineno, keycolno, &pp->toptab, &keypart, true);
  if (!tab) {
    return -1;
  }

  // Look for the last keypart in the final tab
  int j = tab_find(tab, lastkeypart);
  if (j < 0) {
    // If not found: add it.
    if (tab->flag & TOML_FLAG_INLINED) {
      return SETERROR(pp->ebuf, keylineno, "inline table cannot be extended");
    }
    const char *reason;
    toml_datum_t newtab = mkdatum_at(TOML_TABLE, keylineno, keycolno);
    newtab.flag |= TOML_FLAG_STDEXPR;
    if (tab_add(tab, lastkeypart, newtab, &reason)) {
      return SETERROR(pp->ebuf, keylineno, "%s", reason);
    }
    // this is the new tab
    tab = &tab->u.tab.value[tab->u.tab.size - 1];
  } else {
    // Found: check for errors
    tab = &tab->u.tab.value[j];
    if (tab->flag & TOML_FLAG_EXPLICIT) {
      /*
        This is not OK:
        [x.y.z]
        [x.y.z]

        but this is OK:
        [x.y.z]
        [x]
      */
      return SETERROR(pp->ebuf, keylineno, "table defined more than once");
    }
    if (!(tab->flag & TOML_FLAG_STDEXPR)) {
      /*
      [t1]			# OK
      t2.t3.v = 0		# OK
      [t1.t2]   		# should FAIL  - t2 was non-explicit but was not
      created by std-table-expr
      */
      return SETERROR(pp->ebuf, keylineno, "table defined before");
    }
  }

  // Set explicit flag on tab
  tab->flag |= TOML_FLAG_EXPLICIT;
  tab->lineno = keylineno;
  tab->colno = keycolno;

  // Set tab as curtab of the parser
  pp->curtab = tab;
  return 0;
}

// Parse an array table expression, and set the curtab of the parser
// to the table referenced. A standard array table expression is a line
// like [[a.b.c.d]].
static int parse_array_table_expr(parser_t *pp, token_t tok) {
  // array-table = [[ key ]]
  assert(tok.toktyp == TOK_LLBRACK); // [[ ate by caller

  // Read the first keypart
  DO(scan_key(&pp->scanner, &tok));

  int keylineno = tok.lineno;
  int keycolno = tok.colno;
  keypart_t keypart;
  DO(parse_key(pp, tok, &keypart));

  // eat the ]]
  token_t rrb;
  DO(scan_key(&pp->scanner, &rrb));
  if (rrb.toktyp != TOK_RRBRACK) {
    return SETERROR(pp->ebuf, rrb.lineno, "missing ']]'");
  }

  // remove the last keypart from keypart[]
  assert(keypart.nspan > 0);
  span_t lastkeypart = keypart.span[--keypart.nspan];

  // descend intermediate keys from toptab
  toml_datum_t *tab =
      descend_keypart(pp, keylineno, keycolno, &pp->toptab, &keypart, true);
  if (!tab)
    return -1;

  // For the final keypart, make sure entry at key is an array of tables
  const char *reason;
  int idx = tab_find(tab, lastkeypart);
  if (idx == -1) {
    // If not found, add an array of table.
    if (tab->flag & TOML_FLAG_INLINED) {
      return SETERROR(pp->ebuf, keylineno, "inline table cannot be extended");
    }
    toml_datum_t newarr = mkdatum_at(TOML_ARRAY, keylineno, keycolno);
    if (tab_add(tab, lastkeypart, newarr, &reason)) {
      return SETERROR(pp->ebuf, keylineno, "%s", reason);
    }
    idx = tab_find(tab, lastkeypart);
    assert(idx >= 0);
  }
  // Check that this is an array.
  if (tab->u.tab.value[idx].type != TOML_ARRAY) {
    return SETERROR(pp->ebuf, keylineno, "entry must be an array");
  }
  // Add an empty table to the array
  toml_datum_t *arr = &tab->u.tab.value[idx];
  if (arr->flag & TOML_FLAG_INLINED) {
    return SETERROR(pp->ebuf, keylineno, "cannot extend a static array");
  }
  toml_datum_t *pelem = arr_emplace(arr, &reason);
  if (!pelem) {
    return SETERROR(pp->ebuf, keylineno, "%s", reason);
  }
  *pelem = mkdatum_at(TOML_TABLE, keylineno, keycolno);

  // Set the last element of this array as curtab of the parser
  pp->curtab = &arr->u.arr.elem[arr->u.arr.size - 1];
  assert(pp->curtab->type == TOML_TABLE);

  return 0;
}

// Parse an expression. A toml doc is just a list of expressions.
static int parse_keyvalue_expr(parser_t *pp, token_t tok) {
  // Obtain the key
  int keylineno = tok.lineno;
  int keycolno = tok.colno;
  keypart_t keypart;
  DO(parse_key(pp, tok, &keypart));

  // match the '='
  DO(scan_key(&pp->scanner, &tok));
  if (tok.toktyp != TOK_EQUAL) {
    return SETERROR(pp->ebuf, tok.lineno, "expect '='");
  }

  // Locate the last table using keypart[]
  const char *reason;
  toml_datum_t *tab = pp->curtab;
  for (int i = 0; i < keypart.nspan - 1; i++) {
    int j = tab_find(tab, keypart.span[i]);
    if (j < 0) {
      if (i > 0 && (tab->flag & TOML_FLAG_EXPLICIT)) {
        return SETERROR(
            pp->ebuf, keylineno,
            "cannot extend a previously defined table using dotted expression");
      }
      toml_datum_t newtab = mkdatum_at(TOML_TABLE, keylineno, keycolno);
      if (tab_add(tab, keypart.span[i], newtab, &reason)) {
        return SETERROR(pp->ebuf, keylineno, "%s", reason);
      }
      tab = &tab->u.tab.value[tab->u.tab.size - 1];
      continue;
    }
    toml_datum_t *value = &tab->u.tab.value[j];
    if (value->type == TOML_TABLE) {
      tab = value;
      continue;
    }
    if (value->type == TOML_ARRAY) {
      return SETERROR(pp->ebuf, keylineno,
                      "encountered previously declared array '%s'",
                      keypart.span[i].ptr);
    }
    return SETERROR(pp->ebuf, keylineno, "cannot locate table at '%s'",
                    keypart.span[i].ptr);
  }

  // Check for disallowed situations.
  if (tab->flag & TOML_FLAG_INLINED) {
    return SETERROR(pp->ebuf, keylineno, "inline table cannot be extended");
  }
  if (keypart.nspan > 1 && (tab->flag & TOML_FLAG_EXPLICIT)) {
    return SETERROR(
        pp->ebuf, keylineno,
        "cannot extend a previously defined table using dotted expression");
  }

  // Obtain the value
  DO(scan_value(&pp->scanner, &tok));
  toml_datum_t newval = DATUM_ZERO;
  if (parse_val(pp, tok, &newval)) {
    datum_free(&newval);
    return -1;
  }

  // Add a new key/value for tab.
  if (tab_add(tab, keypart.span[keypart.nspan - 1], newval, &reason)) {
    datum_free(&newval);
    return SETERROR(pp->ebuf, keylineno, "%s", reason);
  }

  return 0;
}

// Normalize a LIT/STRING/MLSTRING/LITSTRING/MLLITSTRING
// -> unescape all escaped chars
// The returned string is allocated out of pp->pool
static int parse_norm(parser_t *pp, token_t tok, span_t *ret_span) {
  // Allocate a buffer to store the normalized string. Add one
  // extra-byte for terminating NUL.
  char *p = pool_alloc(pp->pool, tok.str.len + 1);
  if (!p) {
    return SETERROR(pp->ebuf, tok.lineno, "out of memory");
  }

  // Copy from token string into buffer
  memcpy(p, tok.str.ptr, tok.str.len);
  p[tok.str.len] = 0; // additional NUL term for safety

  ret_span->ptr = p;
  ret_span->len = tok.str.len;

  switch (tok.toktyp) {
  case TOK_LIT:
  case TOK_LITSTRING:
  case TOK_MLLITSTRING:
    // no need to handle escape chars
    return 0;

  case TOK_STRING:
  case TOK_MLSTRING:
    // need to handle escape chars
    break;

  default:
    return SETERROR(pp->ebuf, 0, "internal: arg must be a string");
  }

  // if there is no escape char, then done!
  if (!tok.u.escp) {
    return 0; // success
  }

  // p points to the backslash
  p += (tok.u.escp - tok.str.ptr);
  assert(p - ret_span->ptr == tok.u.escp - tok.str.ptr);
  assert(*p == '\\');

  // Normalize the escaped chars
  char *dst = p;
  while (*p) {
    if (*p != '\\') {
      *dst++ = *p++;
      continue;
    }
    switch (p[1]) {
    case '"':
    case '\\':
      *dst++ = p[1];
      p += 2;
      continue;
    case 'b':
      *dst++ = '\b';
      p += 2;
      continue;
    case 't':
      *dst++ = '\t';
      p += 2;
      continue;
    case 'n':
      *dst++ = '\n';
      p += 2;
      continue;
    case 'f':
      *dst++ = '\f';
      p += 2;
      continue;
    case 'r':
      *dst++ = '\r';
      p += 2;
      continue;
    case 'e':
      *dst++ = '\033';
      p += 2;
      continue;
    case 'x': {
      char buf[3];
      memcpy(buf, p + 2, 2);
      buf[2] = 0;
      // There is no need to check for two hex digits here because
      // the scanner already checked it.
      int32_t ucs = strtol(buf, 0, 16);
      int n = ucs_to_utf8(ucs, dst);
      if (n < 0) {
        return SETERROR(pp->ebuf, tok.lineno, "error converting UCS %s to UTF8",
                        buf);
      }
      dst += n;
      p += 2 + 2; // \xNN
      continue;
    }
    case 'u':
    case 'U': {
      char buf[9];
      int sz = (p[1] == 'u' ? 4 : 8);
      memcpy(buf, p + 2, sz);
      buf[sz] = 0;
      // There is no need to check for 4 or 8 hex digits here because
      // the scanner already checked it.
      int32_t ucs = strtol(buf, 0, 16);
      if (0xD800 <= ucs && ucs <= 0xDFFF) {
        // explicitly prohibit surrogates (non-scalar unicode code point)
        return SETERROR(pp->ebuf, tok.lineno, "invalid UTF8 char \\u%04x", ucs);
      }
      int n = ucs_to_utf8(ucs, dst);
      if (n < 0) {
        return SETERROR(pp->ebuf, tok.lineno, "error converting UCS %s to UTF8",
                        buf);
      }
      dst += n;
      p += 2 + sz; // \uNNNN or \UNNNNNNNN
      continue;
    }

    case ' ':
    case '\t':
    case '\r':
      // line-ending backslash
      // --- allow for extra whitespace chars after backslash
      // --- skip until newline
      p++;                     // skip the escape char
      p += strspn(p, " \t\r"); // skip whitespaces
      if (*p != '\n') {
        return SETERROR(pp->ebuf, tok.lineno,
                        "unexpected char after line-ending backslash");
      }
      // fallthru
    case '\n':
      // skip all whitespaces including newline
      p++;
      p += strspn(p, " \t\r\n");
      continue;
    default:
      return SETERROR(pp->ebuf, tok.lineno,
                      "internal: unknown escape char \\%c", p[1]);
    }
  }
  *dst = 0;
  ret_span->len = dst - ret_span->ptr;
  return 0;
}

// ===================================================================
// ==    SCANNER SECTION
// ===================================================================

// Get the next char
static int scan_get(scanner_t *sp) {
  int ret = TOK_FIN;
  const char *p = sp->cur;
  if (p < sp->endp) {
    ret = *p++;
    if (ret == '\r' && p < sp->endp && *p == '\n') {
      ret = *p++;
    }
  }
  sp->cur = p;
  if (ret == '\n') {
    sp->lineno += 1;
    sp->line_start = p;
  }
  return ret;
}

// Check if the next char matches ch.
static inline bool scan_match(scanner_t *sp, int ch) {
  const char *p = sp->cur;
  // exact match? done.
  if (p < sp->endp && *p == ch) {
    return true;
  }
  // \n also matches \r\n
  if (ch == '\n' && p + 1 < sp->endp) {
    return p[0] == '\r' && p[1] == '\n';
  }
  // not a match
  return false;
}

// Check if the next char is in accept[].
static bool scan_matchany(scanner_t *sp, const char *accept) {
  for (; *accept; accept++) {
    if (scan_match(sp, *accept)) {
      return true;
    }
  }
  return false;
}

// Check if the next n chars match ch.
static inline bool scan_nmatch(scanner_t *sp, int ch, int n) {
  assert(ch != '\n'); // not handled
  if (sp->cur + n > sp->endp) {
    return false;
  }
  const char *p = sp->cur;
  int i;
  for (i = 0; i < n && p[i] == ch; i++)
    ;
  return i == n;
}

// Initialize a token.
static inline token_t mktoken(scanner_t *sp, toktyp_t typ) {
  token_t tok = {0};
  tok.toktyp = typ;
  tok.str.ptr = sp->cur;
  tok.lineno = sp->lineno;
  tok.colno = (int)(sp->cur - sp->line_start) + 1;
  return tok;
}

#define S_GET() scan_get(sp)
#define S_MATCH(ch) scan_match(sp, (ch))
#define S_MATCH3(ch) scan_nmatch(sp, (ch), 3)
#define S_MATCH4(ch) scan_nmatch(sp, (ch), 4)
#define S_MATCH6(ch) scan_nmatch(sp, (ch), 6)

static inline bool is_valid_char(int ch) {
  // i.e. (0x20 <= ch && ch <= 0x7e) || (ch & 0x80);
  return isprint((unsigned char)ch) || (ch & 0x80);
}

static inline bool is_hex_char(int ch) {
  ch = toupper((unsigned char)ch);
  return ('0' <= ch && ch <= '9') || ('A' <= ch && ch <= 'F');
}

// Initialize a scanner
static void scan_init(scanner_t *sp, const char *src, int len, char *errbuf,
                      int errbufsz) {
  memset(sp, 0, sizeof(*sp));
  sp->src = src;
  sp->endp = src + len;
  sp->cur = src;
  sp->lineno = 1;
  sp->line_start = src;
  sp->ebuf.ptr = errbuf;
  sp->ebuf.len = errbufsz;
}

// Scan escape sequence characters after a backslash.
// Return #char match on success, 0 if no match, -1 on error.
static int scan_escape_chars(scanner_t *sp) {
  const char *p = sp->cur;
  if (p >= sp->endp) {
    return 0;
  }
  int ch = *p++;
  if (ch && strchr("btnfre\"\\", ch)) {
    return p - sp->cur;
  }
  int hex = (ch == 'x') ? 2 : (ch == 'u') ? 4 : (ch == 'U') ? 8 : 0;
  if (hex) {
    int i = 0;
    for (; i < hex && p < sp->endp && is_hex_char(*p); i++, p++)
      ;
    if (i != hex) {
      return SETERROR(sp->ebuf, sp->lineno, "expect %d hex digits after \\%c",
                      hex, ch);
    }
    return p - sp->cur;
  }
  return 0;
}

// Scan """ ... """
static int scan_multiline_string(scanner_t *sp, token_t *tok) {
  assert(S_MATCH3('"'));
  S_GET(), S_GET(), S_GET(); // skip opening """

  // According to spec: trim first newline after """
  if (S_MATCH('\n')) {
    S_GET();
  }

  *tok = mktoken(sp, TOK_MLSTRING);
  // scan until terminating """
  const char *escp = NULL;
  while (1) {
    if (S_MATCH3('"')) {
      if (S_MATCH4('"')) {
        // special case... """abcd """" -> (abcd ")
        // but sequences of 3 or more double quotes are not allowed
        if (S_MATCH6('"')) {
          return SETERROR(sp->ebuf, sp->lineno,
                          "detected sequences of 3 or more double quotes");
        } else {
          ; // no problem
        }
      } else {
        break; // found terminating """
      }
    }
    int ch = S_GET();
    if (ch == TOK_FIN) {
      return SETERROR(sp->ebuf, sp->lineno, "unterminated \"\"\"");
    }
    // If non-escaped char ...
    if (ch != '\\') {
      if (!(is_valid_char(ch) || (ch && strchr(" \t\n", ch)))) {
        return SETERROR(sp->ebuf, sp->lineno, "invalid char in string");
      }
      continue;
    }
    // ch is backslash
    if (!escp) {
      escp = sp->cur - 1; /* mark the first esc position */
      assert(*escp == '\\');
    }

    // handle escape char
    int cnt = scan_escape_chars(sp);
    if (cnt < 0) {
      return -1;
    }
    if (cnt > 0) {
      sp->cur += cnt; // skip the escape sequence
      continue;
    }
    assert(cnt == 0);

    // handle line-ending backslash
    ch = S_GET();
    if (ch == ' ' || ch == '\t') {
      // Although the spec does not allow for whitespace following a
      // line-ending backslash, some standard tests expect it.
      // Skip whitespace till EOL.
      while (ch != TOK_FIN && ch && strchr(" \t", ch)) {
        ch = S_GET();
      }
      if (ch != '\n') {
        // Got a backslash followed by whitespace, followed by some char
        // before newline
        return SETERROR(sp->ebuf, sp->lineno, "bad escape char in string");
      }
      // fallthru
    }
    if (ch == '\n') {
      // got a line-ending backslash
      // - skip all whitespaces
      while (scan_matchany(sp, " \t\n")) {
        S_GET();
      }
      continue;
    }
    return SETERROR(sp->ebuf, sp->lineno, "bad escape char in string");
  }
  tok->str.len = sp->cur - tok->str.ptr;
  tok->u.escp = escp;

  assert(S_MATCH3('"'));
  S_GET(), S_GET(), S_GET();
  return 0;
}

// Scan " ... "
static int scan_string(scanner_t *sp, token_t *tok) {
  assert(S_MATCH('"'));
  if (S_MATCH3('"')) {
    return scan_multiline_string(sp, tok);
  }
  S_GET(); // skip opening "

  // scan until closing "
  *tok = mktoken(sp, TOK_STRING);
  const char *escp = NULL;
  while (!S_MATCH('"')) {
    int ch = S_GET();
    if (ch == TOK_FIN) {
      return SETERROR(sp->ebuf, sp->lineno, "unterminated string");
    }
    // If non-escaped char ...
    if (ch != '\\') {
      if (!(is_valid_char(ch) || ch == ' ' || ch == '\t')) {
        return SETERROR(sp->ebuf, sp->lineno, "invalid char in string");
      }
      continue;
    }
    // ch is backslash
    if (!escp) {
      escp = sp->cur - 1;
      assert(*escp == '\\');
    }

    // handle escape char
    int cnt = scan_escape_chars(sp);
    if (cnt < 0) {
      return -1;
    }
    if (cnt > 0) {
      sp->cur += cnt;
      continue;
    }
    return SETERROR(sp->ebuf, sp->lineno, "bad escape char in string");
  }
  tok->str.len = sp->cur - tok->str.ptr;
  tok->u.escp = escp;

  assert(S_MATCH('"'));
  S_GET(); // skip the terminating "
  return 0;
}

// Scan ''' ... '''
static int scan_multiline_litstring(scanner_t *sp, token_t *tok) {
  assert(S_MATCH3('\''));
  S_GET(), S_GET(), S_GET(); // skip opening '''

  // According to spec: trim first newline after '''
  if (S_MATCH('\n')) {
    S_GET();
  }

  // scan until terminating '''
  *tok = mktoken(sp, TOK_MLLITSTRING);
  while (1) {
    if (S_MATCH3('\'')) {
      if (S_MATCH4('\'')) {
        // special case... '''abcd '''' -> (abcd ')
        // but sequences of 3 or more single quotes are not allowed
        if (S_MATCH6('\'')) {
          return SETERROR(sp->ebuf, sp->lineno,
                          "sequences of 3 or more single quotes");
        } else {
          ; // no problem
        }
      } else {
        break; // found terminating '''
      }
    }
    int ch = S_GET();
    if (ch == TOK_FIN) {
      return SETERROR(sp->ebuf, sp->lineno,
                      "unterminated multiline lit string");
    }
    if (!(is_valid_char(ch) || (ch && strchr(" \t\n", ch)))) {
      return SETERROR(sp->ebuf, sp->lineno, "invalid char in string");
    }
  }
  tok->str.len = sp->cur - tok->str.ptr;

  assert(S_MATCH3('\''));
  S_GET(), S_GET(), S_GET();
  return 0;
}

// Scan ' ... '
static int scan_litstring(scanner_t *sp, token_t *tok) {
  assert(S_MATCH('\''));
  if (S_MATCH3('\'')) {
    return scan_multiline_litstring(sp, tok);
  }
  S_GET(); // skip opening '

  // scan until closing '
  *tok = mktoken(sp, TOK_LITSTRING);
  while (!S_MATCH('\'')) {
    int ch = S_GET();
    if (ch == TOK_FIN) {
      return SETERROR(sp->ebuf, sp->lineno, "unterminated string");
    }
    if (!(is_valid_char(ch) || ch == '\t')) {
      return SETERROR(sp->ebuf, sp->lineno, "invalid char in string");
    }
  }
  tok->str.len = sp->cur - tok->str.ptr;
  assert(S_MATCH('\''));
  S_GET();
  return 0;
}

static bool is_valid_date(int year, int month, int day) {
  if (!(1 <= year)) {
    return false;
  }
  if (!(1 <= month && month <= 12)) {
    return false;
  }
  int is_leap_year = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
  int days_in_month[] = {
      31, 28 + is_leap_year, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  return (1 <= day && day <= days_in_month[month - 1]);
}

static bool is_valid_time(int hour, int minute, int sec, int usec) {
  if (!(0 <= hour && hour <= 23)) {
    return false;
  }
  if (!(0 <= minute && minute <= 59)) {
    return false;
  }
  // RFC 3339 permits sec == 60 for leap seconds; reject it deliberately.
  if (!(0 <= sec && sec <= 59)) {
    return false;
  }
  if (!(0 <= usec)) {
    return false;
  }
  return true;
}

static bool is_valid_timezone(int minute) {
  minute = (minute < 0 ? -minute : minute);
  int hour = minute / 60;
  minute = minute % 60;
  if (!(0 <= hour && hour <= 23)) {
    return false;
  }
  if (!(0 <= minute && minute < 60)) {
    return false;
  }
  return true;
}

// Read an int (without signs) from the string p.
static int read_int(const char *p, int *ret) {
  const char *pp = p;
  int64_t val = 0;
  for (; isdigit((unsigned char)*p); p++) {
    val = val * 10 + (*p - '0');
    if (val > INT_MAX) {
      return 0; // overflowed
    }
  }
  *ret = (int)val;
  return p - pp;
}

// Read a date as YYYY-MM-DD from p[]. Return #bytes consumed.
static int read_date(const char *p, int *year, int *month, int *day) {
  const char *pp = p;
  int n;
  n = read_int(p, year);
  if (n != 4 || p[4] != '-') {
    return 0;
  }
  n = read_int(p += n + 1, month);
  if (n != 2 || p[2] != '-') {
    return 0;
  }
  n = read_int(p += n + 1, day);
  if (n != 2) {
    return 0;
  }
  p += 2;
  assert(p - pp == 10);
  return p - pp;
}

// Read a time as HH:MM:SS.subsec from p[]. Return #bytes consumed.
static int read_time(const char *p, int *hour, int *minute, int *second,
                     int *usec) {
  const char *pp = p;
  int n;
  *hour = *minute = *second = *usec = 0;
  // scan hours
  n = read_int(p, hour);
  if (n != 2 || p[2] != ':') {
    return 0;
  }
  p += 3;

  // scan minutes
  n = read_int(p, minute);
  if (n != 2) {
    return 0;
  }
  if (p[2] != ':') {
    // seconds are optional in v1.1
    p += 2;
    return p - pp;
  }
  p += 3;

  // scan seconds
  n = read_int(p, second);
  if (n != 2) {
    return 0;
  }
  p += 2;

  if (*p != '.') {
    return p - pp;
  }
  p++; // skip the period
  if (!isdigit((unsigned char)*p)) {
    // trailing period
    return 0;
  }
  int micro_factor = 100000;
  while (isdigit((unsigned char)*p) && micro_factor) {
    *usec += (*p - '0') * micro_factor;
    micro_factor /= 10;
    p++;
  }
  while (isdigit((unsigned char)*p))
    p++; // consume extra sub-microsecond digits
  return p - pp;
}

// Reads a timezone from p[]. Return #bytes consumed.
// tzhours and tzminutes restricted to 2-char integers only.
static int read_tzone(const char *p, char *tzsign, int *tzhour, int *tzminute) {
  const char *pp = p;

  // Default values
  *tzhour = *tzminute = 0;
  *tzsign = '+';

  // Look for Zulu
  if (*p == 'Z' || *p == 'z') {
    return 1; // done! tz is +00:00.
  }

  // Look for +/-
  *tzsign = *p++;
  if (!(*tzsign == '+' || *tzsign == '-')) {
    return 0;
  }

  // Look for HH:MM
  int n;
  n = read_int(p, tzhour);
  if (n != 2 || p[2] != ':') {
    return 0;
  }
  n = read_int(p += 3, tzminute);
  if (n != 2) {
    return 0;
  }
  p += 2;
  return p - pp;
}

// Scan hh:mm:ss.xxxxx
static int scan_time(scanner_t *sp, token_t *tok) {
  int lineno = sp->lineno;
  char buffer[LITBUF_SIZE];
  scan_copystr(sp, buffer, sizeof(buffer));

  char *p = buffer;
  int hour, minute, sec, usec;
  int len = read_time(p, &hour, &minute, &sec, &usec);
  if (len == 0) {
    return SETERROR(sp->ebuf, lineno, "invalid time");
  }
  if (len + 1 >= (int)sizeof(buffer)) {
    return SETERROR(sp->ebuf, lineno, "timestamp too long");
  }
  if (!is_valid_time(hour, minute, sec, usec)) {
    return SETERROR(sp->ebuf, lineno, "invalid time");
  }

  *tok = mktoken(sp, TOK_TIME);
  tok->str.len = len;
  sp->cur += len;
  tok->u.tsval.year = -1;
  tok->u.tsval.month = -1;
  tok->u.tsval.day = -1;
  tok->u.tsval.hour = hour;
  tok->u.tsval.minute = minute;
  tok->u.tsval.sec = sec;
  tok->u.tsval.usec = usec;
  tok->u.tsval.tz = -1;
  return 0;
}

// Scan a time, a date, a datetime, or a datatimetz
static int scan_timestamp(scanner_t *sp, token_t *tok) {
  int year, month, day, hour, minute, sec, usec, tz;
  year = month = day = hour = minute = sec = usec = tz = -1;

  int n;
  // make a copy of sp->cur into buffer to ensure NUL terminated string
  char buffer[LITBUF_SIZE];
  scan_copystr(sp, buffer, sizeof(buffer));

  toktyp_t toktyp = TOK_FIN;
  int lineno = sp->lineno;

  // See if this a TIME only
  const char *p = buffer;
  if (isdigit((unsigned char)p[0]) && isdigit((unsigned char)p[1]) &&
      p[2] == ':') {
    n = read_time(buffer, &hour, &minute, &sec, &usec);
    if (!n) {
      return SETERROR(sp->ebuf, lineno, "invalid time");
    }
    toktyp = TOK_TIME;
    p += n;
    goto done;
  }

  // Try reading a DATE
  n = read_date(p, &year, &month, &day);
  if (!n) {
    return SETERROR(sp->ebuf, lineno, "invalid date");
  }
  toktyp = TOK_DATE;
  p += n;

  // Check if there is no time component in addition
  if (!((p[0] == 'T' || p[0] == ' ' || p[0] == 't') &&
        isdigit((unsigned char)p[1]) && isdigit((unsigned char)p[2]) &&
        p[3] == ':')) {
    goto done; // no TIME component. we are done.
  }

  // Read the TIME
  n = read_time(p += 1, &hour, &minute, &sec, &usec);
  if (!n) {
    return SETERROR(sp->ebuf, lineno, "invalid timestamp");
  }
  toktyp = TOK_DATETIME;
  p += n;

  // Read the (optional) timezone
  char tzsign;
  int tzhour, tzminute;
  n = read_tzone(p, &tzsign, &tzhour, &tzminute);
  if (n == 0) {
    goto done; // datetime only
  }
  toktyp = TOK_DATETIMETZ;
  p += n;

  // Check tzminute range. This must be done here instead of is_valid_timezone()
  // because we combine tzhour and tzminute into tz (by minutes only).
  if (!(0 <= tzminute && tzminute < 60)) {
    return SETERROR(sp->ebuf, lineno, "invalid timezone");
  }
  tz = (tzhour * 60 + tzminute) * (tzsign == '-' ? -1 : 1);
  goto done; // datetimetz

done:
  *tok = mktoken(sp, toktyp);
  n = p - buffer;
  if (n + 1 >= (int)sizeof(buffer)) {
    return SETERROR(sp->ebuf, lineno, "timestamp too long");
  }
  tok->str.len = n;
  sp->cur += n;

  tok->u.tsval.year = year;
  tok->u.tsval.month = month;
  tok->u.tsval.day = day;
  tok->u.tsval.hour = hour;
  tok->u.tsval.minute = minute;
  tok->u.tsval.sec = sec;
  tok->u.tsval.usec = usec;
  tok->u.tsval.tz = tz;

  // Do some error checks based on type
  switch (tok->toktyp) {
  case TOK_TIME:
    if (!is_valid_time(hour, minute, sec, usec)) {
      return SETERROR(sp->ebuf, lineno, "invalid time");
    }
    break;
  case TOK_DATE:
    if (!is_valid_date(year, month, day)) {
      return SETERROR(sp->ebuf, lineno, "invalid date");
    }
    break;
  case TOK_DATETIME:
  case TOK_DATETIMETZ:
    if (!is_valid_date(year, month, day)) {
      return SETERROR(sp->ebuf, lineno, "invalid date");
    }
    if (!is_valid_time(hour, minute, sec, usec)) {
      return SETERROR(sp->ebuf, lineno, "invalid time");
    }
    if (tok->toktyp == TOK_DATETIMETZ && !is_valid_timezone(tz)) {
      return SETERROR(sp->ebuf, lineno, "invalid timezone");
    }
    break;
  default:
    assert(0);
    return SETERROR(sp->ebuf, lineno, "internal error");
  }

  return 0;
}

// Given a toml number (int and float) in buffer[]:
//   1. squeeze out '_'
//   2. check for syntax restrictions
static int process_numstr(char *buffer, int base, const char **reason) {
  // squeeze out _
  char *q = strchr(buffer, '_');
  if (q) {
    for (int i = q - buffer; buffer[i]; i++) {
      if (buffer[i] != '_') {
        *q++ = buffer[i];
        continue;
      }
      int left = (i == 0) ? 0 : (unsigned char)buffer[i - 1];
      int right = (unsigned char)buffer[i + 1];
      if (!isdigit(left) && !(base == 16 && is_hex_char(left))) {
        *reason = "underscore only allowed between digits";
        return -1;
      }
      if (!isdigit(right) && !(base == 16 && is_hex_char(right))) {
        *reason = "underscore only allowed between digits";
        return -1;
      }
    }
    *q = 0;
  }

  // decimal points must be surrounded by digits. Also, convert to lowercase.
  for (int i = 0; buffer[i]; i++) {
    if (buffer[i] == '.') {
      if (i == 0 || !isdigit((unsigned char)buffer[i - 1]) ||
          !isdigit((unsigned char)buffer[i + 1])) {
        *reason = "decimal point must be surrounded by digits";
        return -1;
      }
    } else if ('A' <= buffer[i] && buffer[i] <= 'Z') {
      buffer[i] = tolower((unsigned char)buffer[i]);
    }
  }

  if (base == 10) {
    // check for leading 0:  '+01' is an error!
    q = buffer;
    q += (*q == '+' || *q == '-') ? 1 : 0;
    if (q[0] == '0' && isdigit((unsigned char)q[1])) {
      *reason = "leading 0 in numbers";
      return -1;
    }
  }

  return 0;
}

static int scan_float(scanner_t *sp, token_t *tok) {
  char buffer[LITBUF_SIZE];
  scan_copystr(sp, buffer, sizeof(buffer));

  int lineno = sp->lineno;
  char *p = buffer;
  p += (*p == '+' || *p == '-') ? 1 : 0;
  if (0 == memcmp(p, "nan", 3) || (0 == memcmp(p, "inf", 3))) {
    p += 3;
  } else {
    p += strspn(p, "_0123456789eE.+-");
  }
  int len = p - buffer;
  if (len + 1 >= (int)sizeof(buffer)) {
    return SETERROR(sp->ebuf, lineno, "number too long");
  }
  buffer[len] = 0;

  const char *reason;
  if (process_numstr(buffer, 10, &reason)) {
    return SETERROR(sp->ebuf, lineno, "%s", reason);
  }

  errno = 0;
  char *q;
  double fp64 = strtod(buffer, &q);
  // glibc sets ERANGE on underflow even when strtod's result is correctly
  // rounded, e.g. 5e-324; accept such results, but still reject a value that
  // underflowed to zero or overflowed to infinity. Test the raw bits rather
  // than "fp64 != 0.0" and isfinite(): if the calling program enables
  // denormals-are-zero (e.g. an app linked with -ffast-math, or built with
  // Intel icx), an FP compare reads a subnormal as 0.0 (issue #49).
  static_assert(sizeof(fp64) == sizeof(uint64_t), "double must be 64 bits");
  uint64_t fp64_bits;
  memcpy(&fp64_bits, &fp64, sizeof(fp64));
  uint64_t fp64_mag = fp64_bits & 0x7fffffffffffffffULL; // drop the sign bit
  int is_ok_subnormal =
      (errno == ERANGE) && fp64_mag != 0 && fp64_mag < 0x7ff0000000000000ULL;
  if ((errno && !is_ok_subnormal) || *q || q == buffer) {
    return SETERROR(sp->ebuf, lineno, "error parsing float");
  }

  *tok = mktoken(sp, TOK_FLOAT);
  tok->u.fp64 = fp64;
  tok->str.len = len;
  sp->cur += len;
  return 0;
}

static int scan_number(scanner_t *sp, token_t *tok) {
  const char *reason;
  char buffer[LITBUF_SIZE];
  scan_copystr(sp, buffer, sizeof(buffer));

  char *p = buffer;
  int lineno = sp->lineno;
  // process %0x, %0o or %0b integers
  if (p[0] == '0') {
    const char *span = 0;
    int base = 0;
    switch (p[1]) {
    case 'x':
      base = 16;
      span = "_0123456789abcdefABCDEF";
      break;
    case 'o':
      base = 8;
      span = "_01234567";
      break;
    case 'b':
      base = 2;
      span = "_01";
      break;
    }
    if (base) {
      p += 2;
      p += strspn(p, span);
      int len = p - buffer;
      if (len + 1 >= (int)sizeof(buffer)) {
        return SETERROR(sp->ebuf, lineno, "number too long");
      }
      buffer[len] = 0;

      if (process_numstr(buffer + 2, base, &reason)) {
        return SETERROR(sp->ebuf, lineno, "%s", reason);
      }

      // use strtoll to obtain the value
      *tok = mktoken(sp, TOK_INTEGER);
      char *q;
      errno = 0;
      tok->u.int64 = strtoll(buffer + 2, &q, base);
      if (errno || *q || q == buffer + 2) {
        return SETERROR(sp->ebuf, lineno, "error parsing integer");
      }
      tok->str.len = len;
      sp->cur += len;
      return 0;
    }
  }

  // handle inf/nan
  if (*p == '+' || *p == '-') {
    p++;
  }
  if (*p == 'i' || *p == 'n') {
    return scan_float(sp, tok);
  }

  // regular int or float
  p = buffer;
  p += strspn(p, "0123456789_+-.eE");
  int len = p - buffer;
  if (len + 1 >= (int)sizeof(buffer)) {
    return SETERROR(sp->ebuf, lineno, "number too long");
  }
  buffer[len] = 0;

  if (process_numstr(buffer, 10, &reason)) {
    return SETERROR(sp->ebuf, lineno, "%s", reason);
  }

  *tok = mktoken(sp, TOK_INTEGER);
  char *q;
  errno = 0;
  tok->u.int64 = strtoll(buffer, &q, 10);
  if (errno || *q || q == buffer) {
    if (*q && strchr(".eE", *q)) {
      return scan_float(sp, tok); // try to fit a float
    }
    return SETERROR(sp->ebuf, lineno, "error parsing integer");
  }

  tok->str.len = len;
  sp->cur += len;
  return 0;
}

static int scan_bool(scanner_t *sp, token_t *tok) {
  char buffer[10];
  scan_copystr(sp, buffer, sizeof(buffer));

  int lineno = sp->lineno;
  bool val = false;
  const char *p = buffer;
  if (0 == strncmp(p, "true", 4)) {
    val = true;
    p += 4;
  } else if (0 == strncmp(p, "false", 5)) {
    val = false;
    p += 5;
  } else {
    return SETERROR(sp->ebuf, lineno, "invalid boolean value");
  }
  if (*p && !strchr("# \r\n\t,}]", *p)) {
    return SETERROR(sp->ebuf, lineno, "invalid boolean value");
  }

  int len = p - buffer;
  *tok = mktoken(sp, TOK_BOOL);
  tok->u.b1 = val;
  tok->str.len = len;
  sp->cur += len;
  return 0;
}

// Check if the next token may be TIME
static inline bool test_time(const char *p, const char *endp) {
  return &p[2] < endp && isdigit((unsigned char)p[0]) &&
         isdigit((unsigned char)p[1]) && p[2] == ':';
}

// Check if the next token may be DATE
static inline bool test_date(const char *p, const char *endp) {
  return &p[4] < endp && isdigit((unsigned char)p[0]) &&
         isdigit((unsigned char)p[1]) && isdigit((unsigned char)p[2]) &&
         isdigit((unsigned char)p[3]) && p[4] == '-';
}

// Check if the next token may be BOOL
static inline bool test_bool(const char *p, const char *endp) {
  return &p[0] < endp && (*p == 't' || *p == 'f');
}

// Check if the next token may be NUMBER
static bool test_number(const char *p, const char *endp) {
  if (&p[0] < endp && *p && strchr("0123456789+-._", *p)) {
    return true;
  }
  if (&p[2] < endp) {
    if (0 == memcmp(p, "nan", 3) || 0 == memcmp(p, "inf", 3)) {
      return true;
    }
  }
  return false;
}

// Scan a literal that is not a string
static int scan_nonstring_literal(scanner_t *sp, token_t *tok) {
  int lineno = sp->lineno;
  if (test_time(sp->cur, sp->endp)) {
    return scan_time(sp, tok);
  }

  if (test_date(sp->cur, sp->endp)) {
    return scan_timestamp(sp, tok);
  }

  if (test_bool(sp->cur, sp->endp)) {
    return scan_bool(sp, tok);
  }

  if (test_number(sp->cur, sp->endp)) {
    return scan_number(sp, tok);
  }
  return SETERROR(sp->ebuf, lineno, "invalid value");
}

// Return true if Unicode codepoint is allowed in a TOML 1.1 bare key.
// Ranges taken verbatim from the TOML 1.1 spec grammar for bare-key-char.
static bool is_unicode_bare_key_char(uint32_t cp) {
  if (cp == 0xB2 || cp == 0xB3 || cp == 0xB9)
    return true;
  if (0xBC <= cp && cp <= 0xBE)
    return true;
  if (0xC0 <= cp && cp <= 0xD6)
    return true;
  if (0xD8 <= cp && cp <= 0xF6)
    return true;
  if (0xF8 <= cp && cp <= 0x37D)
    return true;
  if (0x37F <= cp && cp <= 0x1FFF)
    return true;
  if (cp == 0x200C || cp == 0x200D)
    return true;
  if (0x203F <= cp && cp <= 0x2040)
    return true;
  if (0x2070 <= cp && cp <= 0x218F)
    return true;
  if (0x2460 <= cp && cp <= 0x24FF)
    return true;
  if (0x2C00 <= cp && cp <= 0x2FEF)
    return true;
  if (0x3001 <= cp && cp <= 0xD7FF)
    return true;
  if (0xF900 <= cp && cp <= 0xFDCF)
    return true;
  if (0xFDF0 <= cp && cp <= 0xFFFD)
    return cp != 0xFEFF; // BOM: stripped when leading, an error anywhere else
  if (0x10000 <= cp && cp <= 0xEFFFF)
    return true;
  return false;
}

// Scan a literal
static int scan_literal(scanner_t *sp, token_t *tok) {
  *tok = mktoken(sp, TOK_LIT);
  const char *p = sp->cur;
  while (p < sp->endp) {
    if (isalnum((unsigned char)*p) || *p == '_' || *p == '-') {
      p++;
      continue;
    }
    if ((unsigned char)*p >= 0x80) {
      uint32_t cp;
      int n = utf8_to_ucs(p, sp->endp - p, &cp);
      if (n > 0 && is_unicode_bare_key_char(cp)) {
        p += n;
        continue;
      }
    }
    break;
  }
  tok->str.len = p - tok->str.ptr;
  sp->cur = p;
  return 0;
}

// Save the current state of the scanner
static scanner_state_t scan_mark(scanner_t *sp) {
  scanner_state_t mark;
  mark.sp = sp;
  mark.cur = sp->cur;
  mark.lineno = sp->lineno;
  mark.line_start = sp->line_start;
  return mark;
}

// Restore the scanner state to a previously saved state
static void scan_restore(scanner_t *sp, scanner_state_t mark) {
  assert(mark.sp == sp);
  sp->cur = mark.cur;
  sp->lineno = mark.lineno;
  sp->line_start = mark.line_start;
}

// Return the next token
static int scan_next(scanner_t *sp, bool keymode, token_t *tok) {
  static const toktyp_t map[128] = {
      ['\n'] = TOK_ENDL, ['.'] = TOK_DOT,    ['='] = TOK_EQUAL,
      [','] = TOK_COMMA, ['{'] = TOK_LBRACE, ['}'] = TOK_RBRACE};
again:
  *tok = mktoken(sp, TOK_FIN);

  int ch = S_GET();
  if (ch == TOK_FIN) {
    return 0;
  }

  tok->str.len = 1;
  if (0 <= ch && ch < 128 && map[ch]) {
    // map simple char to token type and done
    tok->toktyp = map[ch];
    return 0;
  }

  // handle char that require logic
  switch (ch) {
  case ' ':
  case '\t':
    goto again; // skip whitespace

  case '#':
    // comment: skip until newline
    while (!S_MATCH('\n')) {
      ch = S_GET();
      if (ch == TOK_FIN)
        break;
      if ((0 <= ch && ch <= 0x8) || (0x0a <= ch && ch <= 0x1f) ||
          (ch == 0x7f)) {
        return SETERROR(sp->ebuf, sp->lineno, "bad control char in comment");
      }
    }
    goto again; // skip comment

  case '[':
    tok->toktyp = TOK_LBRACK;
    if (keymode && S_MATCH('[')) {
      S_GET();
      tok->toktyp = TOK_LLBRACK;
      tok->str.len = 2;
    }
    break;

  case ']':
    tok->toktyp = TOK_RBRACK;
    if (keymode && S_MATCH(']')) {
      S_GET();
      tok->toktyp = TOK_RRBRACK;
      tok->str.len = 2;
    }
    break;

  case '"':
    sp->cur--;
    DO(scan_string(sp, tok));
    break;

  case '\'':
    sp->cur--;
    DO(scan_litstring(sp, tok));
    break;

  default:
    sp->cur--;
    DO(keymode ? scan_literal(sp, tok) : scan_nonstring_literal(sp, tok));
    break;
  }

  return 0;
}

// Check for stack overflow due to excessive number of brackets or braces
static int check_overflow(scanner_t *sp, token_t *tok) {
  switch (tok->toktyp) {
  case TOK_LBRACK:
    sp->bracket_level++;
    if (sp->bracket_level > BRACKET_LEVEL_MAX) {
      return SETERROR(sp->ebuf, sp->lineno, "stack overflow");
    }
    break;
  case TOK_RBRACK:
    sp->bracket_level--;
    break;
  case TOK_LBRACE:
    sp->brace_level++;
    if (sp->brace_level > BRACE_LEVEL_MAX) {
      return SETERROR(sp->ebuf, sp->lineno, "stack overflow");
    }
    break;
  case TOK_RBRACE:
    sp->brace_level--;
    break;
  default:
    break;
  }
  return 0;
}

static int scan_key(scanner_t *sp, token_t *tok) {
  if (sp->errmsg) {
    return -1;
  }
  if (scan_next(sp, true, tok) || check_overflow(sp, tok)) {
    sp->errmsg = sp->ebuf.ptr;
    return -1;
  }
  return 0;
}

static int scan_value(scanner_t *sp, token_t *tok) {
  if (sp->errmsg) {
    return -1;
  }
  if (scan_next(sp, false, tok) || check_overflow(sp, tok)) {
    sp->errmsg = sp->ebuf.ptr;
    return -1;
  }
  return 0;
}

/**
 * Convert a char in utf8 into UCS, and store it in *ret.
 * Return #bytes consumed or -1 on failure.
 */
static int utf8_to_ucs(const char *orig, int len, uint32_t *ret) {
  const unsigned char *buf = (const unsigned char *)orig;
  unsigned i = *buf++;
  uint32_t v;

  /* 0x00000000 - 0x0000007F:
     0xxxxxxx
  */
  if (0 == (i >> 7)) {
    if (len < 1)
      return -1;
    v = i;
    return *ret = v, 1;
  }
  /* 0x00000080 - 0x000007FF:
     110xxxxx 10xxxxxx
  */
  if (0x6 == (i >> 5)) {
    if (len < 2)
      return -1;
    v = i & 0x1f;
    for (int j = 0; j < 1; j++) {
      i = *buf++;
      if (0x2 != (i >> 6))
        return -1;
      v = (v << 6) | (i & 0x3f);
    }
    return *ret = v, (const char *)buf - orig;
  }

  /* 0x00000800 - 0x0000FFFF:
     1110xxxx 10xxxxxx 10xxxxxx
  */
  if (0xE == (i >> 4)) {
    if (len < 3)
      return -1;
    v = i & 0x0F;
    for (int j = 0; j < 2; j++) {
      i = *buf++;
      if (0x2 != (i >> 6))
        return -1;
      v = (v << 6) | (i & 0x3f);
    }
    return *ret = v, (const char *)buf - orig;
  }

  /* 0x00010000 - 0x001FFFFF:
     11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
  */
  if (0x1E == (i >> 3)) {
    if (len < 4)
      return -1;
    v = i & 0x07;
    for (int j = 0; j < 3; j++) {
      i = *buf++;
      if (0x2 != (i >> 6))
        return -1;
      v = (v << 6) | (i & 0x3f);
    }
    return *ret = v, (const char *)buf - orig;
  }

  if (0) {
    // NOTE: these code points taking more than 4 bytes are not supported

    /* 0x00200000 - 0x03FFFFFF:
       111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if (0x3E == (i >> 2)) {
      if (len < 5)
        return -1;
      v = i & 0x03;
      for (int j = 0; j < 4; j++) {
        i = *buf++;
        if (0x2 != (i >> 6))
          return -1;
        v = (v << 6) | (i & 0x3f);
      }
      return *ret = v, (const char *)buf - orig;
    }

    /* 0x04000000 - 0x7FFFFFFF:
       1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if (0x7e == (i >> 1)) {
      if (len < 6)
        return -1;
      v = i & 0x01;
      for (int j = 0; j < 5; j++) {
        i = *buf++;
        if (0x2 != (i >> 6))
          return -1;
        v = (v << 6) | (i & 0x3f);
      }
      return *ret = v, (const char *)buf - orig;
    }
  }

  return -1;
}

/**
 * Convert a UCS char to utf8 code, and return it in buf.
 * Return #bytes used in buf to encode the char, or
 * -1 on error.
 */
static int ucs_to_utf8(uint32_t code, char buf[4]) {
  /* http://stackoverflow.com/questions/6240055/manually-converting-unicode-codepoints-into-utf-8-and-utf-16
   */
  /* The UCS code values 0xd800–0xdfff (UTF-16 surrogates) as well
   * as 0xfffe and 0xffff (UCS noncharacters) should not appear in
   * conforming UTF-8 streams.
   */
  /*
   *  https://github.com/toml-lang/toml-test/issues/165
   *  [0xd800, 0xdfff] and [0xfffe, 0xffff] are implicitly allowed by TOML, so
   * we disable the check.
   */
  if (0) {
    if (0xd800 <= code && code <= 0xdfff)
      return -1;
    if (0xfffe <= code && code <= 0xffff)
      return -1;
  }

  /* 0x00000000 - 0x0000007F:
     0xxxxxxx
  */
  if (code <= 0x7F) {
    buf[0] = (unsigned char)code;
    return 1;
  }

  /* 0x00000080 - 0x000007FF:
     110xxxxx 10xxxxxx
  */
  if (code <= 0x000007FF) {
    buf[0] = (unsigned char)(0xc0 | (code >> 6));
    buf[1] = (unsigned char)(0x80 | (code & 0x3f));
    return 2;
  }

  /* 0x00000800 - 0x0000FFFF:
     1110xxxx 10xxxxxx 10xxxxxx
  */
  if (code <= 0x0000FFFF) {
    buf[0] = (unsigned char)(0xe0 | (code >> 12));
    buf[1] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
    buf[2] = (unsigned char)(0x80 | (code & 0x3f));
    return 3;
  }

  /* 0x00010000 - 0x001FFFFF:
     11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
  */
  if (code <= 0x001FFFFF) {
    buf[0] = (unsigned char)(0xf0 | (code >> 18));
    buf[1] = (unsigned char)(0x80 | ((code >> 12) & 0x3f));
    buf[2] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
    buf[3] = (unsigned char)(0x80 | (code & 0x3f));
    return 4;
  }

#ifdef UNDEF
  if (0) {
    // NOTE: these code points taking more than 4 bytes are not supported
    /* 0x00200000 - 0x03FFFFFF:
       111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if (code <= 0x03FFFFFF) {
      buf[0] = (unsigned char)(0xf8 | (code >> 24));
      buf[1] = (unsigned char)(0x80 | ((code >> 18) & 0x3f));
      buf[2] = (unsigned char)(0x80 | ((code >> 12) & 0x3f));
      buf[3] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
      buf[4] = (unsigned char)(0x80 | (code & 0x3f));
      return 5;
    }

    /* 0x04000000 - 0x7FFFFFFF:
       1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if (code <= 0x7FFFFFFF) {
      buf[0] = (unsigned char)(0xfc | (code >> 30));
      buf[1] = (unsigned char)(0x80 | ((code >> 24) & 0x3f));
      buf[2] = (unsigned char)(0x80 | ((code >> 18) & 0x3f));
      buf[3] = (unsigned char)(0x80 | ((code >> 12) & 0x3f));
      buf[4] = (unsigned char)(0x80 | ((code >> 6) & 0x3f));
      buf[5] = (unsigned char)(0x80 | (code & 0x3f));
      return 6;
    }
  }
#endif

  return -1;
}
