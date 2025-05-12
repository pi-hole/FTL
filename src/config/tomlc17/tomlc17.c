/* Copyright (c) 2024-2025, CK Tan.
 * https://github.com/cktan/tomlc17/blob/main/LICENSE
 */
#include "tomlc17.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static toml_option_t toml_option = {0, malloc, free, realloc};

#define MALLOC(n) toml_option.mem_alloc(n)
#define FREE(p) toml_option.mem_free(p)
#define REALLOC(p, n) toml_option.mem_realloc(p, n)

#define DO(x)                                                                  \
  if (x)                                                                       \
    return -1;                                                                 \
  else                                                                         \
    (void)0;
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
static int ERROR(ebuf_t ebuf, int lineno, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char *p = ebuf.ptr;
  char *q = p + ebuf.len;
  if (lineno) {
    snprintf(p, q - p, "(line %d) ", lineno);
    p += strlen(p);
  }
  vsnprintf(p, q - p, fmt, args);
  return -1;
}

/*
 *  Memory pool. Allocated a big block once and hand out piecemeal.
 */
typedef struct pool_t pool_t;
struct pool_t {
  int top, max;
  char buf[0]; // first byte starts here
};

/**
 *  Create a memory pool of N bytes. Return the memory pool on
 *  success, or NULL if out of memory.
 */
static pool_t *pool_create(int N) {
  if (N <= 0) {
    return NULL;
  }
  int totalsz = sizeof(pool_t) + N;
  pool_t *pool = MALLOC(totalsz);
  if (!pool) {
    return NULL;
  }
  memset(pool, 0, totalsz);
  pool->max = N;
  return pool;
}

/**
 *  Destroy a memory pool.
 */
static void pool_destroy(pool_t *pool) { FREE(pool); }

/**
 *  Allocate n bytes from pool. Return the memory allocated on
 *  success, or NULL if out of memory.
 */
static char *pool_alloc(pool_t *pool, int n) {
  if (pool->top + n > pool->max) {
    return NULL;
  }
  char *ret = pool->buf + pool->top;
  pool->top += n;
  return ret;
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

// flags for toml_datum_t::flag.
#define FLAG_INLINED 1
#define FLAG_STDEXPR 2
#define FLAG_EXPLICIT 4

static inline size_t align8(size_t x) { return (((x) + 7) & ~7); }

enum toktyp_t {
  DOT = 1,
  EQUAL,
  COMMA,
  LBRACK,
  LLBRACK,
  RBRACK,
  RRBRACK,
  LBRACE,
  RBRACE,
  LIT,
  STRING,
  MLSTRING,
  LITSTRING,
  MLLITSTRING,
  TIME,
  DATE,
  DATETIME,
  DATETIMETZ,
  INTEGER,
  FLOAT,
  BOOL,
  ENDL,
  FIN = -5000, // EOF
};
typedef enum toktyp_t toktyp_t;
typedef struct scanner_t scanner_t;

/* Remember the current state of a scanner */
typedef struct scanner_state_t scanner_state_t;
struct scanner_state_t {
  scanner_t *sp;
  const char *cur; // points into scanner_t::src[]
  int lineno;      // current line number
};

// A scan token
typedef struct token_t token_t;
struct token_t {
  toktyp_t toktyp;
  int lineno;
  span_t str;

  // values represented by str
  union {
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
  const char *src;  // src[] is a NUL-terminated string
  const char *endp; // end of src[]. always pointing at a NUL char.
  const char *cur;  // current char in src[]
  int lineno;       // line number of current char
  char *errmsg;     // point to errbuf if there was an error
  ebuf_t ebuf;
};
static void scan_init(scanner_t *sp, const char *src, int len, char *errbuf,
                      int errbufsz);
static int scan_key(scanner_t *sp, token_t *tok);
static int scan_value(scanner_t *sp, token_t *tok);
// restore scanner to state before tok was returned
static scanner_state_t scan_mark(scanner_t *sp);
static void scan_restore(scanner_t *sp, scanner_state_t state);

// Parser object
typedef struct parser_t parser_t;
struct parser_t {
  scanner_t scanner;
  toml_datum_t toptab;  // top table
  toml_datum_t *curtab; // current table
  pool_t *pool;         // memory pool for strings
  ebuf_t ebuf;
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

// Add a new key in tab. Return 0 on success, -1 otherwise.
// On error, reason will point to an error message.
static int tab_add(toml_datum_t *tab, span_t newkey, toml_datum_t newvalue,
                   const char **reason) {
  // Check for duplicate key
  int nkey = tab->u.tab.size;
  for (int i = 0; i < nkey; i++) {
    if (tab->u.tab.len[i] == newkey.len &&
        0 == memcmp(tab->u.tab.key[i], newkey.ptr, newkey.len)) {
      *reason = "duplicate key";
      return -1;
    }
  }

  // Expand pkey[], plen[] and value[]
  char **pkey = REALLOC(tab->u.tab.key, sizeof(*pkey) * align8(nkey + 1));
  int *plen = REALLOC(tab->u.tab.len, sizeof(*plen) * align8(nkey + 1));
  toml_datum_t *value =
      REALLOC(tab->u.tab.value, sizeof(*value) * align8(nkey + 1));
  if (!pkey || !plen || !value) {
    *reason = "out of memory";
    return -1;
  }
  tab->u.tab.key = (const char **)pkey;
  tab->u.tab.len = plen;
  tab->u.tab.value = value;

  // Append the new key/value
  tab->u.tab.size = nkey + 1;
  pkey[nkey] = (char *)newkey.ptr;
  plen[nkey] = newkey.len;
  value[nkey] = newvalue;
  return 0;
}

// Add a new element into an array. Return 0 on success, -1 otherwise.
// On error, reason will point to an error message.
static int arr_add(toml_datum_t *arr, toml_datum_t newelem,
                   const char **reason) {
  assert(arr->type == TOML_ARRAY);
  int n = arr->u.arr.size;
  toml_datum_t *elem = REALLOC(arr->u.arr.elem, sizeof(*elem) * align8(n + 1));
  if (!elem) {
    *reason = "out of memory";
    return -1;
  }
  arr->u.arr.elem = elem;
  arr->u.arr.size = n + 1;
  elem[n] = newelem;
  return 0;
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

// Recursively free any dynamically allocated memory in the datum tree
static void free_datum(toml_datum_t datum) {
  if (datum.type == TOML_TABLE) {
    for (int i = 0, top = datum.u.tab.size; i < top; i++) {
      free_datum(datum.u.tab.value[i]);
    }
    FREE(datum.u.tab.key);
    FREE(datum.u.tab.len);
    FREE(datum.u.tab.value);
    return;
  }
  if (datum.type == TOML_ARRAY) {
    for (int i = 0, top = datum.u.arr.size; i < top; i++) {
      free_datum(datum.u.arr.elem[i]);
    }
    FREE(datum.u.arr.elem);
    return;
  }
  // other types do not allocate memory
}

/**
 * Find a key in a toml_table. Return the value of the key if found,
 * or a TOML_UNKNOWN otherwise.
 */
toml_datum_t toml_table_find(toml_datum_t datum, const char *key) {
  toml_datum_t ret = {0};
  if (datum.type == TOML_TABLE) {
    int n = datum.u.tab.size;
    const char **pkey = datum.u.tab.key;
    toml_datum_t *pvalue = datum.u.tab.value;
    for (int i = 0; i < n; i++) {
      if (0 == strcmp(pkey[i], key)) {
        return pvalue[i];
      }
    }
  }
  return ret;
}

/**
 *  Return the default options.
 */
toml_option_t toml_default_option(void) {
  toml_option_t opt = {0, malloc, free, realloc};
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
  pool_destroy((pool_t *)result.__internal);
  free_datum(result.toptab);
}

/**
 *  Parse a toml document.
 */
toml_result_t toml_parse_file_ex(const char *fname) {
  toml_result_t result = {0};
  FILE *fp = fopen(fname, "r");
  if (!fp) {
    snprintf(result.errmsg, sizeof(result.errmsg), "fopen: %s", fname);
    return result;
  }
  result = toml_parse_file(fp);
  fclose(fp);
  return result;
}

/**
 *  Parse a toml document.
 */
toml_result_t toml_parse_file(FILE *fp) {
  toml_result_t result = {0};
  char *buf = 0;
  int top, max; // index into buf[]
  top = max = 0;

  // Read file into memory
  while (!feof(fp)) {
    assert(top <= max);
    if (top == max) {
      // need to extend buf[]
      int tmpmax = (max * 1.5) + 1000;
      if (tmpmax < 0) {
        // the real max is INT_MAX - 1 to account for terminating NUL.
        if (max < INT_MAX - 1) {
          tmpmax = INT_MAX - 1;
        } else {
          snprintf(result.errmsg, sizeof(result.errmsg),
                   "file is bigger than %d bytes", INT_MAX - 1);
          FREE(buf);
          return result;
        }
      }
      // add an extra byte for terminating NUL
      char *tmp = REALLOC(buf, tmpmax + 1);
      if (!tmp) {
        snprintf(result.errmsg, sizeof(result.errmsg), "out of memory");
        FREE(buf);
        return result;
      }
      buf = tmp;
      max = tmpmax;
    }

    errno = 0;
    top += fread(buf + top, 1, max - top, fp);
    if (ferror(fp)) {
      snprintf(result.errmsg, sizeof(result.errmsg), "%s",
               errno ? strerror(errno) : "Error reading file");
      FREE(buf);
      return result;
    }
  }
  buf[top] = 0; // NUL terminator

  result = toml_parse(buf, top);
  FREE(buf);
  return result;
}

/**
 *  Parse a toml document.
 */
toml_result_t toml_parse(const char *src, int len) {
  toml_result_t result = {0};
  parser_t parser = {0};
  parser_t *pp = &parser;

  // Check that src is NUL terminated.
  if (src[len]) {
    snprintf(result.errmsg, sizeof(result.errmsg),
             "src[] must be NUL terminated");
    goto bail;
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
  pp->toptab = mkdatum(TOML_TABLE);
  pp->curtab = &pp->toptab;
  pp->ebuf.ptr = result.errmsg;
  pp->ebuf.len = sizeof(result.errmsg);

  // Alloc memory pool
  pp->pool =
      pool_create(len + 10); // add some extra bytes for NUL term and safety
  if (!pp->pool) {
    snprintf(result.errmsg, sizeof(result.errmsg), "out of memory");
    goto bail;
  }

  // Initialize scanner.
  scan_init(&pp->scanner, src, len, pp->ebuf.ptr, pp->ebuf.len);

  // Keep parsing until FIN
  for (;;) {
    token_t tok;
    if (scan_key(&pp->scanner, &tok)) {
      goto bail;
    }
    // break on FIN
    if (tok.toktyp == FIN) {
      break;
    }
    switch (tok.toktyp) {
    case ENDL: // skip blank lines
      continue;
    case LBRACK:
      if (parse_std_table_expr(pp, tok)) {
        goto bail;
      }
      break;
    case LLBRACK:
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
    if (tok.toktyp == FIN || tok.toktyp == ENDL) {
      continue;
    }
    ERROR(pp->ebuf, tok.lineno, "ENDL expected");
    goto bail;
  }

  // return result
  result.ok = true;
  result.toptab = pp->toptab;
  result.__internal = (void *)pp->pool;
  return result;

bail:
  // cleanup
  pool_destroy(pp->pool);
  result.ok = false;
  assert(result.errmsg[0]); // make sure there is an errmsg
  return result;
}

// Convert a (LITSTRING, LIT, MLLITSTRING, MLSTRING, or STRING) token to a
// datum.
static int token_to_string(parser_t *pp, token_t tok, toml_datum_t *ret) {
  *ret = mkdatum(TOML_STRING);
  span_t span;
  DO(parse_norm(pp, tok, &span));
  ret->u.str.ptr = (char *)span.ptr;
  ret->u.str.len = span.len;
  return 0;
}

// Convert TIME token to a datum.
static int token_to_time(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  *ret = mkdatum(TOML_TIME);
  ret->u.ts.hour = tok.u.tsval.hour;
  ret->u.ts.minute = tok.u.tsval.minute;
  ret->u.ts.second = tok.u.tsval.sec;
  ret->u.ts.usec = tok.u.tsval.usec;
  return 0;
}

// Convert a DATE token to a datum.
static int token_to_date(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  *ret = mkdatum(TOML_DATE);
  ret->u.ts.year = tok.u.tsval.year;
  ret->u.ts.month = tok.u.tsval.month;
  ret->u.ts.day = tok.u.tsval.day;
  return 0;
}

// Convert a DATETIME token to a datum.
static int token_to_datetime(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  *ret = mkdatum(TOML_DATETIME);
  ret->u.ts.year = tok.u.tsval.year;
  ret->u.ts.month = tok.u.tsval.month;
  ret->u.ts.day = tok.u.tsval.day;
  ret->u.ts.hour = tok.u.tsval.hour;
  ret->u.ts.minute = tok.u.tsval.minute;
  ret->u.ts.second = tok.u.tsval.sec;
  ret->u.ts.usec = tok.u.tsval.usec;
  return 0;
}

// Convert a DATETIMETZ token to a datum.
static int token_to_datetimetz(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  *ret = mkdatum(TOML_DATETIMETZ);
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
  assert(tok.toktyp == INTEGER);
  *ret = mkdatum(TOML_INT64);
  ret->u.int64 = tok.u.int64;
  return 0;
}

// Convert a fp64 token to a datum.
static int token_to_fp64(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  assert(tok.toktyp == FLOAT);
  *ret = mkdatum(TOML_FP64);
  ret->u.fp64 = tok.u.fp64;
  return 0;
}

// Convert a boolean token to a datum.
static int token_to_boolean(parser_t *pp, token_t tok, toml_datum_t *ret) {
  (void)pp;
  assert(tok.toktyp == BOOL);
  *ret = mkdatum(TOML_BOOLEAN);
  ret->u.boolean = tok.u.b1;
  return 0;
}

// Parse a multipart key. Return 0 on success, -1 otherwise.
static int parse_key(parser_t *pp, token_t tok, keypart_t *ret_keypart) {
  ret_keypart->nspan = 0;
  // key = simple-key | dotted_key
  // simple-key = STRING | LITSTRING | LIT
  // dotted-key = simple-key (DOT simple-key)+
  if (tok.toktyp != STRING && tok.toktyp != LITSTRING && tok.toktyp != LIT) {
    return ERROR(pp->ebuf, tok.lineno, "missing key");
  }

  int n = 0;
  span_t *kpspan = ret_keypart->span;

  // Normalize the first keypart
  if (parse_norm(pp, tok, &kpspan[n])) {
    return ERROR(pp->ebuf, tok.lineno,
                 "unable to normalize string; probably a unicode issue");
  }
  n++;

  // Scan and normalize the second to last keypart
  while (1) {
    scanner_state_t mark = scan_mark(&pp->scanner);

    // Eat the dot if it is there
    DO(scan_key(&pp->scanner, &tok));

    // If not a dot, we are done with keyparts.
    if (tok.toktyp != DOT) {
      scan_restore(&pp->scanner, mark);
      break;
    }

    // Scan the n-th key
    DO(scan_key(&pp->scanner, &tok));

    if (tok.toktyp != STRING && tok.toktyp != LITSTRING && tok.toktyp != LIT) {
      return ERROR(pp->ebuf, tok.lineno, "expects a string in dotted-key");
    }

    if (n >= KEYPARTMAX) {
      return ERROR(pp->ebuf, tok.lineno, "too many key parts");
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
static toml_datum_t *descend_keypart(parser_t *pp, int lineno,
                                     toml_datum_t *toptab, keypart_t *keypart,
                                     bool stdtabexpr) {
  toml_datum_t *tab = toptab; // current tab

  for (int i = 0; i < keypart->nspan; i++) {
    const char *reason;
    // Find the i-th keypart
    int j = tab_find(tab, keypart->span[i]);
    // Not found: add a new (key, tab) pair.
    if (j < 0) {
      toml_datum_t newtab = mkdatum(TOML_TABLE);
      newtab.flag |= stdtabexpr ? FLAG_STDEXPR : 0;
      if (tab_add(tab, keypart->span[i], newtab, &reason)) {
        ERROR(pp->ebuf, lineno, "%s", reason);
        return NULL;
      }
      // Descend.
      tab = &tab->u.tab.value[tab->u.tab.size - 1];
      continue;
    }

    // Found: extract the value of the key.
    toml_datum_t *value = &tab->u.tab.value[j];

    // If the value is a table, descend.
    if (value->type == TOML_TABLE) {
      tab = value;
      continue;
    }

    // If the value is an array...
    if (value->type == TOML_ARRAY) {
      // If empty: error.
      if (value->u.arr.size <= 0) {
        ERROR(pp->ebuf, lineno, "array %s has no elements",
              keypart->span[i].ptr);
        return NULL;
      }

      // Extract the last element of the array.
      value = &value->u.arr.elem[value->u.arr.size - 1];

      // It must be a table!
      if (value->type != TOML_TABLE) {
        ERROR(pp->ebuf, lineno, "array %s must be array of tables",
              keypart->span[i].ptr);
        return NULL;
      }

      // Descend.
      tab = value;
      continue;
    }

    // key not found
    ERROR(pp->ebuf, lineno, "cannot locate table at key %s",
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
  assert(tok.toktyp == LBRACK);
  *ret_datum = mkdatum(TOML_ARRAY);
  int need_comma = 0;

  // loop until RBRACK
  for (;;) {
    // skip ENDL
    do {
      DO(scan_value(&pp->scanner, &tok));
    } while (tok.toktyp == ENDL);

    // If got an RBRACK: done!
    if (tok.toktyp == RBRACK) {
      break;
    }

    // If got a COMMA: check if it is expected.
    if (tok.toktyp == COMMA) {
      if (need_comma) {
        need_comma = 0;
        continue;
      }
      return ERROR(pp->ebuf, tok.lineno,
                   "syntax error while parsing array: unexpected comma");
    }

    // Not a comma, but need a comma: error!
    if (need_comma) {
      return ERROR(pp->ebuf, tok.lineno,
                   "syntax error while parsing array: missing comma");
    }

    // This is a valid value!

    // Parse the value.
    const char *reason;
    toml_datum_t elem;
    DO(parse_val(pp, tok, &elem));

    // Add the value to the array.
    if (arr_add(ret_datum, elem, &reason)) {
      return ERROR(pp->ebuf, tok.lineno, "while parsing array: %s", reason);
    }

    // Need comma before the next value.
    need_comma = 1;
  }

  // Set the INLINE flag for all things in this array.
  set_flag_recursive(ret_datum, FLAG_INLINED);
  return 0;
}

// Parse an inline table.
static int parse_inline_table(parser_t *pp, token_t tok,
                              toml_datum_t *ret_datum) {
  assert(tok.toktyp == LBRACE);
  *ret_datum = mkdatum(TOML_TABLE);
  bool need_comma = 0;
  bool was_comma = 0;

  // loop until RBRACE
  for (;;) {
    DO(scan_key(&pp->scanner, &tok));

    // Got an RBRACE: done!
    if (tok.toktyp == RBRACE) {
      if (was_comma) {
        return ERROR(pp->ebuf, tok.lineno, "extra comma before closing brace");
      }
      break;
    }

    // Got a comma: check if it is expected.
    if (tok.toktyp == COMMA) {
      if (need_comma) {
        need_comma = 0, was_comma = 1;
        continue;
      }
      return ERROR(pp->ebuf, tok.lineno, "unexpected comma");
    }

    // Not a comma, but need a comma: error!
    if (need_comma) {
      return ERROR(pp->ebuf, tok.lineno, "missing comma");
    }

    // Newline not allowed in inline table.
    if (tok.toktyp == ENDL) {
      return ERROR(pp->ebuf, tok.lineno, "unexpected newline");
    }

    // Get the keyparts
    keypart_t keypart = {0};
    int keylineno = tok.lineno;
    DO(parse_key(pp, tok, &keypart));

    // Descend to one keypart before last
    span_t lastkeypart = keypart.span[--keypart.nspan];
    toml_datum_t *tab =
        descend_keypart(pp, keylineno, ret_datum, &keypart, false);
    if (!tab) {
      return -1;
    }

    // If tab is a previously declared inline table: error.
    if (tab->flag & FLAG_INLINED) {
      return ERROR(pp->ebuf, tok.lineno, "inline table cannot be extended");
    }

    // We are explicitly defining it now.
    tab->flag |= FLAG_EXPLICIT;

    // match EQUAL
    DO(scan_value(&pp->scanner, &tok));

    if (tok.toktyp != EQUAL) {
      if (tok.toktyp == ENDL) {
        return ERROR(pp->ebuf, tok.lineno, "unexpected newline");
      } else {
        return ERROR(pp->ebuf, tok.lineno, "missing '='");
      }
    }

    // obtain the value
    toml_datum_t value;
    DO(scan_value(&pp->scanner, &tok));
    DO(parse_val(pp, tok, &value));

    // Add the value to tab.
    const char *reason;
    if (tab_add(tab, lastkeypart, value, &reason)) {
      return ERROR(pp->ebuf, tok.lineno, "%s", reason);
    }
    need_comma = 1, was_comma = 0;
  }

  set_flag_recursive(ret_datum, FLAG_INLINED);
  return 0;
}

// Parse a value.
static int parse_val(parser_t *pp, token_t tok, toml_datum_t *ret) {
  // val = string / boolean / array / inline-table / date-time / float / integer
  switch (tok.toktyp) {
  case STRING:
  case MLSTRING:
  case LITSTRING:
  case MLLITSTRING:
    return token_to_string(pp, tok, ret);
  case TIME:
    return token_to_time(pp, tok, ret);
  case DATE:
    return token_to_date(pp, tok, ret);
  case DATETIME:
    return token_to_datetime(pp, tok, ret);
  case DATETIMETZ:
    return token_to_datetimetz(pp, tok, ret);
  case INTEGER:
    return token_to_int64(pp, tok, ret);
  case FLOAT:
    return token_to_fp64(pp, tok, ret);
  case BOOL:
    return token_to_boolean(pp, tok, ret);
  case LBRACK: // inline-array
    return parse_inline_array(pp, tok, ret);
  case LBRACE: // inline-table
    return parse_inline_table(pp, tok, ret);
  default:
    break;
  }
  return ERROR(pp->ebuf, tok.lineno, "missing value");
}

// Parse a standard table expression, and set the curtab of the parser
// to the table referenced.  A standard table expression is a line
// like [a.b.c.d].
static int parse_std_table_expr(parser_t *pp, token_t tok) {
  // std-table = [ key ]
  // Eat the [
  assert(tok.toktyp == LBRACK); // [ ate by caller

  // Read the first keypart
  DO(scan_key(&pp->scanner, &tok));

  // Extract the keypart[]
  int keylineno = tok.lineno;
  keypart_t keypart;
  DO(parse_key(pp, tok, &keypart));

  // Eat the ]
  DO(scan_key(&pp->scanner, &tok));
  if (tok.toktyp != RBRACK) {
    return ERROR(pp->ebuf, tok.lineno, "missing right-bracket");
  }

  // Descend to one keypart before last.
  span_t lastkeypart = keypart.span[--keypart.nspan];

  // Descend keypart from the toptab.
  toml_datum_t *tab =
      descend_keypart(pp, keylineno, &pp->toptab, &keypart, true);
  if (!tab) {
    return -1;
  }

  // Look for the last keypart in the final tab
  int j = tab_find(tab, lastkeypart);
  if (j < 0) {
    // If not found: add it.
    if (tab->flag & FLAG_INLINED) {
      return ERROR(pp->ebuf, keylineno, "inline table cannot be extended");
    }
    const char *reason;
    toml_datum_t newtab = mkdatum(TOML_TABLE);
    newtab.flag |= FLAG_STDEXPR;
    if (tab_add(tab, lastkeypart, newtab, &reason)) {
      return ERROR(pp->ebuf, keylineno, "%s", reason);
    }
    // this is the new tab
    tab = &tab->u.tab.value[tab->u.tab.size - 1];
  } else {
    // Found: check for errors
    tab = &tab->u.tab.value[j];
    if (tab->flag & FLAG_EXPLICIT) {
      /*
        This is not OK:
        [x.y.z]
        [x.y.z]

        but this is OK:
        [x.y.z]
        [x]
      */
      return ERROR(pp->ebuf, keylineno, "table defined more than once");
    }
    if (!(tab->flag & FLAG_STDEXPR)) {
      /*
      [t1]			# OK
      t2.t3.v = 0		# OK
      [t1.t2]   		# should FAIL  - t2 was non-explicit but was not
      created by std-table-expr
      */
      return ERROR(pp->ebuf, keylineno, "table defined before");
    }
  }

  // Set explicit flag on tab
  tab->flag |= FLAG_EXPLICIT;

  // Set tab as curtab of the parser
  pp->curtab = tab;
  return 0;
}

// Parse an array table expression, and set the curtab of the parser
// to the table referenced. A standard array table expresison is a line
// like [[a.b.c.d]].
static int parse_array_table_expr(parser_t *pp, token_t tok) {
  // array-table = [[ key ]]
  assert(tok.toktyp == LLBRACK); // [[ ate by caller

  // Read the first keypart
  DO(scan_key(&pp->scanner, &tok));

  int keylineno = tok.lineno;
  keypart_t keypart;
  DO(parse_key(pp, tok, &keypart));

  // eat the ]]
  token_t rrb;
  DO(scan_key(&pp->scanner, &rrb));
  if (rrb.toktyp != RRBRACK) {
    return ERROR(pp->ebuf, rrb.lineno, "missing ']]'");
  }

  // remove the last keypart from keypart[]
  span_t lastkeypart = keypart.span[--keypart.nspan];

  // descend the key from the toptab
  toml_datum_t *tab = &pp->toptab;
  for (int i = 0; i < keypart.nspan; i++) {
    span_t curkey = keypart.span[i];
    int j = tab_find(tab, curkey);
    if (j < 0) {
      // If not found: add a new (key,tab) pair
      const char *reason;
      toml_datum_t newtab = mkdatum(TOML_TABLE);
      newtab.flag |= FLAG_STDEXPR;
      if (tab_add(tab, curkey, newtab, &reason)) {
        return ERROR(pp->ebuf, keylineno, "%s", reason);
      }
      tab = &tab->u.tab.value[tab->u.tab.size - 1];
      continue;
    }

    // Found: get the value
    toml_datum_t *value = &tab->u.tab.value[j];

    // If value is table, then point to that table and continue descent.
    if (value->type == TOML_TABLE) {
      tab = value;
      continue;
    }

    // If value is an array of table, point to the last element of the array and
    // continue descent.
    if (value->type == TOML_ARRAY) {
      if (value->flag & FLAG_INLINED) {
        return ERROR(pp->ebuf, keylineno, "cannot expand array %s", curkey.ptr);
      }
      if (value->u.arr.size <= 0) {
        return ERROR(pp->ebuf, keylineno, "array %s has no elements",
                     curkey.ptr);
      }
      value = &value->u.arr.elem[value->u.arr.size - 1];
      if (value->type != TOML_TABLE) {
        return ERROR(pp->ebuf, keylineno, "array %s must be array of tables",
                     curkey.ptr);
      }
      tab = value;
      continue;
    }

    // keypart not found
    return ERROR(pp->ebuf, keylineno, "cannot locate table at key %s",
                 curkey.ptr);
  }

  // For the final keypart, make sure entry at key is an array of tables
  const char *reason;
  int idx = tab_find(tab, lastkeypart);
  if (idx == -1) {
    // If not found, add an array of table.
    if (tab_add(tab, lastkeypart, mkdatum(TOML_ARRAY), &reason)) {
      return ERROR(pp->ebuf, keylineno, "%s", reason);
    }
    idx = tab_find(tab, lastkeypart);
    assert(idx >= 0);
  }
  // Check that this is an array.
  if (tab->u.tab.value[idx].type != TOML_ARRAY) {
    return ERROR(pp->ebuf, keylineno, "entry must be an array");
  }
  // Add a table to the array
  toml_datum_t *arr = &tab->u.tab.value[idx];
  if (arr->flag & FLAG_INLINED) {
    return ERROR(pp->ebuf, keylineno, "cannot extend a static array");
  }
  if (arr_add(arr, mkdatum(TOML_TABLE), &reason)) {
    return ERROR(pp->ebuf, keylineno, "%s", reason);
  }

  // Set the last element of this array as curtab of the parser
  pp->curtab = &arr->u.arr.elem[arr->u.arr.size - 1];
  assert(pp->curtab->type == TOML_TABLE);

  return 0;
}

// Parse an expression. A toml doc is just a list of expressions.
static int parse_keyvalue_expr(parser_t *pp, token_t tok) {
  // Obtain the key
  int keylineno = tok.lineno;
  keypart_t keypart;
  DO(parse_key(pp, tok, &keypart));

  // match the '='
  DO(scan_key(&pp->scanner, &tok));
  if (tok.toktyp != EQUAL) {
    return ERROR(pp->ebuf, tok.lineno, "expect '='");
  }

  // Obtain the value
  toml_datum_t val;
  DO(scan_value(&pp->scanner, &tok));
  DO(parse_val(pp, tok, &val));

  // Locate the last table using keypart[]
  const char *reason;
  toml_datum_t *tab = pp->curtab;
  for (int i = 0; i < keypart.nspan - 1; i++) {
    int j = tab_find(tab, keypart.span[i]);
    if (j < 0) {
      if (i > 0 && (tab->flag & FLAG_EXPLICIT)) {
        return ERROR(
            pp->ebuf, keylineno,
            "cannot extend a previously defined table using dotted expression");
      }
      toml_datum_t newtab = mkdatum(TOML_TABLE);
      if (tab_add(tab, keypart.span[i], newtab, &reason)) {
        return ERROR(pp->ebuf, keylineno, "%s", reason);
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
      return ERROR(pp->ebuf, keylineno,
                   "encountered previously declared array '%s'",
                   keypart.span[i].ptr);
    }
    return ERROR(pp->ebuf, keylineno, "cannot locate table at '%s'",
                 keypart.span[i].ptr);
  }

  // Check for disallowed situations.
  if (tab->flag & FLAG_INLINED) {
    return ERROR(pp->ebuf, keylineno, "inline table cannot be extended");
  }
  if (keypart.nspan > 1 && (tab->flag & FLAG_EXPLICIT)) {
    return ERROR(
        pp->ebuf, keylineno,
        "cannot extend a previously defined table using dotted expression");
  }

  // Add a new key/value for tab.
  if (tab_add(tab, keypart.span[keypart.nspan - 1], val, &reason)) {
    return ERROR(pp->ebuf, keylineno, "%s", reason);
  }

  return 0;
}

// Normalize a LIT/STRING/MLSTRING/LITSTRING/MLLITSTRING
// -> unescape all escaped chars
// The returned string is allocated out of pp->sbuf[]
static int parse_norm(parser_t *pp, token_t tok, span_t *ret_span) {
  // Allocate a buffer to store the normalized string. Add one
  // extra-byte for terminating NUL.
  char *p = pool_alloc(pp->pool, tok.str.len + 1);
  if (!p) {
    return ERROR(pp->ebuf, tok.lineno, "out of memory");
  }

  // Copy from token string into buffer
  memcpy(p, tok.str.ptr, tok.str.len);
  p[tok.str.len] = 0; // additional NUL term for safety

  ret_span->ptr = p;
  ret_span->len = tok.str.len;

  switch (tok.toktyp) {
  case LIT:
  case LITSTRING:
  case MLLITSTRING:
    // no need to handle escape chars
    return 0;

  case STRING:
  case MLSTRING:
    // need to handle escape chars
    break;

  default:
    return ERROR(pp->ebuf, 0, "internal: arg must be a string");
  }

  // if there is no escape char, then done!
  p = memchr(ret_span->ptr, '\\', ret_span->len);
  if (!p) {
    return 0; // success
  }

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
    case 'f':
      *dst++ = '\f';
      p += 2;
      continue;
    case 't':
      *dst++ = '\t';
      p += 2;
      continue;
    case 'r':
      *dst++ = '\r';
      p += 2;
      continue;
    case 'n':
      *dst++ = '\n';
      p += 2;
      continue;
    case 'u':
    case 'U': {
      char buf[9];
      int sz = (p[1] == 'u' ? 4 : 8);
      memcpy(buf, p + 2, sz);
      buf[sz] = 0;
      int32_t ucs = strtol(buf, 0, 16);
      if (0xD800 <= ucs && ucs <= 0xDFFF) {
        // explicitly prohibit surrogates (non-scalar unicode code point)
        return ERROR(pp->ebuf, tok.lineno, "invalid UTF8 char \\u%04x", ucs);
      }
      int n = ucs_to_utf8(ucs, dst);
      if (n < 0) {
        return ERROR(pp->ebuf, tok.lineno, "error converting UCS %s to UTF8",
                     buf);
      }
      dst += n;
      p += 2 + sz;
    } break;

    case ' ':
    case '\t':
    case '\r':
      // line-ending backslash
      // --- allow for extra whitespace chars after backslash
      // --- skip until newline
      p++;
      p += strspn(p, " \t\r");
      if (*p != '\n') {
        return ERROR(pp->ebuf, tok.lineno, "internal error");
      }
      // fallthru
    case '\n':
      // skip all whitespaces including newline
      p++;
      p += strspn(p, " \t\r\n");
      continue;
    default:
      *dst++ = *p++;
      break;
    }
  }
  *dst = 0;
  ret_span->len = dst - ret_span->ptr;
  return 0;
}

// -------------- scanner functions

// Get the next char
static int scan_get(scanner_t *sp) {
  int ret = FIN;
  const char *p = sp->cur;
  if (p < sp->endp) {
    ret = *p++;
    if (ret == '\r' && p < sp->endp && *p == '\n') {
      ret = *p++;
    }
  }
  sp->cur = p;
  sp->lineno += (ret == '\n' ? 1 : 0);
  return ret;
}

// Check if the next char matches ch.
static inline bool scan_match(scanner_t *sp, int ch) {
  const char *p = sp->cur;
  if (p < sp->endp && *p == ch) {
    return true;
  }
  if (ch == '\n' && p + 1 < sp->endp) {
    return p[0] == '\r' && p[1] == '\n';
  }
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
  return tok;
}

#define S_GET() scan_get(sp)
#define S_MATCH(ch) scan_match(sp, (ch))
#define S_MATCH3(ch) scan_nmatch(sp, (ch), 3)
#define S_MATCH4(ch) scan_nmatch(sp, (ch), 4)
#define S_MATCH6(ch) scan_nmatch(sp, (ch), 6)

static inline bool is_valid_char(int ch) {
  // i.e. (0x20 <= ch && ch <= 0x7e) || (ch & 0x80);
  return isprint(ch) || (ch & 0x80);
}

static inline bool is_hex_char(int ch) {
  ch = toupper(ch);
  return ('0' <= ch && ch <= '9') || ('A' <= ch && ch <= 'F');
}

// Initialize a scanner
static void scan_init(scanner_t *sp, const char *src, int len, char *errbuf,
                      int errbufsz) {
  memset(sp, 0, sizeof(*sp));
  sp->src = src;
  sp->endp = src + len;
  assert(*sp->endp == '\0');
  sp->cur = src;
  sp->lineno = 1;
  sp->ebuf.ptr = errbuf;
  sp->ebuf.len = errbufsz;
}

static int scan_multiline_string(scanner_t *sp, token_t *tok) {
  assert(S_MATCH3('"'));
  S_GET(), S_GET(), S_GET(); // skip opening """

  // According to spec: trim first newline after """
  if (S_MATCH('\n')) {
    S_GET();
  }

  *tok = mktoken(sp, MLSTRING);
  // scan until terminating """
  while (1) {
    if (S_MATCH3('"')) {
      if (S_MATCH4('"')) {
        // special case... """abcd """" -> (abcd ")
        // but sequences of 3 or more double quotes are not allowed
        if (S_MATCH6('"')) {
          return ERROR(sp->ebuf, sp->lineno,
                       "detected sequences of 3 or more double quotes");
        } else {
          ; // no problem
        }
      } else {
        break; // found terminating """
      }
    }
    int ch = S_GET();
    if (ch == FIN) {
      return ERROR(sp->ebuf, sp->lineno, "unterminated \"\"\"");
    }
    // If non-escaped char ...
    if (ch != '\\') {
      if (!(is_valid_char(ch) || (ch && strchr(" \t\n", ch)))) {
        return ERROR(sp->ebuf, sp->lineno, "invalid char in string");
      }
      continue;
    }
    // ch is backslash; handle escape char
    ch = S_GET();
    if (ch && strchr("\"\\bfnrt", ch)) {
      // skip \", \\, \b, \f, \n, \r, \t
      continue;
    }
    if (ch == 'u' || ch == 'U') {
      int top = (ch == 'u' ? 4 : 8);
      for (int i = 0; i < top; i++) {
        if (!is_hex_char(S_GET())) {
          return ERROR(sp->ebuf, sp->lineno, "expect %d hex digits after \\%c",
                       top, ch);
        }
      }
      continue;
    }
    if (ch == ' ' || ch == '\t') {
      // Although the spec does not allow for whitespace following a
      // line-ending backslash, some standard tests expect it.
      // Skip whitespace till EOL.
      while (ch != FIN && ch && strchr(" \t", ch)) {
        ch = S_GET();
      }
      if (ch != '\n') {
        // Got a backslash followed by whitespace
        return ERROR(sp->ebuf, sp->lineno, "bad escape char in string");
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
    return ERROR(sp->ebuf, sp->lineno, "bad escape char in string");
  }
  tok->str.len = sp->cur - tok->str.ptr;

  assert(S_MATCH3('"'));
  S_GET(), S_GET(), S_GET();
  return 0;
}

static int scan_string(scanner_t *sp, token_t *tok) {
  assert(S_MATCH('"'));
  if (S_MATCH3('"')) {
    return scan_multiline_string(sp, tok);
  }
  S_GET(); // skip opening "

  // scan until closing "
  *tok = mktoken(sp, STRING);
  while (!S_MATCH('"')) {
    int ch = S_GET();
    if (ch == FIN) {
      return ERROR(sp->ebuf, sp->lineno, "unterminated string");
    }
    // If non-escaped char ...
    if (ch != '\\') {
      if (!(is_valid_char(ch) || ch == ' ' || ch == '\t')) {
        return ERROR(sp->ebuf, sp->lineno, "invalid char in string");
      }
      continue;
    }
    // ch is backslash; handle escape char
    ch = S_GET();
    if (ch && strchr("\"\\bfnrt", ch)) {
      // skip \", \\, \b, \f, \n, \r, \t
      continue;
    }
    if (ch == 'u' || ch == 'U') {
      int top = (ch == 'u' ? 4 : 8);
      for (int i = 0; i < top; i++) {
        if (!is_hex_char(S_GET())) {
          return ERROR(sp->ebuf, sp->lineno, "expect %d hex digits after \\%c",
                       top, ch);
        }
      }
      continue;
    }
    return ERROR(sp->ebuf, sp->lineno, "bad escape char in string");
  }
  tok->str.len = sp->cur - tok->str.ptr;

  assert(S_MATCH('"'));
  S_GET(); // skip the terminating "
  return 0;
}

static int scan_multiline_litstring(scanner_t *sp, token_t *tok) {
  assert(S_MATCH3('\''));
  S_GET(), S_GET(), S_GET(); // skip opening '''

  // According to spec: trim first newline after '''
  if (S_MATCH('\n')) {
    S_GET();
  }

  // scan until terminating '''
  *tok = mktoken(sp, MLLITSTRING);
  while (1) {
    if (S_MATCH3('\'')) {
      if (S_MATCH4('\'')) {
        // special case... '''abcd '''' -> (abcd ')
        // but sequences of 3 or more single quotes are not allowed
        if (S_MATCH6('\'')) {
          return ERROR(sp->ebuf, sp->lineno,
                       "sequences of 3 or more single quotes");
        } else {
          ; // no problem
        }
      } else {
        break; // found terminating '''
      }
    }
    int ch = S_GET();
    if (ch == FIN) {
      return ERROR(sp->ebuf, sp->lineno, "unterminated multiline lit string");
    }
    if (!(is_valid_char(ch) || (ch && strchr(" \t\n", ch)))) {
      return ERROR(sp->ebuf, sp->lineno, "invalid char in string");
    }
  }
  tok->str.len = sp->cur - tok->str.ptr;

  assert(S_MATCH3('\''));
  S_GET(), S_GET(), S_GET();
  return 0;
}

static int scan_litstring(scanner_t *sp, token_t *tok) {
  assert(S_MATCH('\''));
  if (S_MATCH3('\'')) {
    return scan_multiline_litstring(sp, tok);
  }
  S_GET(); // skip opening '

  // scan until closing '
  *tok = mktoken(sp, LITSTRING);
  while (!S_MATCH('\'')) {
    int ch = S_GET();
    if (ch == FIN) {
      return ERROR(sp->ebuf, sp->lineno, "unterminated string");
    }
    if (!(is_valid_char(ch) || ch == '\t')) {
      return ERROR(sp->ebuf, sp->lineno, "invalid char in string");
    }
  }
  tok->str.len = sp->cur - tok->str.ptr;
  assert(S_MATCH('\''));
  S_GET();
  return 0;
}

static bool is_valid_date(int year, int month, int day) {
  if (!(year >= 1)) {
    return false;
  }
  if (!(1 <= month && month <= 12)) {
    return false;
  }
  int is_leap_year = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
  int days_in_month[] = {
      31, 28 + is_leap_year, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  return !(day < 1 || day > days_in_month[month - 1]);
}

static bool is_valid_time(int hour, int minute, int sec, int64_t usec) {
  if (!(0 <= hour && hour <= 23)) {
    return false;
  }
  if (!(0 <= minute && minute <= 59)) {
    return false;
  }
  if (!(0 <= sec && sec <= 59)) {
    return false;
  }
  if (!(usec >= 0)) {
    return false;
  }
  return true;
}

static bool is_valid_timezone(int minute) {
  int neg = (minute < 0);
  minute = neg ? -minute : minute;
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

// Reads a date from p[]. Return #bytes consumed.
static int read_date(const char *p, int *year, int *month, int *day) {
  int n;
  if (3 == sscanf(p, "%4d-%2d-%2d%n", year, month, day, &n) && n == 10) {
    return n;
  }
  return 0;
}

// Reads a time from p[]. Return #bytes consumed.
static int read_time(const char *p, int *hour, int *minute, int *second,
                     int *usec) {
  const char *pp = p;
  int n;
  *usec = 0;
  if (3 == sscanf(p, "%2d:%2d:%2d%n", hour, minute, second, &n) && n == 8) {
    p += n;
    if (*p != '.') {
      return p - pp;
    }
    p++; // skip the period
    int micro_factor = 100000;
    while (isdigit(*p) && micro_factor) {
      *usec += (*p - '0') * micro_factor;
      micro_factor /= 10;
      p++;
    }
    return p - pp;
  }
  return 0;
}

// Reads a timezone from p[]. Return #bytes consumed.
static int read_tzone(const char *p, char *tzsign, int *tzhour, int *tzminute) {
  *tzhour = *tzminute = *tzsign = 0;
  if (*p == 'Z' || *p == 'z') {
    return 1;
  }
  int n;
  int cnt = sscanf(p, "%c%2d:%2d%n", tzsign, tzhour, tzminute, &n);
  return (cnt == 3 && n == 6 && (*tzsign == '+' || *tzsign == '-')) ? n : 0;
}

static int scan_time(scanner_t *sp, token_t *tok) {
  int lineno = sp->lineno;
  char buffer[20];
  int len = sp->endp - sp->cur;
  if (len >= (int)sizeof(buffer)) {
    len = sizeof(buffer) - 1;
  }
  memcpy(buffer, sp->cur, len);
  buffer[len] = 0; // NUL

  char *p = buffer;
  int hour, minute, sec, usec;
  len = read_time(p, &hour, &minute, &sec, &usec);
  if (len == 0) {
    return ERROR(sp->ebuf, lineno, "invalid time");
  }
  if (!is_valid_time(hour, minute, sec, usec)) {
    return ERROR(sp->ebuf, lineno, "invalid time");
  }

  *tok = mktoken(sp, TIME);
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

static int scan_timestamp(scanner_t *sp, token_t *tok) {
  int year, month, day, hour, minute, sec, usec, tz;
  int n;
  // make a copy of sp->cur into buffer to ensure NUL terminated string
  char buffer[80];
  int len = sp->endp - sp->cur;
  if (len >= (int)sizeof(buffer)) {
    len = sizeof(buffer) - 1;
  }
  memcpy(buffer, sp->cur, len);
  buffer[len] = 0; // NUL

  toktyp_t toktyp = FIN;
  int lineno = sp->lineno;
  const char *p = buffer;
  if (isdigit(p[0]) && isdigit(p[1]) && p[2] == ':') {
    year = month = day = hour = minute = sec = usec = tz = -1;
    n = read_time(buffer, &hour, &minute, &sec, &usec);
    if (!n) {
      return ERROR(sp->ebuf, lineno, "invalid time");
    }
    toktyp = TIME;
    p += n;
    goto done;
  }

  year = month = day = hour = minute = sec = usec = tz = -1;
  n = read_date(p, &year, &month, &day);
  if (!n) {
    return ERROR(sp->ebuf, lineno, "invalid date");
  }
  toktyp = DATE;
  p += n;
  if (!((p[0] == 'T' || p[0] == ' ' || p[0] == 't') && isdigit(p[1]) &&
        isdigit(p[2]) && p[3] == ':')) {
    goto done; // date only
  }

  n = read_time(p + 1, &hour, &minute, &sec, &usec);
  if (!n) {
    return ERROR(sp->ebuf, lineno, "invalid timestamp");
  }
  toktyp = DATETIME;
  p += 1 + n;
  char tzsign;
  int tzhour, tzminute;
  n = read_tzone(p, &tzsign, &tzhour, &tzminute);
  if (n == 0) {
    goto done; // datetime only
  }
  toktyp = DATETIMETZ;
  p += n;
  if (!(0 <= tzminute && tzminute <= 60)) {
    return ERROR(sp->ebuf, lineno, "invalid timezone");
  }
  tz = (tzhour * 60 + tzminute) * (tzsign == '-' ? -1 : 1);
  goto done; // datetimetz

done:
  *tok = mktoken(sp, toktyp);
  n = p - buffer;
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

  switch (tok->toktyp) {
  case TIME:
    if (!is_valid_time(hour, minute, sec, usec)) {
      return ERROR(sp->ebuf, lineno, "invalid time");
    }
    break;
  case DATE:
    if (!is_valid_date(year, month, day)) {
      return ERROR(sp->ebuf, lineno, "invalid date");
    }
    break;
  case DATETIME:
  case DATETIMETZ:
    if (!is_valid_date(year, month, day)) {
      return ERROR(sp->ebuf, lineno, "invalid date");
    }
    if (!is_valid_time(hour, minute, sec, usec)) {
      return ERROR(sp->ebuf, lineno, "invalid time");
    }
    if (tok->toktyp == DATETIMETZ && !is_valid_timezone(tz)) {
      return ERROR(sp->ebuf, lineno, "invalid timezone");
    }
    break;
  default:
    assert(0);
    return ERROR(sp->ebuf, lineno, "internal error");
  }

  return 0;
}

static int process_numstr(char *buffer, int base, const char **reason) {
  // squeeze out _
  char *q = strchr(buffer, '_');
  if (q) {
    for (int i = q - buffer; buffer[i]; i++) {
      if (buffer[i] != '_') {
        *q++ = buffer[i];
        continue;
      }
      int left = (i == 0) ? 0 : buffer[i - 1];
      int right = buffer[i + 1];
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
      if (i == 0 || !isdigit(buffer[i - 1]) || !isdigit(buffer[i + 1])) {
        *reason = "decimal point must be surrounded by digits";
        return -1;
      }
    } else if ('A' <= buffer[i] && buffer[i] <= 'Z') {
      buffer[i] = tolower(buffer[i]);
    }
  }

  if (base == 10) {
    // check for leading 0:  '+01' is an error!
    q = buffer;
    q += (*q == '+' || *q == '-') ? 1 : 0;
    if (q[0] == '0' && isdigit(q[1])) {
      *reason = "leading 0 in numbers";
      return -1;
    }

    // 1e+01 is also an error
    if (0 != (q = strchr(buffer, 'e'))) {
      q += (*q == '+' || *q == '-') ? 1 : 0;
      if (q[0] == '0' && isdigit(q[1])) {
        *reason = "leading 0 in numbers";
        return -1;
      }
    }
  }

  return 0;
}

static int scan_float(scanner_t *sp, token_t *tok) {
  char buffer[50]; // need to accomodate "9_007_199_254_740_991.0"
  int len = sp->endp - sp->cur;
  if (len >= (int)sizeof(buffer)) {
    len = sizeof(buffer) - 1;
  }
  memcpy(buffer, sp->cur, len);
  buffer[len] = 0; // NUL

  int lineno = sp->lineno;
  char *p = buffer;
  p += (*p == '+' || *p == '-') ? 1 : 0;
  if (0 == memcmp(p, "nan", 3) || (0 == memcmp(p, "inf", 3))) {
    p += 3;
  } else {
    p += strspn(p, "_0123456789eE.+-");
  }
  len = p - buffer;
  buffer[len] = 0;

  const char *reason;
  if (process_numstr(buffer, 10, &reason)) {
    return ERROR(sp->ebuf, lineno, reason);
  }

  errno = 0;
  char *q;
  double fp64 = strtod(buffer, &q);
  if (errno || *q || q == buffer) {
    return ERROR(sp->ebuf, lineno, "error parsing float");
  }

  *tok = mktoken(sp, FLOAT);
  tok->u.fp64 = fp64;
  tok->str.len = len;
  sp->cur += len;
  return 0;
}

static int scan_number(scanner_t *sp, token_t *tok) {
  const char *reason;
  char buffer[50]; // need to accomodate "9_007_199_254_740_991.0"
  int len = sp->endp - sp->cur;
  if (len >= (int)sizeof(buffer)) {
    len = sizeof(buffer) - 1;
  }
  memcpy(buffer, sp->cur, len);
  buffer[len] = 0; // NUL

  char *p = buffer;
  char *q = buffer + len;
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
      len = p - buffer;
      buffer[len] = 0;

      if (process_numstr(buffer + 2, base, &reason)) {
        return ERROR(sp->ebuf, lineno, reason);
      }

      // use strtoll to obtain the value
      *tok = mktoken(sp, INTEGER);
      errno = 0;
      tok->u.int64 = strtoll(buffer + 2, &q, base);
      if (errno || *q || q == buffer + 2) {
        return ERROR(sp->ebuf, lineno, "error parsing integer");
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
  len = p - buffer;
  buffer[len] = 0;

  if (process_numstr(buffer, 10, &reason)) {
    return ERROR(sp->ebuf, lineno, reason);
  }

  *tok = mktoken(sp, INTEGER);
  errno = 0;
  tok->u.int64 = strtoll(buffer, &q, 10);
  if (errno || *q || q == buffer) {
    if (*q && strchr(".eE", *q)) {
      return scan_float(sp, tok); // try to fit a float
    }
    return ERROR(sp->ebuf, lineno, "error parsing integer");
  }

  tok->str.len = len;
  sp->cur += len;
  return 0;
}

static int scan_bool(scanner_t *sp, token_t *tok) {
  char buffer[10];
  int len = sp->endp - sp->cur;
  if (len >= (int)sizeof(buffer)) {
    len = sizeof(buffer) - 1;
  }
  memcpy(buffer, sp->cur, len);
  buffer[len] = 0; // NUL

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
    return ERROR(sp->ebuf, lineno, "invalid boolean value");
  }
  if (*p && !strchr("# \r\n\t,}]", *p)) {
    return ERROR(sp->ebuf, lineno, "invalid boolean value");
  }

  len = p - buffer;
  *tok = mktoken(sp, BOOL);
  tok->u.b1 = val;
  tok->str.len = len;
  sp->cur += len;
  return 0;
}

// Check if the next token may be TIME
static inline bool test_time(const char *p, const char *endp) {
  return &p[2] < endp && isdigit(p[0]) && isdigit(p[1]) && p[2] == ':';
}

// Check if the next token may be DATE
static inline bool test_date(const char *p, const char *endp) {
  return &p[4] < endp && isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2]) &&
         isdigit(p[3]) && p[4] == '-';
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
  if (&p[3] < endp) {
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
  return ERROR(sp->ebuf, lineno, "invalid value");
}

// Scan a literal
static int scan_literal(scanner_t *sp, token_t *tok) {
  *tok = mktoken(sp, LIT);
  const char *p = sp->cur;
  while (p < sp->endp && (isalnum(*p) || *p == '_' || *p == '-')) {
    p++;
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
  return mark;
}

// Restore the scanner state to a previously saved state
static void scan_restore(scanner_t *sp, scanner_state_t mark) {
  assert(mark.sp == sp);
  sp->cur = mark.cur;
  sp->lineno = mark.lineno;
}

// Return the next token
static int scan_next(scanner_t *sp, bool keymode, token_t *tok) {
again:
  *tok = mktoken(sp, FIN);
  if (sp->errmsg) {
    return -1;
  }

  int ch = S_GET();
  if (ch == FIN) {
    return 0;
  }

  tok->str.len = 1;
  switch (ch) {
  case '\n':
    tok->toktyp = ENDL;
    break;

  case ' ':
  case '\t':
    goto again; // skip whitespace

  case '#':
    // comment: skip until newline
    while (!S_MATCH('\n')) {
      ch = S_GET();
      if (ch == FIN)
        break;
      if ((0 <= ch && ch <= 0x8) || (0x0a <= ch && ch <= 0x1f) ||
          (ch == 0x7f)) {
        return ERROR(sp->ebuf, sp->lineno, "bad control char in comment");
      }
    }
    goto again; // skip comment

  case '.':
    tok->toktyp = DOT;
    break;

  case '=':
    tok->toktyp = EQUAL;
    break;

  case ',':
    tok->toktyp = COMMA;
    break;

  case '[':
    tok->toktyp = LBRACK;
    if (keymode && S_MATCH('[')) {
      S_GET();
      tok->toktyp = LLBRACK;
      tok->str.len = 2;
    }
    break;

  case ']':
    tok->toktyp = RBRACK;
    if (keymode && S_MATCH(']')) {
      S_GET();
      tok->toktyp = RRBRACK;
      tok->str.len = 2;
    }
    break;

  case '{':
    tok->toktyp = LBRACE;
    break;

  case '}':
    tok->toktyp = RBRACE;
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

static int scan_key(scanner_t *sp, token_t *tok) {
  return scan_next(sp, true, tok);
}

static int scan_value(scanner_t *sp, token_t *tok) {
  return scan_next(sp, false, tok);
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
