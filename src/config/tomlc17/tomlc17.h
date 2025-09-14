/* Copyright (c) 2024-2025, CK Tan.
 * https://github.com/cktan/tomlc17/blob/main/LICENSE
 */
#ifndef TOMLC17_H
#define TOMLC17_H

/*
 *  USAGE:
 *
 *  1. Call toml_parse(), toml_parse_file(), or toml_parse_file_ex()
 *  2. Check result.ok
 *  3. Use toml_get() or toml_seek() to query and traverse the
 *     result.toptab
 *  4. Call toml_free() to release resources.
 *
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
#define TOML_EXTERN extern "C"
#else
#define TOML_EXTERN extern
#endif

enum toml_type_t {
  TOML_UNKNOWN = 0,
  TOML_STRING,
  TOML_INT64,
  TOML_FP64,
  TOML_BOOLEAN,
  TOML_DATE,
  TOML_TIME,
  TOML_DATETIME,
  TOML_DATETIMETZ,
  TOML_ARRAY,
  TOML_TABLE,
};
typedef enum toml_type_t toml_type_t;

/* This is a Node in a Tree that represents a toml document rooted
 * at toml_result_t::toptab.
 */
typedef struct toml_datum_t toml_datum_t;
struct toml_datum_t {
  toml_type_t type;
  uint32_t flag; // internal
  union {
    const char *s; // same as str.ptr; use if there are no NUL in string.
    struct {
      const char *ptr; // NUL terminated string
      int len;         // length excluding the terminating NUL.
    } str;
    int64_t int64; // integer
    double fp64;   // float
    bool boolean;
    struct { // date, time
      int16_t year, month, day;
      int16_t hour, minute, second;
      int32_t usec;
      int16_t tz; // in minutes
    } ts;
    struct {              // array
      int32_t size;       // count elem
      toml_datum_t *elem; // elem[]
    } arr;
    struct {               // table
      int32_t size;        // count key
      const char **key;    // key[]
      int *len;            // len[]
      toml_datum_t *value; // value[]
    } tab;
  } u;
};

/* Result returned by toml_parse() */
typedef struct toml_result_t toml_result_t;
struct toml_result_t {
  bool ok;             // success flag
  toml_datum_t toptab; // valid if ok
  char errmsg[200];    // valid if not ok
  void *__internal;    // do not use
};

/**
 * Parse a toml document. Returns a toml_result which must be freed
 * using toml_free() eventually.
 *
 * IMPORTANT: src[] must be a NUL terminated string! The len parameter
 * does not include the NUL terminator.
 */
TOML_EXTERN toml_result_t toml_parse(const char *src, int len);

/**
 * Parse a toml file. Returns a toml_result which must be freed
 * using toml_free() eventually.
 *
 * IMPORTANT: you are still responsible to fclose(fp).
 */
TOML_EXTERN toml_result_t toml_parse_file(FILE *fp);

/**
 * Parse a toml file. Returns a toml_result which must be freed
 * using toml_free() eventually.
 */
TOML_EXTERN toml_result_t toml_parse_file_ex(const char *fname);

/**
 * Release the result.
 */
TOML_EXTERN void toml_free(toml_result_t result);

/**
 * Find a key in a toml_table. Return the value of the key if found,
 * or a TOML_UNKNOWN otherwise.
 */
TOML_EXTERN toml_datum_t toml_get(toml_datum_t table, const char *key);

/**
 * Locate a value starting from a toml_table. Return the value of the key if
 * found, or a TOML_UNKNOWN otherwise.
 *
 * Note: the multipart-key is separated by DOT, and must not have any escape
 * chars. The maximum length of the multipart_key must not exceed 127 bytes.
 */
TOML_EXTERN toml_datum_t toml_seek(toml_datum_t table,
                                   const char *multipart_key);

/**
 * OBSOLETE: use toml_get() instead.
 * Find a key in a toml_table. Return the value of the key if found,
 * or a TOML_UNKNOWN otherwise. (
 */
static inline toml_datum_t toml_table_find(toml_datum_t table,
                                           const char *key) {
  return toml_get(table, key);
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
TOML_EXTERN toml_result_t toml_merge(const toml_result_t *r1,
                                     const toml_result_t *r2);

/**
 *  Check if two results are the same. Dictinary and array orders are
 *  sensitive.
 */
TOML_EXTERN bool toml_equiv(const toml_result_t *r1, const toml_result_t *r2);

/* Options that override tomlc17 defaults globally */
typedef struct toml_option_t toml_option_t;
struct toml_option_t {
  bool check_utf8; // Check all chars are valid utf8; default: false.
  void *(*mem_realloc)(void *ptr, size_t size); // default: realloc()
  void (*mem_free)(void *ptr);                  // default: free()
};

/**
 * Get the default options. IF NECESSARY, use this to initialize
 * toml_option_t and override values before calling
 * toml_set_option().
 */
TOML_EXTERN toml_option_t toml_default_option(void);

/**
 * Set toml options globally. Do this ONLY IF you are not satisfied with the
 * defaults.
 */
TOML_EXTERN void toml_set_option(toml_option_t opt);

#endif // TOMLC17_H
