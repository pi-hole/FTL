/* Copyright (c) 2024-2025, CK Tan.
 * https://github.com/cktan/tomlc17/blob/main/LICENSE
 */
#ifndef TOMLC17_H
#define TOMLC17_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
#define TOML_EXTERN extern "C"
#else
#define TOML_EXTERN extern
#endif

typedef enum toml_type_t toml_type_t;
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

/* This is a Node in a Tree that represents a toml document rooted
 * from toml_result_t::toptab.
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
      int32_t year, month, day;
      int32_t hour, minute, second, usec;
      int32_t tz; // in minutes
    } ts;
    struct {        // array
      int32_t size; // count elem
      toml_datum_t *elem;
    } arr;
    struct {        // table
      int32_t size; // count key
      const char **key;
      int *len;
      toml_datum_t *value;
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
 */
TOML_EXTERN toml_result_t toml_parse_file(FILE *file);

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
TOML_EXTERN toml_datum_t toml_table_find(toml_datum_t datum, const char *key);

/* Options that override tomlc17 defaults globally */
typedef struct toml_option_t toml_option_t;
struct toml_option_t {
  bool check_utf8; // Check all chars are valid utf8; default: false.
  void *(*mem_alloc)(size_t size);              // default: malloc()
  void (*mem_free)(void *ptr);                  // default: free()
  void *(*mem_realloc)(void *ptr, size_t size); // default: realloc()
};

/**
 * Get the default options. IF necessary, use this to initialize
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
