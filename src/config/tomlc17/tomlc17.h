/* Copyright (c) 2024-2026, CK Tan.
 * https://github.com/cktan/tomlc17/blob/main/LICENSE
 */

/**
 * @file tomlc17.h
 * @brief A TOML parser for C17.
 *
 * This library provides a simple and efficient way to parse TOML documents
 * in C. It supports standard TOML features and provides an easy-to-use API
 * for traversing the parsed data.
 */

#ifndef TOMLC17_H
#define TOMLC17_H

// A crude way to determine version. Manually changed.
#define TOMLC17_RELEASE_AFTER "260618"

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

/**
 * @brief Enumeration of TOML data types.
 */
enum toml_type_t {
  TOML_UNKNOWN = 0, /**< Unknown or invalid type */
  TOML_STRING,      /**< String type */
  TOML_INT64,       /**< 64-bit integer type */
  TOML_FP64,        /**< 64-bit floating point type */
  TOML_BOOLEAN,     /**< Boolean type */
  TOML_DATE,        /**< Local date type */
  TOML_TIME,        /**< Local time type */
  TOML_DATETIME,    /**< Local datetime type */
  TOML_DATETIMETZ,  /**< Offset datetime type */
  TOML_ARRAY,       /**< Array type */
  TOML_TABLE,       /**< Table type */
};
typedef enum toml_type_t toml_type_t;

/**
 * @brief Represents a single piece of TOML data.
 *
 * This structure is a node in a tree that represents a TOML document.
 * The `u` union contains the actual value based on the `type` field.
 */
typedef struct toml_datum_t toml_datum_t;
struct toml_datum_t {
  toml_type_t type;   /**< Type of the datum */
  uint32_t flag;      /**< Internal flag, do not use */
  int lineno;         /**< 1-based source line number, 0 if synthesized */
  int colno;          /**< 1-based source column number, 0 if synthesized */
  const char *source; /**< Source name (e.g. filename), NULL if not provided.
                           Owned by the result; valid until toml_free(). */
  union {
    const char *s; /**< Shorthand for str.ptr */
    struct {
      const char *ptr; /**< NUL terminated string pointer */
      int len; /**< Length of the string excluding the terminating NUL */
    } str;
    int64_t int64; /**< 64-bit integer value */
    double fp64;   /**< 64-bit floating point value */
    bool boolean;  /**< Boolean value */
    struct {       /**< Date and time components */
      int16_t year, month, day;
      int16_t hour, minute, second;
      int32_t usec;
      int16_t tz; /**< Timezone offset in minutes */
    } ts;
    struct {              /**< Array data */
      int32_t size;       /**< Number of elements in the array */
      toml_datum_t *elem; /**< Array of elements */
    } arr;
    struct {               /**< Table data */
      int32_t size;        /**< Number of keys in the table */
      const char **key;    /**< Array of keys */
      int *len;            /**< Array of key lengths */
      toml_datum_t *value; /**< Array of values corresponding to keys */
    } tab;
  } u;
};

/**
 * @brief Bit values for toml_datum_t::flag.
 *
 * These record how a datum appeared in the source document. They are set
 * by the parser and are informational for API users.
 */
#define TOML_FLAG_INLINED                                                      \
  1 /**< appeared in inline form, e.g. {x = 1} or [1, 2] */
#define TOML_FLAG_STDEXPR 2  /**< table created by a [table] header */
#define TOML_FLAG_EXPLICIT 4 /**< table explicitly defined */

/**
 * @brief Result of a TOML parsing operation.
 */
typedef struct toml_result_t toml_result_t;
struct toml_result_t {
  bool ok;             /**< True if parsing was successful */
  toml_datum_t toptab; /**< The top-level table (valid if ok is true) */
  char errmsg[200];    /**< Error message (valid if ok is false) */
  void *__internal;    /**< Internal state, do not use */
};

/**
 * @brief Parse a TOML document from a string.
 *
 * @param src A string containing the TOML document.
 * @param len The length of the string. src need not be NUL-terminated;
 * only the first len bytes are read.
 * @return A toml_result_t structure. Must be freed with toml_free().
 */
TOML_EXTERN toml_result_t toml_parse(const char *src, int len);

/**
 * @brief Parse a TOML document, tagging every datum with a source name.
 *
 * @param src A string containing the TOML document.
 * @param len The length of the string. src need not be NUL-terminated;
 * only the first len bytes are read.
 * @param name A source name (e.g. filename) copied into the result, or NULL.
 *             Every parsed datum's `source` is set to this name (or NULL).
 * @return A toml_result_t structure. Must be freed with toml_free().
 */
TOML_EXTERN toml_result_t toml_parse_named(const char *src, int len,
                                           const char *name);

/**
 * @brief Parse a TOML document from a file pointer.
 *
 * @param fp A pointer to the open file. The caller is responsible for closing
 * it.
 * @return A toml_result_t structure. Must be freed with toml_free().
 *
 * IMPORTANT: you are still responsible to fclose(fp).
 */
TOML_EXTERN toml_result_t toml_parse_file(FILE *fp);

/**
 * @brief Parse a TOML document from a file pointer, tagging datums with a name.
 *
 * @param fp A pointer to the open file. The caller is responsible for closing
 * it.
 * @param name A source name copied into the result, or NULL.
 * @return A toml_result_t structure. Must be freed with toml_free().
 *
 * IMPORTANT: you are still responsible to fclose(fp).
 */
TOML_EXTERN toml_result_t toml_parse_file_named(FILE *fp, const char *name);

/**
 * @brief Parse a TOML document from a file path.
 *
 * @param fname The path to the TOML file.
 * @return A toml_result_t structure. Must be freed with toml_free().
 */
TOML_EXTERN toml_result_t toml_parse_file_ex(const char *fname);

/**
 * @brief Release resources allocated for a TOML result.
 *
 * @param result The TOML result to free.
 */
TOML_EXTERN void toml_free(toml_result_t result);

/**
 * @brief Find a value for a specific key in a TOML table.
 *
 * @param table The TOML table to search in.
 * @param key The key to look for.
 * @return The value associated with the key, or a datum with type TOML_UNKNOWN
 * if not found.
 */
TOML_EXTERN toml_datum_t toml_get(toml_datum_t table, const char *key);

/**
 * @brief Locate a value using a multipart-key (e.g., "a.b.c").
 *
 * @param table The TOML table to start the search from.
 * @param multipart_key A dot-separated key string. No escape characters
 * allowed. Maximum length is 255 bytes.
 * @return The value found, or a datum with type TOML_UNKNOWN if not found.
 */
TOML_EXTERN toml_datum_t toml_seek(toml_datum_t table,
                                   const char *multipart_key);

/**
 * @brief OBSOLETE: use toml_get() instead.
 * Find a key in a toml_table. Return the value of the key if found,
 * or a TOML_UNKNOWN otherwise.
 */
static inline toml_datum_t toml_table_find(toml_datum_t table,
                                           const char *key) {
  return toml_get(table, key);
}

/**
 * @brief Merge two TOML results.
 *
 * All results (r1, r2, and the returned result) must be freed independently.
 *
 * @param r1 The base TOML result.
 * @param r2 The TOML result containing overrides.
 * @return A new toml_result_t representing the merged document.
 *
 *  LOGIC:
 *   ret = copy of r1
 *   for each item x in r2:
 *     if x is not in ret:
 *         set x in ret
 *     elif x in ret is NOT of the same type:
 *         override
 *     elif x in ret is an array of tables:
 *         append r2.x to ret.x
 *     elif x in ret is a table:
 *         merge r2.x to ret.x
 *     else:
 *         override
 */
TOML_EXTERN toml_result_t toml_merge(const toml_result_t *r1,
                                     const toml_result_t *r2);

/**
 * @brief Compare two TOML results for equality.
 *
 * Tables compare as unordered maps (keys matched by name); array element
 * order is significant.
 *
 * @param r1 The first TOML result.
 * @param r2 The second TOML result.
 * @return True if they are equivalent, false otherwise.
 */
TOML_EXTERN bool toml_equiv(const toml_result_t *r1, const toml_result_t *r2);

/**
 * @brief Global options for the TOML parser.
 */
typedef struct toml_option_t toml_option_t;
struct toml_option_t {
  bool check_utf8; /**< If true, check if all characters are valid UTF-8.
                      Default: false. */
  void *(*mem_realloc)(void *ptr,
                       size_t size); /**< Custom realloc function (called with
                                        size > 0). Default: realloc(). */
  void (*mem_free)(void *ptr); /**< Custom free function. Default: free(). */
};

/**
 * @brief Get the default parser options.
 *
 * Use this to obtain and initialize a toml_option_t structure before
 * customizing it.
 *
 * @return A toml_option_t with default values.
 */
TOML_EXTERN toml_option_t toml_default_option(void);

/**
 * @brief Set the global parser options.
 *
 * Call this only if you need to override the default behavior.
 *
 * @param opt The options to set.
 */
TOML_EXTERN void toml_set_option(toml_option_t opt);

#endif // TOMLC17_H
