/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Dynamic vector prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef VECTOR_H
#define VECTOR_H

#include <stdio.h>
#include <stdlib.h>
// memmove()
#include <string.h>
// type bool
#include <stdbool.h>
// type sqlite3_stmt
#include "database/sqlite3.h"

#define VEC_ALLOC_STEP 10u

typedef struct sqlite3_stmt_vec {
	unsigned int size;
	unsigned int capacity;
	sqlite3_stmt **items;
	sqlite3_stmt *(*get)(struct sqlite3_stmt_vec *, unsigned int);
	void (*append)(struct sqlite3_stmt_vec *, sqlite3_stmt*);
	void (*set)(struct sqlite3_stmt_vec *, unsigned int, sqlite3_stmt*);
	void (*del)(struct sqlite3_stmt_vec *, unsigned int);
	void (*free)(struct sqlite3_stmt_vec *);
} sqlite3_stmt_vec;

sqlite3_stmt_vec *new_sqlite3_stmt_vec(unsigned int initial_size);
void append_sqlite3_stmt_vec(sqlite3_stmt_vec *v, sqlite3_stmt* item);
void set_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int index, sqlite3_stmt* item);
sqlite3_stmt* get_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int index) __attribute__((pure));
void del_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int index);
void free_sqlite3_stmt_vec(sqlite3_stmt_vec *v);

#endif //VECTOR_H