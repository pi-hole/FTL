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

// type bool
#include <stdbool.h>

#define VEC_ALLOC_STEP 2u

typedef struct ucharvec {
	unsigned int size;
	unsigned int capacity;
	unsigned char *items;
	unsigned char (*get)(struct ucharvec *, unsigned int);
	void (*append)(struct ucharvec *, unsigned char);
	void (*set)(struct ucharvec *, unsigned int, unsigned char);
	void (*del)(struct ucharvec *, unsigned int);
	void (*free)(struct ucharvec *);
} ucharvec;

ucharvec *new_ucharvec(unsigned int initial_size);
void append_ucharvec(ucharvec *v, unsigned char item);
void set_ucharvec(ucharvec *v, unsigned int index, unsigned char item);
unsigned char get_ucharvec(ucharvec *v, unsigned int index) __attribute__((pure));
void del_ucharvec(ucharvec *v, unsigned int index);
void free_ucharvec(ucharvec *v);

#endif //VECTOR_H
