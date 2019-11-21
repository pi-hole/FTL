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

typedef struct vector {
	unsigned int size;
	unsigned int capacity;
	bool  *alloc;
	void **items;
} vector;

vector *vNew(void);
unsigned int vSize(vector *v);
void vAppend(vector *v, void *item, bool allocated);
void vSet(vector *v, unsigned int index, void *item, bool allocated);
void *vGet(vector *v, unsigned int index) __attribute__((pure));
void vRemove(vector *v, unsigned int index);
void vFree(vector *v);

#endif //VECTOR_H
