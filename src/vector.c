/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Dynamic vector routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <stdio.h>
#include <stdlib.h>
#include "vector.h"

// memmove()
#include <string.h>

vector *vNew(void)
{
	vector *v = calloc(1, sizeof(vector));
	v->size = 0u;
	v->capacity = 0u;
	v->alloc = NULL;
	v->items = NULL;
	return v;
}

unsigned int vSize(vector *v)
{
	if(v == NULL)
	{
		printf("ERROR: Passed NULL vector to vSize(%p)",
		       v);
		return 0;
	}

	return v->size;
}

static void vResize(vector *v, unsigned int capacity)
{
	//#ifdef DEBUG_ON
	printf("vResize: Resizing %p from %u to %u\n", v, v->capacity, capacity);
	//#endif

	// If ptr is NULL, the call to realloc(ptr, size) is
	// equivalent to malloc(size) so we can use it also for
	// initializing a vector for the first time.
	void **items = realloc(v->items, sizeof(void *) * capacity);
	bool  *alloc = realloc(v->alloc, sizeof(bool) * capacity);
	if (items && alloc)
	{
		v->items = items;
		v->alloc = alloc;
		v->capacity = capacity;
	}
	else
	{
		printf("ERROR: Memory allocation failed in vResize(%p, %u)",
		       v, capacity);
	}
}

void vAppend(vector *v, void *item, bool allocated)
{
	if(v == NULL)
	{
		printf("ERROR: Passed NULL vector to vAppend(%p, %p)",
		       v, item);
		return;
	}

	// Check if vector needs to be resized
	if (v->capacity == v->size)
	{
		vResize(v, v->capacity + VEC_ALLOC_STEP);
	}

	// Append item
	unsigned int index = v->size++;
	v->items[index] = item;
	v->alloc[index] = allocated;
}

void vSet(vector *v, unsigned int index, void *item, bool allocated)
{
	if(v == NULL)
	{
		printf("ERROR: Passed NULL vector to vSet(%p, %u, %p)",
		       v, index, item);
		return;
	}

	if (index >= v->size)
	{
		printf("ERROR: Boundary violation vSet(%p, %u %p)",
		       v, index, item);
		return;
	}

	// Set item
	v->items[index] = item;
	v->alloc[index] = allocated;
}

// This function has no effects except to return a value. It can
// be subject to data flow analysis and might be eliminated.
// Hence, we add the "pure" attribute to this function.
void __attribute__((pure)) *vGet(vector *v, unsigned int index)
{
	if (v != NULL && index < v->size)
	{
		return v->items[index];
	}
	return NULL;
}

void vRemove(vector *v, unsigned int index)
{
	if (index >= v->size)
		return;

	// If this vector entry was allocated, we need to
	// free it to avoid leaking memory. We do not set
	// the pointer explicitly to NULL as it will be
	// overwritten by memmove in the next step.
	if(v->alloc[index])
	{
		printf("Freeing \"%s\"\n", (char*)v->items[index]);
		free(v->items[index]);
	}

	size_t move = v->size - index - 1u;
	memmove(&v->items[index], &v->items[index + 1u], move*sizeof(v->items[index]));
	memmove(&v->alloc[index], &v->alloc[index + 1u], move*sizeof(v->alloc[index]));

	v->size--;

	if (v->size > 0u && v->size == v->capacity / 4)
	{
		vResize(v, v->capacity / 2);
	}
}

void vFree(vector *v)
{
	for(unsigned int index = 0; index < vSize(v); index++)
	{
		// We need to free allocated children
		// individually before freeing the vector
		if(v->alloc[index])
		{
			free(&v->items[index]);
		}
	}
	// Free elements of the vector...
	free(v->items);
	free(v->alloc);
	// ...and then then vector itself
	free(v);
	v = NULL;
}
