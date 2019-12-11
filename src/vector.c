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


/********************************* type ucharvec *********************************/
ucharvec *new_ucharvec(unsigned int initial_size)
{
	ucharvec *v = calloc(1, sizeof(ucharvec));
	v->size = initial_size;
	v->capacity = initial_size;
	// Calloc ensures they are all set to zero which is the default state
	v->items = calloc(initial_size, sizeof(unsigned char) * initial_size);
	// Set correct subroutine pointers
	v->append = append_ucharvec;
	v->set = set_ucharvec;
	v->get = get_ucharvec;
	v->del = del_ucharvec;
	v->free = free_ucharvec;
	return v;
}

static void resize_ucharvec(ucharvec *v, unsigned int capacity)
{
	printf("resize_ucharvec: Resizing %p from %u to %u\n", v, v->capacity, capacity);

	// If ptr is NULL, the call to realloc(ptr, size) is
	// equivalent to malloc(size) so we can use it also for
	// initializing a vector for the first time.
	unsigned char *items = realloc(v->items, sizeof(unsigned char) * capacity);
	if (items)
	{
		v->items = items;
		v->capacity = capacity;
	}
	else
	{
		printf("ERROR: Memory allocation failed in resize_ucharvec(%p, %u)",
		       v, capacity);
	}
}
void append_ucharvec(ucharvec *v, unsigned char item)
{
	if(v == NULL)
	{
		printf("ERROR: Passed NULL vector to append_ucharvec(%p, %u)",
		       v, item);
		return;
	}

	// Check if vector needs to be resized
	if (v->capacity == v->size)
	{
		resize_ucharvec(v, v->capacity + VEC_ALLOC_STEP);
	}

	// Append item
	unsigned int index = v->size++;
	v->items[index] = item;
}

void set_ucharvec(ucharvec *v, unsigned int index, unsigned char item)
{
	if(v == NULL)
	{
		printf("ERROR: Passed NULL vector to set_ucharvec(%p, %u, %u)",
		       v, index, item);
		return;
	}

	if (index >= v->size)
	{
		printf("ERROR: Boundary violation in set_ucharvec(%p, %u, %u)",
		       v, index, item);
		return;
	}

	// Set item
	v->items[index] = item;
}

// This function has no effects except to return a value. It can
// be subject to data flow analysis and might be eliminated.
// Hence, we add the "pure" attribute to this function.
unsigned char __attribute__((pure)) get_ucharvec(ucharvec *v, unsigned int index)
{
	if(v == NULL)
	{
		printf("ERROR: Passed NULL vector to get_ucharvec(%p, %u)",
		       v, index);
		return 0;
	}

	if (index >= v->size)
	{
		printf("ERROR: Boundary violation in get_ucharvec(%p, %u)",
		       v, index);
		return 0;
	}

	return v->items[index];
}

void del_ucharvec(ucharvec *v, unsigned int index)
{
	if (index >= v->size)
		return;

	// Use memmove to ensure there are no gaps in the vector
	size_t move = v->size - index - 1u;
	memmove(&v->items[index], &v->items[index + 1u], move * sizeof(v->items[index]));

	v->size--;

	// // Shorten vector to save some space
	// if (v->size > 0u && v->size == v->capacity / 4)
	// {
	// 	vResize(v, v->capacity / 2);
	// }
}

void free_ucharvec(ucharvec *v)
{
	// Free elements of the vector...
	free(v->items);
	// ...and then then vector itself
	free(v);
	v = NULL;
}
/********************************* type ucharvec *********************************/
