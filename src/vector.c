/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Dynamic vector routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "vector.h"
// struct config
#include "config/config.h"
// logging routines
#include "log.h"

sqlite3_stmt_vec *new_sqlite3_stmt_vec(unsigned int initial_size)
{
	log_debug(DEBUG_VECTORS, "Initializing new sqlite3_stmt* vector with size %u", initial_size);

	sqlite3_stmt_vec *v = calloc(1, sizeof(sqlite3_stmt_vec));
	if(v == NULL)
	{
		log_err("Memory allocation failed in new_sqlite3_stmt_vec(%u)",
		        initial_size);
		return NULL;
	}

	// Initialize vector
	v->capacity = initial_size;
	// Calloc ensures they are all set to zero which is the default state
	v->items = calloc(initial_size, sizeof(sqlite3_stmt *) * initial_size);
	// Set correct subroutine pointers
	v->set = set_sqlite3_stmt_vec;
	v->get = get_sqlite3_stmt_vec;
	return v;
}

static void resize_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int capacity)
{
	log_debug(DEBUG_VECTORS, "Resizing sqlite3_stmt* vector %p from %u to %u", v, v->capacity, capacity);

	// If ptr is NULL, the call to realloc(ptr, size) is equivalent to
	// malloc(size) so we can use it also for initializing a vector for the
	// first time.
	sqlite3_stmt **items = realloc(v->items, sizeof(sqlite3_stmt *) * capacity);
	if(!items)
	{
		log_err("Memory allocation failed in resize_sqlite3_stmt_vec(%p, %u)",
		        v, capacity);
		return;
	}

	// Update items pointer
	v->items = items;

	// NULL-initialize newly allocated memory slots
	for(unsigned int i = v->capacity; i < capacity; i++)
		v->items[i] = NULL;

	// Update capacity
	v->capacity = capacity;
}

void set_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int index, sqlite3_stmt *item)
{
	log_debug(DEBUG_VECTORS, "Setting sqlite3_stmt** %p[%u] <-- %p", v, index, item);

	if(v == NULL)
	{
		log_err("Passed NULL vector to set_sqlite3_stmt_vec(%p, %u, %p)",
		        v, index, item);
		return;
	}

	if(index >= v->capacity)
	{
		// Allocate more memory when trying to set a statement vector entry with
		// an index larger than the current array size (this makes set an
		// equivalent alternative to append)
		resize_sqlite3_stmt_vec(v, index + VEC_ALLOC_STEP);
	}

	// Set item
	v->items[index] = item;
}

// This function has no effects except to return a value. It can be subject to
// data flow analysis and might be eliminated. Hence, we add the "pure"
// attribute to this function.
sqlite3_stmt * __attribute__((pure)) get_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int index)
{
	if(v == NULL)
	{
		log_err("Passed NULL vector to get_sqlite3_stmt_vec(%p, %u)",
		        v, index);
		return 0;
	}

	if(index >= v->capacity)
	{
		// Silently increase size of vector if trying to read out-of-bounds
		resize_sqlite3_stmt_vec(v, index + VEC_ALLOC_STEP);
	}

	sqlite3_stmt* item = v->items[index];
	log_debug(DEBUG_VECTORS, "Getting sqlite3_stmt** %p[%u] --> %p", v, index, item);

	return item;
}

void free_sqlite3_stmt_vec(sqlite3_stmt_vec **v)
{
	log_debug(DEBUG_VECTORS, "Freeing sqlite3_stmt* vector %p", *v);

	// This vector was never allocated, invoking free_sqlite3_stmt_vec() on a
	// NULL pointer should be a harmless no-op.
	if(v == NULL || *v == NULL || (*v)->items == NULL)
		return;

	// Free elements of the vector...
	free((*v)->items);
	// ...and then the vector itself
	free(*v);
	*v = NULL;
}
