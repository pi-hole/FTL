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
#include "config.h"
// logg()
#include "log.h"

/********************************* type sqlite3_stmt_vec *********************************/
sqlite3_stmt_vec *new_sqlite3_stmt_vec(unsigned int initial_size)
{
	if(config.debug & DEBUG_VECTORS)
		logg("Initializing new sqlite3_stmt* vector with size %u", initial_size);

	sqlite3_stmt_vec *v = calloc(1, sizeof(sqlite3_stmt_vec));
	v->size = initial_size;
	v->capacity = initial_size;
	// Calloc ensures they are all set to zero which is the default state
	v->items = calloc(initial_size, sizeof(sqlite3_stmt *) * initial_size);
	// Set correct subroutine pointers
	v->append = append_sqlite3_stmt_vec;
	v->set = set_sqlite3_stmt_vec;
	v->get = get_sqlite3_stmt_vec;
	v->del = del_sqlite3_stmt_vec;
	v->free = free_sqlite3_stmt_vec;
	return v;
}

static void resize_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int capacity)
{
	if(config.debug & DEBUG_VECTORS)
		logg("Resizing sqlite3_stmt* vector %p from %u to %u", v, v->capacity, capacity);

	// If ptr is NULL, the call to realloc(ptr, size) is
	// equivalent to malloc(size) so we can use it also for
	// initializing a vector for the first time.
	sqlite3_stmt **items = realloc(v->items, sizeof(sqlite3_stmt *) * capacity);
	if (!items)
	{
		logg("ERROR: Memory allocation failed in resize_sqlite3_stmt_vec(%p, %u)",
		       v, capacity);
		return;
	}

	// Update items pointer
	v->items = items;

	// NULL-initialize newly allocated memory slots
	for(unsigned int i = capacity - v->capacity; i < capacity; i++)
		v->items[i] = NULL;

	// Update capacity
	v->capacity = capacity;
}
void append_sqlite3_stmt_vec(sqlite3_stmt_vec *v, sqlite3_stmt *item)
{
	if(config.debug & DEBUG_VECTORS)
		logg("Appending item %p to sqlite3_stmt* vector %p", item, v);

	if(v == NULL)
	{
		logg("ERROR: Passed NULL vector to append_sqlite3_stmt_vec(%p, %p)",
		       v, item);
		return;
	}

	// Check if vector needs to be resized
	if (v->capacity == v->size)
	{
		resize_sqlite3_stmt_vec(v, v->capacity + VEC_ALLOC_STEP);
	}

	// Append item
	unsigned int index = v->size++;
	v->items[index] = item;
}

void set_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int index, sqlite3_stmt *item)
{
	if(config.debug & DEBUG_VECTORS)
		logg("Setting sqlite3_stmt** %p[%u] <-- %p", v, index, item);

	if(v == NULL)
	{
		logg("ERROR: Passed NULL vector to set_sqlite3_stmt_vec(%p, %u, %p)",
		       v, index, item);
		return;
	}

	if (index >= v->size)
	{
		// Allocate more memory when trying to set a statement vector entry with
		// an index larger than the current array size (this makes set an equivalent
		// alternative to append)
		resize_sqlite3_stmt_vec(v, index + VEC_ALLOC_STEP);
	}

	// Set item
	v->items[index] = item;
}

// This function has no effects except to return a value. It can
// be subject to data flow analysis and might be eliminated.
// Hence, we add the "pure" attribute to this function.
sqlite3_stmt * __attribute__((pure)) get_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int index)
{
	if(v == NULL)
	{
		logg("ERROR: Passed NULL vector to get_sqlite3_stmt_vec(%p, %u)",
		       v, index);
		return 0;
	}

	if (index >= v->size)
	{
		logg("ERROR: Boundary violation in get_sqlite3_stmt_vec(%p, %u)",
		       v, index);
		return 0;
	}

	sqlite3_stmt* item = v->items[index];
	if(config.debug & DEBUG_VECTORS)
		logg("Getting sqlite3_stmt** %p[%u] --> %p", v, index, item);

	return item;
}

void del_sqlite3_stmt_vec(sqlite3_stmt_vec *v, unsigned int index)
{
	if(config.debug & DEBUG_VECTORS)
		logg("Deleting item at index %u of sqlite3_stmt* vector %p", index, v);

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

void free_sqlite3_stmt_vec(sqlite3_stmt_vec *v)
{
	if(config.debug & DEBUG_VECTORS)
		logg("Freeing sqlite3_stmt* vector %p", v);

	// Free elements of the vector...
	free(v->items);
	// ...and then then vector itself
	free(v);
	v = NULL;
}
/********************************* type sqlite3_stmt_vec *********************************/