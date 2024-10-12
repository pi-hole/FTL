/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Lookup table routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

/**
* @file lookup-table.c
* @brief Provides functionality to find/add/remove elements in a lookup table.
*/

#include "lookup-table.h"
// log_info
#include "log.h"
// counters
#include "shmem.h"


/**
 * @brief Compare two hash values.
 *
 * This function compares two 32-bit hash values and returns:
 * - -1 if the first hash is less than the second hash.
 * - 1 if the first hash is greater than the second hash.
 * - 0 if both hashes are equal.
 *
 * @param a The first hash value to compare.
 * @param b The second hash value to compare.
 * @return An integer indicating the result of the comparison.
 */
static inline int cmp_hash(const uint32_t a, const uint32_t b)
{
	// Compare hash values
	if(a < b)
		// First hash is less than second hash
		return -1;
	if(a > b)
		// First hash is greater than second hash
		return 1;

	// Match
	return 0;
}

/**
 * @file datastructure.c
 * @brief Implements a binary search algorithm for lookup_table structures.
 *
 * @param key Pointer to the lookup_table structure to search for (element to find).
 * @param base Pointer to the base of the array of lookup_table structures to search in.
 * @param nel Number of elements in the array to search in.
 * @param try Pointer to a pointer where the address of the found element will be stored.
 * @return true if the element is found, false otherwise.
 *
 * This function performs a binary search on an array of lookup_table structures.
 * It compares the key with the middle element of the array and decides whether
 * to search in the left or right half of the array. The search continues until
 * the element is found or the array is exhausted. This function is used to find
 * an element in a sorted array of lookup_table structures based on the hash value.
 * Finding the element in the array is done in O(log n) time complexity.
 *
 * This function is different from the standard bsearch function in that it
 * always the address of where the element would be found if it were in the
 * array - even if the element is not found. This is useful for inserting new
 * elements subsequently as we already have the correct position in the array
 * without resorting to do a linear search to find the insertion point later on.
 * We, instead, make the function return false if the element is not found.
 *
 * The standard library's bsearch() function, however, returns a pointer to the
 * found element or NULL (!) if the element is not found which provides no
 * information about the position where the element would need to be inserted.
 */
static bool binsearch(const struct lookup_table *base, const uint32_t hash, size_t nel, const struct lookup_table **try)
{
	// Run while there are elements left to be searched in the base array
	while(nel > 0)
	{
		// Set the try pointer to the (relative) middle element of the
		// current base
		*try = base + (nel/2);

		// Compare the key with the current element
		const int sign = cmp_hash(hash, (*try)->hash);

		if(sign == 0)
		{
			// If the key matches the element, we found at least one
			// occurrence of the key in the array
			return true;
		}
		else if(nel == 1)
		{
			// If there's only one element left and it doesn't
			// match, break the loop as the key is not in the array
			// => return false

			// If the key is less than the middle element, the key
			// would be inserted before the middle element
			if(sign < 0)
				break;

			// If the key is greater than the middle element, the key
			// would be inserted after the middle element
			(*try)++;
			break;
		}
		else if(sign < 0)
		{
			// If the key is less than the middle element, search in
			// the (relative) left half and try again
			nel /= 2;
		}
		else
		{
			// If the key is greater than the middle element, search
			// in the (relative) right half and try again
			base = *try;
			nel -= nel/2;
		}
	}

	// If the key was not found, return false
	return false;
}

/**
 * @brief Retrieves the appropriate lookup table and its size based on the specified memory type.
 *
 * This function assigns the correct lookup table and its corresponding size to the provided pointers
 * based on the given memory type. If the memory type is invalid, an error is logged and the function
 * returns false.
 *
 * @param type The memory type for which the lookup table is requested. It can be one of the following:
 *             - CLIENTS_LOOKUP
 *             - DOMAINS_LOOKUP
 *             - DNS_CACHE_LOOKUP
 * @param table A pointer to a pointer that will be assigned the address of the appropriate lookup table.
 * @param size A pointer to a pointer that will be assigned the address of the size of the appropriate lookup table.
 * @return true if the lookup table and size were successfully retrieved, false if the memory type is invalid.
 */
static bool get_table(const enum memory_type type, struct lookup_table **table, unsigned int **size)
{
	// Get the correct lookup_table array based on the type
	if(type == CLIENTS_LOOKUP)
	{
		*table = clients_lookup;
		*size = &counters->clients_lookup_size;
	}
	else if(type == DOMAINS_LOOKUP)
	{
		*table = domains_lookup;
		*size = &counters->domains_lookup_size;
	}
	else if(type == DNS_CACHE_LOOKUP)
	{
		*table = dns_cache_lookup;
		*size = &counters->dns_cache_lookup_size;
	}
	else
	{
		log_err("Invalid memory type in get_table(%u)", type);
		return false;
	}

	return true;
}

/**
 * @brief Inserts an element into the lookup table.
 *
 * This function inserts an element with the specified ID and hash into the
 * lookup table corresponding to the given memory type. If the element already
 * exists in the table, it logs a message and returns without making any changes.
 *
 * @param type The memory type that determines which lookup table to use.
 * @param id The ID of the element to be inserted.
 * @param hash The hash value of the element to be inserted.
 * @return bool true if the element was successfully inserted, false otherwise.
 */
bool lookup_insert(const enum memory_type type, const unsigned int id, const uint32_t hash)
{

	// Get the correct lookup_table array based on the type
	struct lookup_table *table = NULL;
	unsigned int *size = NULL;
	if(!get_table(type, &table, &size))
		return false;

	// Find the correct position in the lookup_table array
	// We do not check the return value as we are inserting a new element
	// and don't care if elements with the same hash value exist already
	const struct lookup_table *try = NULL;
	binsearch(table, hash, *size, &try);

	// Calculate the position where the element would be inserted
	const size_t pos = try - table;

	// Move all elements from the insertion point to the end of the array
	// one position to the right to make space for the new element
	memmove((void*)(try + 1), try, (*size - pos) * sizeof(struct lookup_table));

	// Prepare the new lookup_table element
	struct lookup_table key = { .id = id, .hash = hash };

	// Insert the new element at the correct position
	memcpy((void*)try, &key, sizeof(struct lookup_table));

	log_debug(DEBUG_GC, "Inserted element (type %u, ID %u, hash %u) at position %zu",
	          type, id, hash, pos);

	// Increase the number of elements in the array
	(*size)++;

	return true;
}

/**
 * @brief Inserts an element into the lookup table.
 *
 * This function removes an element with the specified ID and hash from the
 * lookup table corresponding to the given memory type. If the element does not
 * exist in the table, it logs a message and returns without making any changes.
 * If the element is found, it is removed from the table and the remaining
 * elements are shifted to the left to fill the gap and maintain the order.
 *
 * @param type The memory type that determines which lookup table to use.
 * @param id The ID of the element to be removed.
 * @param hash The hash value of the element to be removed.
 * @return bool true if the element was successfully removed, false otherwise.
 */
bool lookup_remove(const enum memory_type type, const unsigned int id, const uint32_t hash)
{
	// Get the correct lookup_table array based on the type
	struct lookup_table *table = NULL;
	unsigned int *size = NULL;
	if(!get_table(type, &table, &size))
		return false;

	// Find the correct position in the lookup_table array
	const struct lookup_table *try = NULL;
	if(!binsearch(table, hash, *size, &try))
	{
		// The element is not in the array
		log_warn("Element to be removed (type %u, hash %u) is not in the lookup table",
		         type, hash);
		return true;
	}

	// Calculate the position where the element is located
	size_t pos = try - table;

	// If binsearch finds the element, it returns the address *one*
	// of the elements matching the hash value. We need to find the
	// first element with the same hash value and then iterate over
	// all elements with the same hash value to find the correct one
	// where the ID matches as well.
	while(pos > 0 && table[pos - 1].hash == hash)
		pos--;

	// Iterate over all elements with the same hash value
	while(pos < *size && table[pos].hash == hash)
	{
		// If the ID matches, we found the correct element
		if(table[pos].id == id)
		{
			// Move all elements from the position to the end of the array
			// one position to the left to remove the element
			memmove((void*)(&table[pos]), &table[pos + 1], (*size - pos - 1) * sizeof(struct lookup_table));

			// Decrease the number of elements in the array
			(*size)--;

			log_debug(DEBUG_GC, "Removed element (type %u, ID %u, hash %u) at position %zu",
			          type, id, hash, pos);

			return true;
		}

		// Move to the next element with the same hash value
		pos++;
	}

	// The element is not in the array
	log_warn("Element to be removed (type %u, ID, %u, hash %u) not in lookup table",
	         type, id, hash);

	return true;
}

/**
 * @brief Finds an element in the lookup table based on the given type and hash.
 *
 * This function searches for an element in the lookup table that matches the
 * specified type and hash. If an element with the same hash is found, it iterates
 * over all elements with the same hash to find the correct one where the ID matches
 * as well.
 *
 * @param type The type of memory to search in.
 * @param hash The hash value of the element to find.
 * @param lookup_data A pointer to a structure containing the data to match.
 * @param matchingID A pointer to an unsigned integer where the matching ID will be stored.
 * @param cmp_func A comparison function to check if the element matches the data.
 * @return true if the element is found, false otherwise.
 */
bool lookup_find_id(const enum memory_type type, const uint32_t hash, const struct lookup_data *lookup_data,
                    unsigned int *matchingID,
                    bool (*cmp_func)(const struct lookup_table *entry, const struct lookup_data *lookup_data))
{
	// Get the correct lookup_table array based on the type
	struct lookup_table *table = NULL;
	unsigned int *size = NULL;
	if(!get_table(type, &table, &size))
		return false;

	// Find the correct position in the lookup_table array
	const struct lookup_table *try = NULL;
	if(!binsearch(table, hash, *size, &try))
	{
		// The element is not in the array
		log_warn("Element to be found (type %u, hash %u) is not in the lookup table",
		         type, hash);
		return false;
	}

	// Calculate the position where the element is located
	size_t pos = try - table;

	// If binsearch finds the element, it returns the address *one*
	// of the elements matching the hash value. We need to find the
	// first element with the same hash value and then iterate over
	// all elements with the same hash value to find the correct one
	// where the ID matches as well.
	while(pos > 0 && table[pos - 1].hash == hash)
		pos--;

	// Iterate over all elements with the same hash value
	while(pos < *size && table[pos].hash == hash)
	{
		// If the ID matches, we found the correct element
		if(cmp_func(&table[pos], lookup_data))
		{
			log_debug(DEBUG_GC, "Found element (type %u, ID %u, hash %u) at position %zu",
			          type, table[pos].id, hash, pos);

			// Store the matching ID
			*matchingID = table[pos].id;

			// Return success
			return true;
		}

		// Move to the next element with the same hash value
		pos++;
	}

	// The element is not in the array
	log_warn("Element to be found (type %u, hash %u) not in lookup table",
	         type, hash);

	return false;
}

/**
 * @brief Prints the lookup table based on the specified memory type.
 *
 * This function retrieves the appropriate lookup table and its size based on
 * the provided memory type. It then iterates through the table and logs each
 * element's ID and hash value.
 *
 * @param type The memory type used to determine which lookup table to print.
 */
void print_lookup_table(const enum memory_type type)
{
	// Get the correct lookup_table array based on the type
	unsigned int *size = NULL;
	struct lookup_table *table = NULL;
	if(!get_table(type, &table, &size))
		return;

	// Print the lookup_table array's elements
	for(unsigned int i = 0; i < *size; i++)
		log_info("Table %u[%u]: ID = %u, hash = %u, ok = %s",
		         type, i, table[i].id, table[i].hash,
		         i > 0 ? table[i].hash >= table[i-1].hash ?
		            "true" : "false" : "---");
}
