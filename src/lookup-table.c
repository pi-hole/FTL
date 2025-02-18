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
// PRIu32
#include <inttypes.h>

/**
 * @brief Compare two hash values.
 *
 * This function compares two 32-bit hash values and returns:
 * - -1 if the first hash is less than the second hash.
 * -  1 if the first hash is greater than the second hash.
 * -  0 if both hashes are equal.
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
 * @param size Number of elements in the array to search in.
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
 * always returns the address of where the element would be found if it were in the
 * array - even if the element is not found. This is useful for inserting new
 * elements subsequently as we already have the correct position in the array
 * without resorting to do a linear search to find the insertion point later on.
 * We, instead, make the function return false if the element is not found.
 *
 * The standard library's bsearch() function, however, returns a pointer to the
 * found element or NULL (!) if the element is not found which provides no
 * information about the position where the element would need to be inserted.
 */
static bool binsearch(struct lookup_table *base, const uint32_t hash,
                      size_t size, struct lookup_table **try)
{
	// Initialize the base pointer to the start of the array
	*try = base;

	// Run while there are elements left to be searched in the base array
	while(size > 0)
	{
		// Use unsigned arithmetic to avoid overflow when calculating
		// the middle element of the array
		const size_t mid = size / 2;
		// Update the base pointer to the middle element of the array
		*try = base + mid;

		// Compare the key with the current element
		const int sign = cmp_hash(hash, (*try)->hash);

		if(sign == 0)
		{
			// If the key matches the element, we found at least one
			// occurrence of the key in the array
			return true;
		}
		else if(size == 1)
		{
			// If there's only one element left and it doesn't
			// match, break the loop as the key is not in the array
			// => return false

			// If the key is greater than the middle element, the
			// key would be inserted after the middle element
			if(sign > 0)
				(*try)++;

			// Break the loop, we have not found the key but
			// know that it would need to be inserted at *try
			break;
		}
		else if(sign < 0)
		{
			// If the key is less than the middle element, search in
			// the (relative) left half (XXXX-----) and try again

			// base stays the same
			size = mid; // size is now the left half
		}
		else
		{
			// If the key is greater than the middle element, search
			// in the (relative) right half (-----XXXX) and try again

			base = *try; // base is now the beginning of the right half
			size -= mid; // size is now the right half
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
 * @param name A pointer to a pointer that will be assigned the name of the appropriate lookup table.
 * @return true if the lookup table and size were successfully retrieved, false if the memory type is invalid.
 */
static bool get_table(const enum memory_type type, struct lookup_table **table, unsigned int **size, const char **name)
{
	// Get the correct lookup_table array based on the type
	if(type == CLIENTS_LOOKUP)
	{
		*name = "clients";
		*table = clients_lookup;
		*size = &counters->clients_lookup_size;
	}
	else if(type == DOMAINS_LOOKUP)
	{
		*name = "domains";
		*table = domains_lookup;
		*size = &counters->domains_lookup_size;
	}
	else if(type == DNS_CACHE_LOOKUP)
	{
		*name = "DNS cache";
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
	const char *name = NULL;
	if(!get_table(type, &table, &size, &name))
		return false;

	// Find the correct position in the lookup_table array
	// We do not check the return value as we are inserting a new element
	// and don't care if elements with the same hash value exist already
	struct lookup_table *try = table;
	binsearch(table, hash, *size, &try);

	// Calculate the position where the element would be inserted
	const size_t pos = try - table;

	// Move all elements from the insertion point to the end of the array
	// one position to the right to make space for the new element
	// Don't move anything if the element is added at the end of the array
	if(pos < *size)
		memmove(try + 1, try, (*size - pos) * sizeof(struct lookup_table));

	// Prepare the new lookup_table element and insert it at the correct
	// position
	table[pos] = (struct lookup_table){ .id = id, .hash = hash };

	// Increase the number of elements in the array
	(*size)++;

	return true;
}

/**
 * @brief Removes an element from the lookup table.
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
	const char *name = NULL;
	if(!get_table(type, &table, &size, &name))
		return false;

	// Find the correct position in the lookup_table array
	struct lookup_table *try = NULL;
	if(!binsearch(table, hash, *size, &try))
	{
		// The element is not in the array
		log_warn("Element to be removed (hash %u) is not in the %s lookup table",
		         hash, name);
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
			// Don't move anything if the element is removed from the end of the array
			if(pos < *size - 1)
				memmove(table + pos, table + pos + 1,
				        (*size - pos - 1) * sizeof(struct lookup_table));

			// Decrease the number of elements in the array
			(*size)--;

			// Zero out the memory of the removed element
			memset(table + *size, 0, sizeof(struct lookup_table));

			return true;
		}

		// Move to the next element with the same hash value
		pos++;
	}

	// The element is not in the array
	log_warn("Element to be removed (ID %u, hash %u) not in %s lookup table",
	         id, hash, name);

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
	const char *name = NULL;
	if(!get_table(type, &table, &size, &name))
		return false;

	// Find the correct position in the lookup_table array
	struct lookup_table *try = NULL;
	if(!binsearch(table, hash, *size, &try))
		return false;

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
			// Store the matching ID
			*matchingID = table[pos].id;

			// Return success
			return true;
		}

		// Move to the next element with the same hash value
		pos++;
	}

	return false;
}

/**
 * @brief Searches for hash collisions in the lookup table of the specified memory type.
 *
 * This function my be used to assess the quality of the hash function.
 *
 * @param type The type of memory for which to search for hash collisions. This can be one of:
 *             - CLIENTS_LOOKUP: Searches for collisions in the clients lookup table.
 *             - DOMAINS_LOOKUP: Searches for collisions in the domains lookup table.
 *             - DNS_CACHE_LOOKUP: Searches for collisions in the DNS cache lookup table.
 *
 * The function retrieves the appropriate lookup table based on the provided type and iterates
 * through it to find and log any hash collisions. The logged information varies depending on the
 * type of lookup table being searched.
 */
static void lookup_find_hash_collisions_table(const enum memory_type type)
{
	// Get the correct lookup_table array based on the type
	struct lookup_table *table = NULL;
	unsigned int *size = NULL;
	const char *name = NULL;
	if(!get_table(type, &table, &size, &name))
		return;

	log_info("Searching for hash collisions in %s lookup table", name);

	// Do a linear search to find hash collisions in the sorted array
	unsigned int collisions = 0, errors = 0;
	for(size_t i = 1; i < *size; i++)
	{
		// If the hash value of the current element is the same as the previous element
		if(table[i].hash == table[i - 1].hash)
		{
			// Get the corresponding ID of the previous and this element
			unsigned int id1 = table[i - 1].id;
			unsigned int id2 = table[i].id;

			if(type == CLIENTS_LOOKUP)
			{
				// Get and log the correlated client name (clients lookup only)
				const clientsData *client1 = getClient(id1, true);
				const clientsData *client2 = getClient(id2, true);

				const char *name1 = client1 ? getstr(client1->namepos) : "<invalid>";
				const char *name2 = client2 ? getstr(client2->namepos) : "<invalid>";

				log_info("Hash collision %"PRIu32" found at position %zu/%zu between client IDs %u (%s) and %u (%s)",
				         table[i].hash, i - 1, i, id1, name1, id2, name2);
			}
			else if(type == DOMAINS_LOOKUP)
			{
				// Get and log the correlated domain name (domains lookup only)
				const domainsData *domain1 = getDomain(id1, true);
				const domainsData *domain2 = getDomain(id2, true);

				const char *name1 = domain1 ? getstr(domain1->domainpos) : "<invalid>";
				const char *name2 = domain2 ? getstr(domain2->domainpos) : "<invalid>";

				log_info("Hash collision %"PRIu32" found at position %zu/%zu between domain IDs %u (%s) and %u (%s)",
				         table[i].hash, i - 1, i, id1, name1, id2, name2);
			}
			else if(type == DNS_CACHE_LOOKUP)
			{
				// Get and log the correlated IDs (DNS cache only)
				const DNSCacheData *cache1 = getDNSCache(id1, true);
				const DNSCacheData *cache2 = getDNSCache(id2, true);

				log_info("Hash collision %"PRIu32" found at position %zu/%zu between DNS cache IDs %u (%u/%u/%u) and %u (%u/%u/%u)",
				         table[i].hash, i - 1, i,
				         id1, cache1->clientID, cache1->domainID, cache1->query_type,
				         id2, cache2->clientID, cache2->domainID, cache2->query_type);
			}

			collisions++;
		}
		else if(table[i].hash < table[i - 1].hash)
		{
			// Log an error if the array is not sorted, the equality
			// check was already done in the previous if statement
			//
			// This is really an error as, when the array is not
			// sorted, the binary search algorithm will not be able
			// to find elements possibly even causing artificial
			// hash collisions above as the same entry might be
			// inserted multiple times
			log_err("Array is not sorted at position %zu/%zu: %"PRIu32" > %"PRIu32,
			        i - 1, i, table[i - 1].hash, table[i].hash);

			errors++;
		}
	}

	// Log results, if there are any collisions or errors, log as error,
	// otherwise as info message
	const int priority = collisions > 0 || errors > 0 ? LOG_ERR : LOG_INFO;
	log_lvl(priority, "Found %u hash collisions and %u sorting errors in %s lookup table (scanned %u elements)",
	        collisions, errors, name, *size);
}

/**
 * @brief Searches for hash collisions in various lookup tables.
 *
 * @return void
 */
void lookup_find_hash_collisions(void)
{
	// Search for hash collisions in the clients lookup table
	lookup_find_hash_collisions_table(CLIENTS_LOOKUP);

	// Search for hash collisions in the domains lookup table
	lookup_find_hash_collisions_table(DOMAINS_LOOKUP);

	// Search for hash collisions in the DNS cache lookup table
	lookup_find_hash_collisions_table(DNS_CACHE_LOOKUP);
}
