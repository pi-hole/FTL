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

// The lookup tables are open-addressing hash tables with linear probing. A
// zero hash marks an empty slot (fresh shared memory is zeroed), so a real
// hash of zero is stored as one.
static inline uint32_t slot_hash(const uint32_t hash)
{
	return hash != 0 ? hash : 1u;
}


// Fibonacci hashing also spreads the bit-packed DNS cache hashes
static inline unsigned int home_slot(const uint32_t hash, const unsigned int cap)
{
	return (uint32_t)(hash * 2654435769u) >> (32 - __builtin_ctz(cap));
}

/**
 * @brief Retrieves the appropriate lookup table and its size based on the specified memory type.
 *
 * @param type The memory type for which the lookup table is requested. It can be one of the following:
 *             - CLIENTS_LOOKUP
 *             - DOMAINS_LOOKUP
 *             - DNS_CACHE_LOOKUP
 * @param table A pointer to a pointer that will be assigned the address of the appropriate lookup table.
 * @param size A pointer to a pointer that will be assigned the address of the number of entries.
 * @param cap A pointer that will be assigned the number of usable slots (a power of two).
 * @param name A pointer to a pointer that will be assigned the name of the appropriate lookup table.
 * @return true if the lookup table and size were successfully retrieved, false if the memory type is invalid.
 */
static bool get_table(const enum memory_type type, struct lookup_table **table, unsigned int **size,
                      unsigned int *cap, const char **name)
{
	// Get the correct lookup_table array based on the type
	if(type == CLIENTS_LOOKUP)
	{
		*name = "clients";
		*table = clients_lookup;
		*size = &counters->clients_lookup_size;
		*cap = lookup_capacity(counters->clients_lookup_MAX);
	}
	else if(type == DOMAINS_LOOKUP)
	{
		*name = "domains";
		*table = domains_lookup;
		*size = &counters->domains_lookup_size;
		*cap = lookup_capacity(counters->domains_lookup_MAX);
	}
	else if(type == DNS_CACHE_LOOKUP)
	{
		*name = "DNS cache";
		*table = dns_cache_lookup;
		*size = &counters->dns_cache_lookup_size;
		*cap = lookup_capacity(counters->dns_cache_lookup_MAX);
	}
	else
	{
		log_err("Invalid memory type in get_table(%u)", type);
		return false;
	}

	return *cap > 0;
}

// Put an entry into its first free slot
static void place(struct lookup_table *table, const unsigned int cap, const struct lookup_table entry)
{
	unsigned int pos = home_slot(entry.hash, cap);
	while(table[pos].hash != 0)
		pos = (pos + 1) & (cap - 1);
	table[pos] = entry;
}

/**
 * @brief Inserts an element into the lookup table.
 *
 * The table is grown first if it is getting full, so there is always an empty
 * slot to end a probe sequence.
 *
 * @param type The memory type that determines which lookup table to use.
 * @param id The ID of the element to be inserted.
 * @param hash The hash value of the element to be inserted.
 * @return bool true if the element was successfully inserted, false otherwise.
 */
bool lookup_insert(const enum memory_type type, const unsigned int id, const uint32_t hash)
{
	shm_ensure_lookup_size(type);

	// Get the correct lookup_table array based on the type
	struct lookup_table *table = NULL;
	unsigned int *size = NULL, cap = 0;
	const char *name = NULL;
	if(!get_table(type, &table, &size, &cap, &name))
		return false;

	place(table, cap, (struct lookup_table){ .id = id, .hash = slot_hash(hash) });
	(*size)++;

	return true;
}

/**
 * @brief Re-places all entries of a lookup table after it grew.
 *
 * @param type The memory type that determines which lookup table to use.
 */
void lookup_rehash(const enum memory_type type)
{
	struct lookup_table *table = NULL;
	unsigned int *size = NULL, cap = 0;
	const char *name = NULL;
	if(!get_table(type, &table, &size, &cap, &name))
		return;

	unsigned int n = 0;
	for(unsigned int i = 0; i < cap; i++)
		if(table[i].hash != 0)
			n++;

	struct lookup_table *entries = calloc(n + 1, sizeof(*entries));
	if(entries == NULL)
	{
		log_crit("Memory allocation failed while rehashing the %s lookup table! Exiting", name);
		exit(EXIT_FAILURE);
	}

	n = 0;
	for(unsigned int i = 0; i < cap; i++)
		if(table[i].hash != 0)
			entries[n++] = table[i];

	memset(table, 0, cap * sizeof(*table));
	for(unsigned int i = 0; i < n; i++)
		place(table, cap, entries[i]);
	*size = n;

	free(entries);
}

/**
 * @brief Removes an element from the lookup table.
 *
 * Later entries of the same probe sequence are shifted back into the gap
 * (backward-shift deletion), so no tombstones are needed.
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
	unsigned int *size = NULL, cap = 0;
	const char *name = NULL;
	if(!get_table(type, &table, &size, &cap, &name))
		return false;

	const uint32_t h = slot_hash(hash);
	const unsigned int mask = cap - 1;
	unsigned int pos = home_slot(h, cap);
	while(table[pos].hash != 0 && (table[pos].hash != h || table[pos].id != id))
		pos = (pos + 1) & mask;

	if(table[pos].hash == 0)
	{
		// The element is not in the table
		log_warn("Element to be removed (ID %u, hash %u) not in %s lookup table",
		         id, hash, name);
		return true;
	}

	// An entry may move into the gap unless its home slot lies between
	// the gap and its current slot
	for(unsigned int next = (pos + 1) & mask; table[next].hash != 0; next = (next + 1) & mask)
	{
		const unsigned int home = home_slot(table[next].hash, cap);
		if(((next - home) & mask) >= ((next - pos) & mask))
		{
			table[pos] = table[next];
			pos = next;
		}
	}
	table[pos] = (struct lookup_table){ 0 };
	(*size)--;

	return true;
}

/**
 * @brief Finds an element in the lookup table based on the given type and hash.
 *
 * Several elements may share a hash value, cmp_func decides which one matches.
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
	unsigned int *size = NULL, cap = 0;
	const char *name = NULL;
	if(!get_table(type, &table, &size, &cap, &name))
		return false;

	const uint32_t h = slot_hash(hash);
	for(unsigned int pos = home_slot(h, cap); table[pos].hash != 0; pos = (pos + 1) & (cap - 1))
	{
		if(table[pos].hash == h && cmp_func(&table[pos], lookup_data))
		{
			*matchingID = table[pos].id;
			return true;
		}
	}

	return false;
}

/**
 * @brief Searches for hash collisions in the lookup table of the specified memory type.
 *
 * This function my be used to assess the quality of the hash function. It also
 * reports entries that cannot be found because their probe sequence is broken.
 *
 * @param type The type of memory for which to search for hash collisions. This can be one of:
 *             - CLIENTS_LOOKUP: Searches for collisions in the clients lookup table.
 *             - DOMAINS_LOOKUP: Searches for collisions in the domains lookup table.
 *             - DNS_CACHE_LOOKUP: Searches for collisions in the DNS cache lookup table.
 */
static void lookup_find_hash_collisions_table(const enum memory_type type)
{
	// Get the correct lookup_table array based on the type
	struct lookup_table *table = NULL;
	unsigned int *size = NULL, cap = 0;
	const char *name = NULL;
	if(!get_table(type, &table, &size, &cap, &name))
		return;

	log_info("Searching for hash collisions in %s lookup table", name);

	// Walk from each entry's home slot to the entry itself: earlier entries
	// with the same hash are collisions, an empty slot on the way means the
	// entry cannot be found
	unsigned int collisions = 0, errors = 0;
	for(unsigned int i = 0; i < cap; i++)
	{
		if(table[i].hash == 0)
			continue;

		for(unsigned int pos = home_slot(table[i].hash, cap); pos != i; pos = (pos + 1) & (cap - 1))
		{
			if(table[pos].hash == 0)
			{
				log_err("Entry at slot %u (ID %u, hash %"PRIu32") cannot be found in %s lookup table",
				        i, table[i].id, table[i].hash, name);
				errors++;
				break;
			}
			if(table[pos].hash != table[i].hash)
				continue;

			// Get the corresponding ID of the earlier and this element
			unsigned int id1 = table[pos].id;
			unsigned int id2 = table[i].id;

			if(type == CLIENTS_LOOKUP)
			{
				// Get and log the correlated client name (clients lookup only)
				const clientsData *client1 = getClient(id1, true);
				const clientsData *client2 = getClient(id2, true);

				const char *name1 = client1 ? getstr(client1->namepos) : "<invalid>";
				const char *name2 = client2 ? getstr(client2->namepos) : "<invalid>";

				log_info("Hash collision %"PRIu32" found at slots %u/%u between client IDs %u (%s) and %u (%s)",
				         table[i].hash, pos, i, id1, name1, id2, name2);
			}
			else if(type == DOMAINS_LOOKUP)
			{
				// Get and log the correlated domain name (domains lookup only)
				const domainsData *domain1 = getDomain(id1, true);
				const domainsData *domain2 = getDomain(id2, true);

				const char *name1 = domain1 ? getstr(domain1->domainpos) : "<invalid>";
				const char *name2 = domain2 ? getstr(domain2->domainpos) : "<invalid>";

				log_info("Hash collision %"PRIu32" found at slots %u/%u between domain IDs %u (%s) and %u (%s)",
				         table[i].hash, pos, i, id1, name1, id2, name2);
			}
			else if(type == DNS_CACHE_LOOKUP)
			{
				// Get and log the correlated IDs (DNS cache only)
				const DNSCacheData *cache1 = getDNSCache(id1, true);
				const DNSCacheData *cache2 = getDNSCache(id2, true);

				log_info("Hash collision %"PRIu32" found at slots %u/%u between DNS cache IDs %u (%u/%u/%u) and %u (%u/%u/%u)",
				         table[i].hash, pos, i,
				         id1, cache1->clientID, cache1->domainID, cache1->query_type,
				         id2, cache2->clientID, cache2->domainID, cache2->query_type);
			}

			collisions++;
		}
	}

	// Log results, if there are any collisions or errors, log as error,
	// otherwise as info message
	const int priority = collisions > 0 || errors > 0 ? LOG_ERR : LOG_INFO;
	log_lvl(priority, "Found %u hash collisions and %u unreachable entries in %s lookup table (%u entries in %u slots)",
	        collisions, errors, name, *size, cap);
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
