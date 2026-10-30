/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Lookup table header
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef LOOKUP_TABLE_H
#define LOOKUP_TABLE_H

#include <stdbool.h>
#include <stddef.h>
// uint32_t
#include <stdint.h>
// memmove
#include <string.h>
// enum memory_type
#include "enums.h"

#define LOOKUP_TABLE_PRIVATE
#include "shmem.h"
#undef LOOKUP_TABLE_PRIVATE

/**
 * @struct lookup_table
 * @brief A slot of a lookup hash table.
 *
 * It contains an identifier and a hash value, a zero hash marks an empty slot.
 *
 * @var lookup_table::id
 * The identifier for the data.
 *
 * @var lookup_table::hash
 * The hash value associated with the data.
 */
struct lookup_table {
	unsigned int id;
	uint32_t hash;
};

// Usable slots: the largest power of two within the allocated entries
static inline unsigned int lookup_capacity(const unsigned int max)
{
	return max < 2 ? 0 : 1u << (31 - __builtin_clz(max));
}

bool lookup_insert(const enum memory_type type, const unsigned int id, const uint32_t hash);
bool lookup_remove(const enum memory_type type, const unsigned int id, const uint32_t hash);
void lookup_rehash(const enum memory_type type);
bool lookup_find_id(const enum memory_type type, const uint32_t hash, const struct lookup_data *lookup_data,
                    unsigned int *matchingID,
                    bool (*cmp_func)(const struct lookup_table *entry, const struct lookup_data *lookup_data));
void lookup_find_hash_collisions(void);

#endif //LOOKUP_TABLE_H
