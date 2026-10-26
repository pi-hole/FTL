/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Client name history
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "name-history.h"
#include "log.h"

// A query keeps the name its client had when the query was made. An entry
// says that the client's queries with an ID below until_id, and not below the
// until_id of its previous entry, had the name at namepos. The entries are
// sorted by client and until_id. Only the main process uses them (resolver,
// import, export, query log and GC), always with the SHM lock held
struct name_entry {
	int64_t until_id;
	uint32_t clientID;
	uint32_t namepos;
};

// 1 MiB at most. The GC drops the entries older than the oldest query in
// memory, so only a storm of renames reaches this, later names are then not
// remembered
#define NAME_HISTORY_MAX 65536u

static struct name_entry *entries = NULL;
static unsigned int n_entries = 0, cap_entries = 0;

// Position of the client's first entry with an until_id above id, or of the
// first entry of the next client
static unsigned int __attribute__((pure)) upper_bound(const unsigned int clientID, const int64_t id)
{
	unsigned int lo = 0, hi = n_entries;
	while(lo < hi)
	{
		const unsigned int mid = lo + (hi - lo) / 2;
		if(entries[mid].clientID < clientID ||
		   (entries[mid].clientID == clientID && entries[mid].until_id <= id))
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

// Position of the name the client had when its query with this ID was made,
// current is the name it has now
size_t __attribute__((pure)) client_name_at(const unsigned int clientID, const size_t current, const int64_t id)
{
	if(n_entries == 0)
		return current;
	const unsigned int i = upper_bound(clientID, id);
	return i < n_entries && entries[i].clientID == clientID ? entries[i].namepos : current;
}

// Insert an entry at position i, false if the history is full
static bool insert_entry(const unsigned int i, const unsigned int clientID, const int64_t until_id, const size_t namepos)
{
	if(n_entries >= NAME_HISTORY_MAX)
	{
		// Once per run, later renames are not remembered from here on
		static bool warned = false;
		if(!warned)
			log_warn("Client name history is full (%u entries), further renames are not remembered",
			         NAME_HISTORY_MAX);
		warned = true;
		return false;
	}
	if(namepos > UINT32_MAX)
		return false;
	if(n_entries == cap_entries)
	{
		const unsigned int cap = cap_entries > 0 ? 2 * cap_entries : 64;
		struct name_entry *grown = realloc(entries, cap * sizeof(*entries));
		if(grown == NULL)
		{
			log_err("Cannot remember a client name, out of memory");
			return false;
		}
		entries = grown;
		cap_entries = cap;
	}
	memmove(&entries[i + 1], &entries[i], (n_entries - i) * sizeof(*entries));
	entries[i] = (struct name_entry){ .until_id = until_id, .clientID = clientID, .namepos = (uint32_t)namepos };
	n_entries++;
	return true;
}

// The client has the name at namepos from its query with ID from_id on, the
// queries before keep the name it had
void rename_client(clientsData *client, const unsigned int clientID, const size_t namepos, const int64_t from_id)
{
	if(client->namepos == namepos)
		return;
	if(client->count > 0)
		insert_entry(upper_bound(clientID, from_id), clientID, from_id, client->namepos);
	client->namepos = namepos;
}

// A query read from the database, in the order of the IDs, with the name it
// was stored with. Each run of queries with the same name becomes an entry
void name_history_import(const unsigned int clientID, const int64_t id, const size_t namepos)
{
	const unsigned int i = upper_bound(clientID, id);
	if(i > 0 && entries[i - 1].clientID == clientID && entries[i - 1].namepos == namepos)
		entries[i - 1].until_id = id + 1;
	else
		insert_entry(i, clientID, id + 1, namepos);
}

// Drop the entries no query in memory reaches, those below the oldest one
void name_history_gc(const int64_t oldest_id)
{
	unsigned int kept = 0;
	for(unsigned int i = 0; i < n_entries; i++)
		if(entries[i].until_id > oldest_id)
			entries[kept++] = entries[i];
	n_entries = kept;
}
