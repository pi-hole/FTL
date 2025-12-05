/* Pi-hole: A black hole for Internet advertisements
*  (c) 2018 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Shared memory header
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef SHARED_MEMORY_SERVER_H
#define SHARED_MEMORY_SERVER_H
#include <sys/mman.h>        /* For shm_* functions */
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>           /* For O_* constants */
#include <stdbool.h>

// TYPE_MAX
#include "datastructure.h"

typedef struct {
	char *name;
	size_t size;
	void *ptr;
	int fd;
	struct flock lock;
} SharedMemory;

typedef struct {
	int version;
	pid_t pid;
	unsigned int global_shm_counter;
	size_t next_str_pos;
	unsigned int qps[QPS_AVGLEN];
} ShmSettings;

typedef struct {
	unsigned int queries;
	unsigned int upstreams;
	unsigned int clients;
	unsigned int domains;
	unsigned int queries_MAX;
	unsigned int upstreams_MAX;
	unsigned int clients_MAX;
	unsigned int domains_MAX;
	unsigned int strings_MAX;
	unsigned int reply_NODATA;
	unsigned int reply_NXDOMAIN;
	unsigned int reply_CNAME;
	unsigned int reply_IP;
	unsigned int reply_domain;
	unsigned int dns_cache_size;
	unsigned int dns_cache_MAX;
	unsigned int per_client_regex_MAX;
	unsigned int clients_lookup_MAX;
	unsigned int clients_lookup_size;
	unsigned int domains_lookup_MAX;
	unsigned int domains_lookup_size;
	unsigned int dns_cache_lookup_MAX;
	unsigned int dns_cache_lookup_size;
	unsigned int regex_change;
	struct {
		int gravity;
		int clients;
		int groups;
		int lists;
		struct {
			struct {
				struct {
					int total;
					int enabled;
				} exact;
				struct {
					int total;
					int enabled;
				} regex;
			} allowed;
			struct {
				struct {
					int total;
					int enabled;
				} exact;
				struct {
					int total;
					int enabled;
				} regex;
			} denied;
		} domains;
	} database;
	unsigned int querytype[TYPE_MAX];
	unsigned int status[QUERY_STATUS_MAX];
	unsigned int reply[QUERY_REPLY_MAX];
} countersStruct;

extern countersStruct *counters;

#ifdef SHMEM_PRIVATE
/// Create shared memory
///
/// \param name the name of the shared memory
/// \param sharedMemory the shared memory object to fill
/// \param size the size to allocate
/// No return value as the function will exit on failure
static bool create_shm(const char *name, SharedMemory *sharedMemory, const size_t size);

/// Reallocate shared memory
///
/// \param sharedMemory the shared memory struct
/// \param size1 the new size (factor 1)
/// \param size2 the new size (factor 2)
/// \param resize whether the object should be resized (true) or only remapped (false)
/// \return if reallocation was successful
static bool realloc_shm(SharedMemory *sharedMemory, const size_t size1, const size_t size2, const bool resize);

/// Disconnect from shared memory. If there are no other connections to shared memory, it will be deleted.
///
/// \param sharedMemory the shared memory struct
static void delete_shm(SharedMemory *sharedMemory);

// Number of elements in the recycle arrays
// Default: 65535 (which is 2^16 - 1)
// Total RAM estimate of struct recycler_tables is ~ RECYCLE_ARRAY_LEN * 12 bytes
// (roughly 786 KB for the default value)
#define RECYCLE_ARRAY_LEN 65535u

/**
 * struct recycle_table - Structure to hold recycling information.
 * @var recycle_table::size: The size of the recycle table.
 * @var recycle_table::id: An array of recycled IDs.
 */
struct recycle_table {
	unsigned int count;
	unsigned int id[RECYCLE_ARRAY_LEN];
};


/**
 * struct recycler_table - Structure to hold multiple recycle tables.
 * @var recycler_tables::client: Recycle table for clients.
 * @var recycler_tables::domain: Recycle table for domains.
 * @var recycler_tables::DNScache: Recycle table for DNS cache.
 */
struct recycler_tables {
	struct recycle_table client;
	struct recycle_table domain;
	struct recycle_table dns_cache;
};
#endif

#if defined(SHMEM_PRIVATE) || defined(LOOKUP_TABLE_PRIVATE)
extern struct lookup_table *clients_lookup;
extern struct lookup_table *domains_lookup;
extern struct lookup_table *dns_cache_lookup;
#endif

/// Block until a lock can be obtained
#define lock_shm() _lock_shm(__FUNCTION__, __LINE__, __FILE__)
void _lock_shm(const char* func, const int line, const char* file);

// Return if the current mutex locked the SHM lock
bool is_our_lock(void);

/// Unlock the lock. Only call this if there is an active lock.
#define unlock_shm() _unlock_shm(__FUNCTION__, __LINE__, __FILE__)
void _unlock_shm(const char* func, const int line, const char* file);

bool init_shmem(void);
void destroy_shmem(void);
void init_queries_shm_sz(void);
#define addstr(str) _addstr(str, __FUNCTION__, __LINE__, __FILE__)
size_t _addstr(const char *str, const char *func, const int line, const char *file);
#define getstr(pos) _getstr(pos, __FUNCTION__, __LINE__, __FILE__)
const char *_getstr(const size_t pos, const char *func, const int line, const char *file);

/**
 * Create a new overTime client shared memory block.
 * This also updates `overTimeClientData`.
 */
void newOverTimeClient(const int clientID);

/**
 * Add a new overTime slot to each overTime client shared memory block.
 * This also updates `overTimeClientData`.
 */
void addOverTimeClientSlot(void);

// Change ownership of shared memory objects
void chown_all_shmem(struct passwd *ent_pw);

// Get details about shared memory used by FTL
void log_shmem_details(void);

// Per-client regex buffer storing whether or not a specific regex is enabled for a particular client
void add_per_client_regex(unsigned int clientID);
void reset_per_client_regex(const unsigned int clientID);
bool get_per_client_regex(const unsigned int clientID, const unsigned int regexID);
void set_per_client_regex(const unsigned int clientID, const unsigned int regexID, const bool value);

// Used in dnsmasq/utils.c
int is_shm_fd(const int fd);

void update_qps(const time_t timestamp);
void reset_qps(const time_t timestamp);
double get_qps(void) __attribute__((pure));

// Recycler table functions
bool set_next_recycled_ID(const enum memory_type type, const unsigned int id);
bool get_next_recycled_ID(const enum memory_type type, unsigned int *id);
void print_recycle_list_fullness(void);

void dump_strings(void);

#endif //SHARED_MEMORY_SERVER_H
