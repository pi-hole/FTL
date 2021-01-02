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
    const char *name;
    size_t size;
    void *ptr;
} SharedMemory;

typedef struct {
	int version;
	unsigned int global_shm_counter;
	unsigned int next_str_pos;
} ShmSettings;

typedef struct {
	int queries;
	int blocked;
	int forwarded;
	int cached;
	int unknown;
	int upstreams;
	int clients;
	int domains;
	int queries_MAX;
	int upstreams_MAX;
	int clients_MAX;
	int domains_MAX;
	int strings_MAX;
	int gravity;
	int querytype[TYPE_MAX];
	int reply_NODATA;
	int reply_NXDOMAIN;
	int reply_CNAME;
	int reply_IP;
	int reply_domain;
	int dns_cache_size;
	int dns_cache_MAX;
	unsigned int regex_change;
} countersStruct;

extern countersStruct *counters;

/// Create shared memory
///
/// \param name the name of the shared memory
/// \param size the size to allocate
/// \param create_new true = delete old file, create new, false = connect to existing object or fail
/// \return a structure with a pointer to the mounted shared memory. The pointer
/// will always be valid, because if it failed FTL will have exited.
SharedMemory create_shm(const char *name, const size_t size, bool create_new);

/// Reallocate shared memory
///
/// \param sharedMemory the shared memory struct
/// \param size1 the new size (factor 1)
/// \param size2 the new size (factor 2)
/// \param resize whether the object should be resized or only remapped
/// \return if reallocation was successful
bool realloc_shm(SharedMemory *sharedMemory, const size_t size1, const size_t size2, const bool resize);

/// Disconnect from shared memory. If there are no other connections to shared memory, it will be deleted.
///
/// \param sharedMemory the shared memory struct
void delete_shm(SharedMemory *sharedMemory);

/// Block until a lock can be obtained
#define lock_shm() _lock_shm(__FUNCTION__, __LINE__, __FILE__)
void _lock_shm(const char* func, const int line, const char* file);

/// Unlock the lock. Only call this if there is an active lock.
#define unlock_shm() _unlock_shm(__FUNCTION__, __LINE__, __FILE__)
void _unlock_shm(const char* func, const int line, const char* file);

bool init_shmem(bool create_new);
void destroy_shmem(void);
size_t addstr(const char *str);
const char *getstr(const size_t pos);
void *enlarge_shmem_struct(const char type);

/**
 * Escapes a string by replacing special characters, such as spaces
 */
char *str_escape(const char *input, unsigned int *N);

/**
 * Compare two strings. Escape them if needed
 */
bool strcmp_escaped(const char *a, const char *b);

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

// Per-client regex buffer storing whether or not a specific regex is enabled for a particular client
void add_per_client_regex(unsigned int clientID);
void reset_per_client_regex(const int clientID);
bool get_per_client_regex(const int clientID, const int regexID);
void set_per_client_regex(const int clientID, const int regexID, const bool value);

void memory_check(const enum memory_type which);

#endif //SHARED_MEMORY_SERVER_H
