/* Pi-hole: A black hole for Internet advertisements
*  (c) 2018 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Shared memory subroutines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#define SHMEM_PRIVATE
#include "shmem.h"
#include "overTime.h"
#include "log.h"
#include "config/config.h"
// data getter functions
#include "datastructure.h"
// get_num_regex()
#include "regex_r.h"
// sleepms()
#include "timers.h"
// FTL_gettid
#include "daemon.h"
// NAME_MAX
#include <limits.h>
// gettid
#include "daemon.h"
// generate_backtrace()
#include "signals.h"
// get_path_usage()
#include "files.h"
// log_resource_shortage()
#include "database/message-table.h"
// struct lookup_table
#include "lookup-table.h"

/// The version of shared memory used
#define SHARED_MEMORY_VERSION 14

/// The name of the shared memory. Use this when connecting to the shared memory.
#define SHMEM_PATH "/dev/shm"
#define SHARED_LOCK_NAME "lock"
#define SHARED_STRINGS_NAME "strings"
#define SHARED_COUNTERS_NAME "counters"
#define SHARED_DOMAINS_NAME "domains"
#define SHARED_CLIENTS_NAME "clients"
#define SHARED_QUERIES_NAME "queries"
#define SHARED_UPSTREAMS_NAME "upstreams"
#define SHARED_OVERTIME_NAME "overTime"
#define SHARED_SETTINGS_NAME "settings"
#define SHARED_DNS_CACHE "dns-cache"
#define SHARED_PER_CLIENT_REGEX "per-client-regex"
#define SHARED_CLIENTS_LOOKUP_NAME "clients-lookup"
#define SHARED_DOMAINS_LOOKUP_NAME "domains-lookup"
#define SHARED_DNS_CACHE_LOOKUP_NAME "dns-cache-lookup"
#define SHARED_RECYCLER_NAME "recycler"

// Allocation step for FTL-strings bucket. This is somewhat special as we use
// this as a general-purpose storage which should always be large enough. If,
// for some reason, more data than this step has to be stored (highly unlikely,
// close to impossible), the data will be properly truncated and we try again in
// the next lock round
#define STRINGS_ALLOC_STEP (10*pagesize)

// Global counters struct
countersStruct *counters = NULL;
#define SHARED_FIFO_LOG_NAME "fifo-log"

/// The pointer in shared memory to the shared string buffer
static SharedMemory shm_lock = { 0 };
static SharedMemory shm_strings = { 0 };
static SharedMemory shm_counters = { 0 };
static SharedMemory shm_domains = { 0 };
static SharedMemory shm_clients = { 0 };
static SharedMemory shm_queries = { 0 };
static SharedMemory shm_upstreams = { 0 };
static SharedMemory shm_overTime = { 0 };
static SharedMemory shm_settings = { 0 };
static SharedMemory shm_dns_cache = { 0 };
static SharedMemory shm_per_client_regex = { 0 };
static SharedMemory shm_fifo_log = { 0 };
static SharedMemory shm_clients_lookup = { 0 };
static SharedMemory shm_domains_lookup = { 0 };
static SharedMemory shm_dns_cache_lookup = { 0 };
static SharedMemory shm_recycler = { 0 };

static SharedMemory *sharedMemories[] = { &shm_lock,
                                          &shm_strings,
                                          &shm_counters,
                                          &shm_domains,
                                          &shm_clients,
                                          &shm_queries,
                                          &shm_upstreams,
                                          &shm_overTime,
                                          &shm_settings,
                                          &shm_dns_cache,
                                          &shm_per_client_regex,
                                          &shm_fifo_log,
                                          &shm_clients_lookup,
                                          &shm_domains_lookup,
                                          &shm_dns_cache_lookup,
                                          &shm_recycler };

// Variable size array structs
static queriesData *queries = NULL;
static clientsData *clients = NULL;
static domainsData *domains = NULL;
static upstreamsData *upstreams = NULL;
static DNSCacheData *dns_cache = NULL;
fifologData *fifo_log = NULL;
struct lookup_table *clients_lookup = NULL;
struct lookup_table *domains_lookup = NULL;
struct lookup_table *dns_cache_lookup = NULL;
struct recycler_tables *recycler = NULL;

static void **global_pointers[] = {(void**)&queries,
                                   (void**)&clients,
                                   (void**)&domains,
                                   (void**)&upstreams,
                                   (void**)&dns_cache,
                                   (void**)&fifo_log,
                                   (void**)&clients_lookup,
                                   (void**)&domains_lookup,
                                   (void**)&dns_cache_lookup,
                                   (void**)&recycler};

typedef struct {
	struct {
		pthread_mutex_t outer;
		pthread_mutex_t inner;
	} lock;
	struct {
		volatile pid_t pid;
		volatile pid_t tid;
	} owner;
	struct {
		struct timespec begin;
		struct timespec end;
	} time;
} ShmLock;
static ShmLock *shmLock = NULL;
static ShmSettings *shmSettings = NULL;

static int pagesize;
static unsigned int local_shm_counter = 0;
static pid_t shmem_pid = 0;
static size_t used_shmem = 0u;
static size_t get_optimal_object_size(const size_t objsize, const size_t minsize);

// Private prototypes
static void *enlarge_shmem_struct(const char type);

// Calculate and format the memory usage of the shared memory segment used by
// FTL
// The function returns the percentage of used memory. A human-readable string
// is stored in the buffer passed to this function.
static int get_dev_shm_usage(char buffer[64])
{
	char buffer2[64] = { 0 };
	const int percentage = get_path_usage(SHMEM_PATH, buffer2);

	// Generate human-readable "used by FTL" size
	char prefix_FTL[2] = { 0 };
	double formatted_FTL = 0.0;
	format_memory_size(prefix_FTL, used_shmem, &formatted_FTL);

	// Print result into buffer passed to this subroutine
	snprintf(buffer, 64, "%s, FTL uses %.1f%sB",
	         buffer2, formatted_FTL, prefix_FTL);

	// Return percentage
	return percentage;
}

// chown_shmem() changes the file ownership of a given shared memory object
static bool chown_shmem(SharedMemory *sharedMemory, struct passwd *ent_pw)
{
	// Open shared memory object
	const int fd = shm_open(sharedMemory->name, O_RDWR, S_IRUSR | S_IWUSR);
	log_debug(DEBUG_SHMEM, "Changing %s (%d) to %u:%u", sharedMemory->name, fd, ent_pw->pw_uid, ent_pw->pw_gid);

	if(fd == -1)
	{
		log_crit("Failed to open shared memory object \"%s\" for chown: %s",
		         sharedMemory->name, strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(fchown(fd, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
	{
		log_crit("Failed to change ownership of shared memory object \"%s\": %s",
		         sharedMemory->name,
		         errno == EPERM ? "Insufficient permissions (CAP_CHOWN required)" : strerror(errno));

		return false;
	}

	// Close shared memory object file descriptor as it is no longer
	// needed after having called ftruncate()
	close(fd);
	return true;
}

// Add string to our shared memory buffer
// This function checks if the string already exists in the buffer and returns
// the position of the existing string if it does. Otherwise, it adds the
// string to the buffer and returns the position of the newly added string.
size_t _addstr(const char *input, const char *func, const int line, const char *file)
{
	if(input == NULL)
	{
		log_warn("Called addstr() with NULL pointer");
		return 0;
	}

	// Get string length, add terminating character
	size_t len = strlen(input) + 1;
	const size_t avail_mem = shm_strings.size - shmSettings->next_str_pos;

	// If this is an empty string (only the terminating character is present),
	// use the shared memory string at position zero instead of creating a new
	// entry here. We also ensure that the given string is not too long to
	// prevent possible memory corruption caused by strncpy() further down
	if(len == 1)
	{
		return 0;
	}
	else if(len > (size_t)(pagesize-1))
	{
		log_warn("Shortening too long string (len %zu > pagesize %i)", len, pagesize);
		len = pagesize;
	}
	else if(len > (size_t)(avail_mem-1))
	{
		log_warn("Shortening too long string (len %zu > available memory %zu)", len, avail_mem);
		len = avail_mem;
	}

	// Search buffer for existence of exact same string
	char *str_pos = memmem(shm_strings.ptr, shmSettings->next_str_pos, input, len);
	if(str_pos != NULL)
	{
		log_debug(DEBUG_SHMEM, "Reusing existing string \"%s\" at %zd in %s() (%s:%i)",
		          input, str_pos - (char*)shm_strings.ptr, func, short_path(file), line);

		// Return position of existing string
		return (str_pos - (char*)shm_strings.ptr);
	}

	// Debugging output
	log_debug(DEBUG_SHMEM, "Adding \"%s\" (len %zu) to buffer in %s() (%s:%i), next_str_pos is %zu",
	          input, len, func, short_path(file), line, shmSettings->next_str_pos);

	// Copy the C string pointed by input into the shared string buffer
	strncpy(&((char*)shm_strings.ptr)[shmSettings->next_str_pos], input, len);

	// Increment string length counter
	shmSettings->next_str_pos += len;

	// Return start of stored string
	return (shmSettings->next_str_pos - len);
}

// Get string from shared memory buffer
const char *_getstr(const size_t pos, const char *func, const int line, const char *file)
{
	// Only access the string memory if this memory region has already been set
	if(pos < shmSettings->next_str_pos)
		return &((const char*)shm_strings.ptr)[pos];
	else
	{
		log_warn("Tried to access %zu in %s() (%s:%i) but next_str_pos is %zu",
		         pos, func, file, line, shmSettings->next_str_pos);
		return "";
	}
}

// Create a mutex for shared memory
static void create_mutex(pthread_mutex_t *lock) {
	log_debug(DEBUG_SHMEM, "Creating SHM mutex lock");
	pthread_mutexattr_t lock_attr;

	// Initialize the lock attributes
	pthread_mutexattr_init(&lock_attr);

	// Allow the lock to be used by other processes
	// Mutexes created with this attributes object can be shared between any
	// threads that have access to the memory containing the object,
	// including threads in different processes.
	pthread_mutexattr_setpshared(&lock_attr, PTHREAD_PROCESS_SHARED);

	// Make the lock robust against thread death
	// If a mutex is initialized with the PTHREAD_MUTEX_ROBUST attribute and
	// its owner dies without unlocking it, any future attempts to call
	// pthread_mutex_lock(3) on this mutex will succeed and return
	// EOWNERDEAD to indicate that the original owner no longer exists and
	// the mutex is in an inconsistent state.
	pthread_mutexattr_setrobust(&lock_attr, PTHREAD_MUTEX_ROBUST);

	// Enabled pthread error checking
	// - A thread attempting to relock this mutex without first unlocking it
	//   shall return with an error (EDEADLK).
	// - A thread attempting to unlock a mutex which another thread has
	//   locked shall return with an error (EPERM).
	// - A thread attempting to unlock an unlocked mutex shall return with
	//   an error (EPERM).
	pthread_mutexattr_settype(&lock_attr, PTHREAD_MUTEX_ERRORCHECK);

	// Initialize the lock
	pthread_mutex_init(lock, &lock_attr);

	// Destroy the lock attributes since we're done with it
	pthread_mutexattr_destroy(&lock_attr);
}

// Remap shared object pointers which might have changed
static void remap_shm(void)
{
	realloc_shm(&shm_queries, counters->queries_MAX, sizeof(queriesData), false);
	queries = (queriesData*)shm_queries.ptr;

	realloc_shm(&shm_domains, counters->domains_MAX, sizeof(domainsData), false);
	domains = (domainsData*)shm_domains.ptr;

	realloc_shm(&shm_clients, counters->clients_MAX, sizeof(clientsData), false);
	clients = (clientsData*)shm_clients.ptr;

	realloc_shm(&shm_upstreams, counters->upstreams_MAX, sizeof(upstreamsData), false);
	upstreams = (upstreamsData*)shm_upstreams.ptr;

	realloc_shm(&shm_dns_cache, counters->dns_cache_MAX, sizeof(DNSCacheData), false);
	dns_cache = (DNSCacheData*)shm_dns_cache.ptr;

	realloc_shm(&shm_per_client_regex, counters->per_client_regex_MAX, sizeof(bool), false);
	// per-client-regex bools are not exposed by a global pointer

	realloc_shm(&shm_strings, counters->strings_MAX, sizeof(char), false);
	// strings are not exposed by a global pointer

	realloc_shm(&shm_domains_lookup, counters->domains_lookup_MAX, sizeof(struct lookup_table), false);
	domains_lookup = (struct lookup_table*)shm_domains_lookup.ptr;

	realloc_shm(&shm_clients_lookup, counters->clients_lookup_MAX, sizeof(struct lookup_table), false);
	clients_lookup = (struct lookup_table*)shm_clients_lookup.ptr;

	realloc_shm(&shm_dns_cache_lookup, counters->dns_cache_lookup_MAX, sizeof(struct lookup_table), false);
	dns_cache_lookup = (struct lookup_table*)shm_dns_cache_lookup.ptr;

	// Update local counter to reflect that we absorbed this change
	local_shm_counter = shmSettings->global_shm_counter;
}

// Obtain SHMEM lock
void _lock_shm(const char *func, const int line, const char *file)
{
	// There is no need to lock if we are the only thread
	// (e.g., when running pihole-FTL --config a.b.c def)
	if(shmLock == NULL)
		return;

	log_debug(DEBUG_LOCKS, "Waiting for SHM lock in %s() (%s:%i)", func, file, line);
	log_debug(DEBUG_LOCKS, "SHM lock: %p", shmLock);

	int result = pthread_mutex_lock(&shmLock->lock.outer);

	if(result != 0)
		log_err("Error when obtaining outer SHM lock: %s", strerror(result));

	if(result == EOWNERDEAD) {
		// Try to make the lock consistent if the other process died while
		// holding the lock
		log_debug(DEBUG_LOCKS, "Owner of outer SHM lock died, making lock consistent");

		result = pthread_mutex_consistent(&shmLock->lock.outer);
		if(result != 0)
			log_err("Failed to make outer SHM lock consistent: %s", strerror(result));
	}

	// Store lock owner after lock has been acquired and was made consistent (if required)
	shmLock->owner.pid = getpid();
	shmLock->owner.tid = gettid();

	// Check if this process needs to remap the shared memory objects
	if(shmSettings != NULL &&
	   local_shm_counter != shmSettings->global_shm_counter)
	{
		log_debug(DEBUG_SHMEM, "Remapping shared memory for current process %u %u",
		          local_shm_counter, shmSettings->global_shm_counter);
		remap_shm();
	}

	// Ensure we have enough shared memory available for new data
	shm_ensure_size();

	result = pthread_mutex_lock(&shmLock->lock.inner);

	clock_gettime(CLOCK_MONOTONIC, &shmLock->time.begin);
	log_debug(DEBUG_LOCKS, "Obtained SHM lock for %s() (%s:%i)", func, file, line);

	if(result != 0)
		log_err("Error when obtaining inner SHM lock: %s", strerror(result));

	if(result == EOWNERDEAD) {
		// Try to make the lock consistent if the other process died while
		// holding the lock
		log_debug(DEBUG_LOCKS, "Owner of inner SHM lock died, making lock consistent");

		result = pthread_mutex_consistent(&shmLock->lock.inner);
		if(result != 0)
			log_err("Failed to make inner SHM lock consistent: %s", strerror(result));
	}
}

// Release SHM lock
void _unlock_shm(const char *func, const int line, const char * file)
{
	// There is no need to unlock if we are the only thread
	// (e.g., when running pihole-FTL --config a.b.c def)
	if(shmLock == NULL)
		return;

	if(config.debug.locks.v.b && !is_our_lock())
	{
		log_err("Tried to unlock but lock is owned by %li/%li",
		        (long int)shmLock->owner.pid, (long int)shmLock->owner.tid);
	}

	// Unlock mutex
	int result = pthread_mutex_unlock(&shmLock->lock.inner);
	shmLock->owner.pid = 0;
	shmLock->owner.tid = 0;

	if(result != 0)
		log_err("Failed to unlock SHM lock: %s in %s() (%s:%i)", strerror(result), func, file, line);

	result = pthread_mutex_unlock(&shmLock->lock.outer);
	if(result != 0)
		log_err("Failed to unlock outer SHM lock: %s", strerror(result));

	clock_gettime(CLOCK_MONOTONIC, &shmLock->time.end);
	if(config.debug.timing.v.b)
	{
		const double lock_time = (shmLock->time.end.tv_sec - shmLock->time.begin.tv_sec) / 1000.0 +
		                         (shmLock->time.end.tv_nsec - shmLock->time.begin.tv_nsec) / 1e6;
		log_debug(DEBUG_TIMING, "SHM lock held for %.3f ms in %s() (%s:%i)",
		          lock_time, func, file, line);
	}

	log_debug(DEBUG_LOCKS, "Removed SHM lock in %s() (%s:%i)", func, file, line);
}

// Return if we locked this mutex (PID and TID match)
bool is_our_lock(void)
{
	if(shmLock->owner.pid == getpid() &&
	   shmLock->owner.tid == gettid())
		return true;
	return false;
}

bool init_shmem()
{
	// Get kernel's page size
	pagesize = getpagesize();

	/****************************** shared memory lock ******************************/
	// Try to create shared memory object
	create_shm(SHARED_LOCK_NAME, &shm_lock, sizeof(ShmLock));
	if(shm_lock.ptr == NULL)
		return false;

	shmLock = (ShmLock*)shm_lock.ptr;
	create_mutex(&shmLock->lock.outer);
	create_mutex(&shmLock->lock.inner);

	/****************************** shared counters struct ******************************/
	// Try to create shared memory object
	create_shm(SHARED_COUNTERS_NAME, &shm_counters, sizeof(countersStruct));
	if(shm_counters.ptr == NULL)
		return false;

	counters = (countersStruct*)shm_counters.ptr;

	/****************************** shared settings struct ******************************/
	// Try to create shared memory object
	create_shm(SHARED_SETTINGS_NAME, &shm_settings, sizeof(ShmSettings));
	if(shm_settings.ptr == NULL)
		return false;

	shmSettings = (ShmSettings*)shm_settings.ptr;
	shmSettings->version = SHARED_MEMORY_VERSION;
	shmSettings->global_shm_counter = 0;
	shmSettings->pid = shmem_pid = getpid();

	/****************************** shared strings buffer ******************************/
	// Try to create shared memory object
	create_shm(SHARED_STRINGS_NAME, &shm_strings, STRINGS_ALLOC_STEP);
	if(shm_strings.ptr == NULL)
		return false;

	counters->strings_MAX = shm_strings.size;

	// Initialize shared string object with an empty string at position zero
	((char*)shm_strings.ptr)[0] = '\0';
	shmSettings->next_str_pos = 1;

	/****************************** shared domains struct ******************************/
	size_t size = get_optimal_object_size(sizeof(domainsData), 1);
	// Try to create shared memory object
	create_shm(SHARED_DOMAINS_NAME, &shm_domains, size*sizeof(domainsData));
	if(shm_domains.ptr == NULL)
		return false;

	domains = (domainsData*)shm_domains.ptr;
	counters->domains_MAX = size;

	/****************************** shared clients struct ******************************/
	size = get_optimal_object_size(sizeof(clientsData), 1);
	// Try to create shared memory object
	create_shm(SHARED_CLIENTS_NAME, &shm_clients, size*sizeof(clientsData));
	if(shm_clients.ptr == NULL)
		return false;

	clients = (clientsData*)shm_clients.ptr;
	counters->clients_MAX = size;

	/****************************** shared upstreams struct ******************************/
	size = get_optimal_object_size(sizeof(upstreamsData), 1);
	// Try to create shared memory object
	create_shm(SHARED_UPSTREAMS_NAME, &shm_upstreams, size*sizeof(upstreamsData));
	if(shm_upstreams.ptr == NULL)
		return false;
	upstreams = (upstreamsData*)shm_upstreams.ptr;

	counters->upstreams_MAX = size;

	/****************************** shared queries struct ******************************/
	// Try to create shared memory object
	create_shm(SHARED_QUERIES_NAME, &shm_queries, pagesize*sizeof(queriesData));
	if(shm_queries.ptr == NULL)
		return false;
	queries = (queriesData*)shm_queries.ptr;

	counters->queries_MAX = pagesize;

	/****************************** shared overTime struct ******************************/
	size = get_optimal_object_size(sizeof(overTimeData), OVERTIME_SLOTS);
	// Try to create shared memory object
	create_shm(SHARED_OVERTIME_NAME, &shm_overTime, size*sizeof(overTimeData));
	if(shm_overTime.ptr == NULL)
		return false;

	// set global pointer in overTime.c
	overTime = (overTimeData*)shm_overTime.ptr;

	/****************************** shared DNS cache struct ******************************/
	size = get_optimal_object_size(sizeof(DNSCacheData), 1);
	// Try to create shared memory object
	create_shm(SHARED_DNS_CACHE, &shm_dns_cache, size*sizeof(DNSCacheData));
	if(shm_dns_cache.ptr == NULL)
		return false;

	dns_cache = (DNSCacheData*)shm_dns_cache.ptr;
	counters->dns_cache_MAX = size;

	/****************************** shared per-client regex buffer ******************************/
	size = pagesize; // Allocate one pagesize initially. This may be expanded later on
	// Try to create shared memory object
	create_shm(SHARED_PER_CLIENT_REGEX, &shm_per_client_regex, size);
	if(shm_per_client_regex.ptr == NULL)
		return false;

	counters->per_client_regex_MAX = size;

	/****************************** shared fifo_buffer struct ******************************/
	// Try to create shared memory object
	create_shm(SHARED_FIFO_LOG_NAME, &shm_fifo_log, sizeof(fifologData));
	if(shm_fifo_log.ptr == NULL)
		return false;
	fifo_log = (fifologData*)shm_fifo_log.ptr;

	/****************************** shared clients_lookup struct ******************************/
	size = get_optimal_object_size(sizeof(struct lookup_table), 1);
	// Try to create shared memory object
	create_shm(SHARED_CLIENTS_LOOKUP_NAME, &shm_clients_lookup, size*sizeof(struct lookup_table));
	if(shm_clients_lookup.ptr == NULL)
		return false;
	clients_lookup = (struct lookup_table*)shm_clients_lookup.ptr;
	counters->clients_lookup_MAX = size;

	/****************************** shared domains_lookup struct ******************************/
	size = get_optimal_object_size(sizeof(struct lookup_table), 1);
	// Try to create shared memory object
	create_shm(SHARED_DOMAINS_LOOKUP_NAME, &shm_domains_lookup, size*sizeof(struct lookup_table));
	if(shm_domains_lookup.ptr == NULL)
		return false;
	domains_lookup = (struct lookup_table*)shm_domains_lookup.ptr;
	counters->domains_lookup_MAX = size;

	/****************************** shared dns_cache_lookup struct ******************************/
	size = get_optimal_object_size(sizeof(struct lookup_table), 1);
	// Try to create shared memory object
	create_shm(SHARED_DNS_CACHE_LOOKUP_NAME, &shm_dns_cache_lookup, size*sizeof(struct lookup_table));
	if(shm_dns_cache_lookup.ptr == NULL)
		return false;
	dns_cache_lookup = (struct lookup_table*)shm_dns_cache_lookup.ptr;
	counters->dns_cache_lookup_MAX = size;

	/****************************** shared recycler struct ******************************/
	// Try to create shared memory object
	create_shm(SHARED_RECYCLER_NAME, &shm_recycler, sizeof(struct recycler_tables));
	if(shm_recycler.ptr == NULL)
		return false;
	recycler = (struct recycler_tables*)shm_recycler.ptr;

	return true;
}

// CHOWN all shared memory objects to supplied user/group
void chown_all_shmem(struct passwd *ent_pw)
{
	for(unsigned int i = 0; i < ArraySize(sharedMemories); i++)
		chown_shmem(sharedMemories[i], ent_pw);
}

// Destroy mutex and, subsequently, delete all shared memory objects
void destroy_shmem(void)
{
	// First, we destroy the mutex
	if(shmLock != NULL)
	{
		pthread_mutex_destroy(&shmLock->lock.inner);
		pthread_mutex_destroy(&shmLock->lock.outer);
	}
	shmLock = NULL;

	// Then, we delete the shared memory objects
	for(unsigned int i = 0; i < ArraySize(sharedMemories); i++)
		delete_shm(sharedMemories[i]);
}

/// Create shared memory
///
/// \param suffix the suffix of the shared memory's name
/// \param sharedMemory the shared memory object to fill
/// \param size the size to allocate
/// No return value as the function will exit on failure
static bool create_shm(const char *suffix, SharedMemory *sharedMemory, const size_t size)
{
	// Generate an individual shm name for this process by using the PID
	const size_t namelen = strlen(suffix) + 24;
	char *name = calloc(namelen, sizeof(char));
	if(name == NULL)
	{
		log_err("create_shm(): Failed to allocate memory for shared memory name");
		exit(EXIT_FAILURE);
	}
	snprintf(name, namelen, "/FTL-%d-%s", getpid(), suffix);

	char df[64] = { 0 };
	const unsigned int percentage = get_dev_shm_usage(df);
	if(config.debug.shmem.v.b || (config.misc.check.shmem.v.ui > 0 && percentage > config.misc.check.shmem.v.ui))
		log_info("Creating shared memory with name \"%s\" and size %zu (%s)", name, size, df);

	if(config.misc.check.shmem.v.ui > 0 && percentage > config.misc.check.shmem.v.ui)
		log_resource_shortage(-1.0, 0, percentage, -1, SHMEM_PATH, df);

	// Initialize shared memory object
	sharedMemory->name = name;
	sharedMemory->size = size;
	sharedMemory->ptr = NULL;

	// Create the shared memory file in read/write mode with 600 (u+rw) permissions
	// and the following open flags:
	// - O_RDWR: Open the object for read-write access (we need to be able to modify the locks)
	// - O_CREAT: Create the shared memory object if it does not exist.
	// - O_EXCL: Return an error if a shared memory object with the given name already exists.
	errno = 0;
	sharedMemory->fd = shm_open(sharedMemory->name, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);

	// Check for `shm_open` error
	if(sharedMemory->fd == -1)
	{
		log_err("create_shm(): Failed to create shared memory object \"%s\": %s",
		        name, strerror(errno));
		return sharedMemory;
	}

	// Create exclusive file lock on shared memory object
	// The lock will be automatically released when the file descriptor is closed
	sharedMemory->lock.l_type = F_WRLCK; // write = exclusive lock
	sharedMemory->lock.l_whence = SEEK_SET;
	sharedMemory->lock.l_start = 0; // lock everything from the start ...
	sharedMemory->lock.l_len = 0; // ... to the end of the file (magic 0 = EOF)

	// Try to lock the shared memory object
	if(fcntl(sharedMemory->fd, F_SETLK, &sharedMemory->lock) == -1)
	{
		log_err("create_shm(): Failed to exclusively lock shared memory object \"%s\": %s",
		        name, strerror(errno));
		close(sharedMemory->fd);
		return sharedMemory;
	}

	// Allocate shared memory object to specified size
	// Using f[tl]allocate() will ensure that there's actually space for
	// this file. Otherwise we end up with a sparse file that can give
	// SIGBUS if we run out of space while writing to it.
	const int ret = ftlallocate(sharedMemory->fd, 0U, size);
	if(ret != 0)
	{
		log_err("create_shm(): Failed to resize \"%s\" (%i) to %zu: %s (%i)",
		        sharedMemory->name, sharedMemory->fd, size, strerror(errno), ret);
		exit(EXIT_FAILURE);
	}

	// Update how much memory FTL uses
	// We only add here as this is a new file
	used_shmem += size;

	// Create shared memory mapping
	void *shm = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, sharedMemory->fd, 0);

	// Check for `mmap` error
	if(shm == MAP_FAILED)
	{
		log_err("create_shm(): Failed to map shared memory object \"%s\" (%i): %s",
		        sharedMemory->name, sharedMemory->fd, strerror(errno));
		return sharedMemory;
	}

	// Initialize shared memory object to zero
	memset(shm, 0, size);

	sharedMemory->ptr = shm;
	return sharedMemory;
}

static void *enlarge_shmem_struct(const char type)
{
	SharedMemory *sharedMemory = NULL;
	size_t sizeofobj, allocation_step;
	unsigned int *size = NULL;

	// Select type of struct that should be enlarged
	switch(type)
	{
		case QUERIES:
			sharedMemory = &shm_queries;
			allocation_step = pagesize;
			sizeofobj = sizeof(queriesData);
			size = &counters->queries_MAX;
			break;
		case CLIENTS:
			sharedMemory = &shm_clients;
			allocation_step = get_optimal_object_size(sizeof(clientsData), 1);
			sizeofobj = sizeof(clientsData);
			size = &counters->clients_MAX;
			break;
		case DOMAINS:
			sharedMemory = &shm_domains;
			allocation_step = get_optimal_object_size(sizeof(domainsData), 1);
			sizeofobj = sizeof(domainsData);
			size = &counters->domains_MAX;
			break;
		case UPSTREAMS:
			sharedMemory = &shm_upstreams;
			allocation_step = get_optimal_object_size(sizeof(upstreamsData), 1);
			sizeofobj = sizeof(upstreamsData);
			size = &counters->upstreams_MAX;
			break;
		case DNS_CACHE:
			sharedMemory = &shm_dns_cache;
			allocation_step = get_optimal_object_size(sizeof(DNSCacheData), 1);
			sizeofobj = sizeof(DNSCacheData);
			size = &counters->dns_cache_MAX;
			break;
		case STRINGS:
			sharedMemory = &shm_strings;
			allocation_step = STRINGS_ALLOC_STEP;
			sizeofobj = 1;
			size = &counters->strings_MAX;
			break;
		case CLIENTS_LOOKUP:
			sharedMemory = &shm_clients_lookup;
			allocation_step = get_optimal_object_size(sizeof(struct lookup_table), 1);
			sizeofobj = sizeof(struct lookup_table);
			size = &counters->clients_lookup_MAX;
			break;
		case DOMAINS_LOOKUP:
			sharedMemory = &shm_domains_lookup;
			allocation_step = get_optimal_object_size(sizeof(struct lookup_table), 1);
			sizeofobj = sizeof(struct lookup_table);
			size = &counters->domains_lookup_MAX;
			break;
		case DNS_CACHE_LOOKUP:
			sharedMemory = &shm_dns_cache_lookup;
			allocation_step = get_optimal_object_size(sizeof(struct lookup_table), 1);
			sizeofobj = sizeof(struct lookup_table);
			size = &counters->dns_cache_lookup_MAX;
			break;
		default:
			log_err("Invalid argument in enlarge_shmem_struct(%i)", type);
			return 0;
	}

	// Reallocate enough space for requested object
	const size_t current = sharedMemory->size/sizeofobj;
	realloc_shm(sharedMemory, current + allocation_step, sizeofobj, true);

	// Add allocated memory to corresponding size
	*size += allocation_step;

	return sharedMemory->ptr;
}

static bool realloc_shm(SharedMemory *sharedMemory, const size_t size1, const size_t size2, const bool resize)
{
	// Absolute target size
	const size_t size = size1 * size2;

	// Log that we are doing something here
	char df[64] =  { 0 };
	const unsigned int percentage = get_dev_shm_usage(df);

	// Log output
	if(resize)
	{
		log_debug(DEBUG_SHMEM, "Resizing \"%s\" from %zu to (%zu * %zu) == %zu (%s)",
		          sharedMemory->name, sharedMemory->size, size1, size2, size, df);
	}
	else
	{
		log_debug(DEBUG_SHMEM, "Remapping \"%s\" from %zu to (%zu * %zu) == %zu",
		          sharedMemory->name, sharedMemory->size, size1, size2, size);
	}

	if(config.misc.check.shmem.v.ui > 0 && percentage > config.misc.check.shmem.v.ui)
		log_resource_shortage(-1.0, 0, percentage, -1, SHMEM_PATH, df);

	// Resize shard memory object if requested
	// If not, we only remap a shared memory object which might have changed
	// in another process. This happens when pihole-FTL forks due to incoming
	// TCP requests.
	if(resize)
	{
		// Allocate shared memory object to specified size
		// Using f[tl]allocate() will ensure that there's actually space for
		// this file. Otherwise we end up with a sparse file that can give
		// SIGBUS if we run out of space while writing to it.
		const int ret = ftlallocate(sharedMemory->fd, 0U, size);
		if(ret != 0)
		{
			log_crit("realloc_shm(): Failed to resize \"%s\" (%i) to %zu: %s (%i)",
			         sharedMemory->name, sharedMemory->fd, size, strerror(ret), ret);
			exit(EXIT_FAILURE);
		}

		// Update shm counters to indicate that at least one shared memory object changed
		shmSettings->global_shm_counter++;
		local_shm_counter++;
	}

	void *new_ptr = mremap(sharedMemory->ptr, sharedMemory->size, size, MREMAP_MAYMOVE);
	if(new_ptr == MAP_FAILED)
	{
		log_crit("realloc_shm(): mremap(%p, %zu, %zu, MREMAP_MAYMOVE): Failed to reallocate \"%s\": %s",
		         sharedMemory->ptr, sharedMemory->size, size, sharedMemory->name, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Update how much memory FTL uses
	// We add the difference between updated and previous size
	used_shmem += (size - sharedMemory->size);

	if(sharedMemory->ptr == new_ptr)
	{
		log_debug(DEBUG_SHMEM, "SHMEM pointer not updated: %p (%zu %zu)",
		          sharedMemory->ptr, sharedMemory->size, size);
	}
	else
	{
		log_debug(DEBUG_SHMEM, "SHMEM pointer updated: %p -> %p (%zu %zu)",
		          sharedMemory->ptr, new_ptr, sharedMemory->size, size);
	}

	sharedMemory->ptr = new_ptr;
	sharedMemory->size = size;

	return true;
}

static void delete_shm(SharedMemory *sharedMemory)
{
	// Unmap shared memory (if mmapped)
	if(sharedMemory->ptr != NULL)
	{
		// Unmap global pointers
		for(unsigned int i = 0; i < ArraySize(global_pointers); i++)
		{
			log_debug(DEBUG_SHMEM, "Pointer comparison at pos. %u: %p == %p", i, *global_pointers[i], sharedMemory->ptr);
			if(*global_pointers[i] == sharedMemory->ptr)
			{
				log_debug(DEBUG_SHMEM, "Unmapping global pointer %s at %p", sharedMemory->name, *global_pointers[i]);
				*global_pointers[i] = NULL;
				break;
			}
		}
		if(munmap(sharedMemory->ptr, sharedMemory->size) != 0)
			log_warn("delete_shm(): munmap(%p, %zu) failed: %s",
			         sharedMemory->ptr, sharedMemory->size, strerror(errno));
	}

	// Set unmapped pointer to NULL
	sharedMemory->ptr = NULL;

	// Close shared memory file descriptor
	if(close(sharedMemory->fd) != 0)
		log_warn("delete_shm(): close(%i) failed: %s", sharedMemory->fd, strerror(errno));
	sharedMemory->fd = -1;

	// Now you can no longer `shm_open` the memory, and once all others
	// unlink, it will be destroyed.
	if(shm_unlink(sharedMemory->name) != 0)
		log_warn("delete_shm(): shm_unlink(%s) failed: %s",
		         sharedMemory->name, strerror(errno));

	// Free the shared memory name
	free(sharedMemory->name);
}

// Euclidean algorithm to return greatest common divisor of the numbers
static size_t __attribute__((const)) gcd(size_t a, size_t b)
{
	while(b != 0)
	{
		size_t temp = b;
		b = a % b;
		a = temp;
	}
	return a;
}

// Function to return the optimal (minimum) size for page-aligned
// shared memory objects. This routine works by computing the LCM
// of two numbers, the pagesize and the size of a single element
// in the shared memory object
static size_t get_optimal_object_size(const size_t objsize, const size_t minsize)
{
	// optsize and minsize are in units of objsize
	const size_t optsize = pagesize / gcd(pagesize, objsize);
	if(optsize < minsize)
	{
		log_debug(DEBUG_SHMEM, "LCM(%i, %zu) == %zu < %zu",
		          pagesize, objsize,
		          optsize*objsize,
		          minsize*objsize);

		// Upscale optimal size by a certain factor
		// Logic of this computation:
		// First part: Integer division, may cause clipping, e.g., 5/3 = 1
		// Second part: Catch a possibly happened clipping event by adding
		//              one to the number: (5 % 3 != 0) is 1
		const size_t multiplier = (minsize/optsize) + ((minsize % optsize != 0) ? 1u : 0u);

		log_debug(DEBUG_SHMEM, "Using %zu*%zu == %zu >= %zu",
		          multiplier, optsize*objsize,
		          multiplier*optsize*objsize,
		          minsize*objsize);

		// As optsize ensures perfect page-alignment,
		// any multiple of it will be aligned as well
		return multiplier*optsize;
	}
	else
	{
		log_debug(DEBUG_SHMEM, "LCM(%i, %zu) == %zu >= %zu",
		          pagesize, objsize,
		          optsize*objsize,
		          minsize*objsize);

		// Return computed optimal size
		return optsize;
	}
}

// Enlarge shared memory to be able to hold at least one new record
void shm_ensure_size(void)
{
	if(counters->queries >= counters->queries_MAX-1)
	{
		// Have to reallocate shared memory
		queries = enlarge_shmem_struct(QUERIES);
		if(queries == NULL)
		{
			log_crit("Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->upstreams >= counters->upstreams_MAX-1)
	{
		// Have to reallocate shared memory
		upstreams = enlarge_shmem_struct(UPSTREAMS);
		if(upstreams == NULL)
		{
			log_crit("Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->clients >= counters->clients_MAX-1)
	{
		// Have to reallocate shared memory
		clients = enlarge_shmem_struct(CLIENTS);
		if(clients == NULL)
		{
			log_crit("Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->domains >= counters->domains_MAX-1)
	{
		// Have to reallocate shared memory
		domains = enlarge_shmem_struct(DOMAINS);
		if(domains == NULL)
		{
			log_crit("Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->dns_cache_size >= counters->dns_cache_MAX-1)
	{
		// Have to reallocate shared memory
		dns_cache = enlarge_shmem_struct(DNS_CACHE);
		if(dns_cache == NULL)
		{
			log_crit("Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(shmSettings->next_str_pos + STRINGS_ALLOC_STEP >= shm_strings.size)
	{
		// Have to reallocate shared memory
		if(enlarge_shmem_struct(STRINGS) == NULL)
		{
			log_crit("Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->clients_lookup_size >= counters->clients_lookup_MAX-1)
	{
		// Have to reallocate shared memory
		clients_lookup = enlarge_shmem_struct(CLIENTS_LOOKUP);
		if(clients_lookup == NULL)
		{
			log_crit("Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->domains_lookup_size >= counters->domains_lookup_MAX-1)
	{
		// Have to reallocate shared memory
		domains_lookup = enlarge_shmem_struct(DOMAINS_LOOKUP);
		if(domains_lookup == NULL)
		{
			log_crit("Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->dns_cache_lookup_size >= counters->dns_cache_lookup_MAX-1)
	{
		// Have to reallocate shared memory
		dns_cache_lookup = enlarge_shmem_struct(DNS_CACHE_LOOKUP);
		if(dns_cache_lookup == NULL)
		{
			log_crit("Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
}

void reset_per_client_regex(const unsigned int clientID)
{
	const unsigned int num_regex_tot = get_num_regex(REGEX_MAX); // total number
	for(unsigned int i = 0u; i < num_regex_tot; i++)
	{
		// Zero-initialize/reset (= false) all regex (allow + deny)
		set_per_client_regex(clientID, i, false);
	}
}

void add_per_client_regex(const unsigned int clientID)
{
	const unsigned int num_regex_tot = get_num_regex(REGEX_MAX); // total number
	const size_t size = get_optimal_object_size(1, (size_t)counters->clients * num_regex_tot);
	if(size > shm_per_client_regex.size &&
	   realloc_shm(&shm_per_client_regex, 1, size, true))
	{
		reset_per_client_regex(clientID);
		counters->per_client_regex_MAX = size;
	}
}

bool get_per_client_regex(const unsigned int clientID, const unsigned int regexID)
{
	const unsigned int num_regex_tot = get_num_regex(REGEX_MAX); // total number
	const unsigned int id = clientID * num_regex_tot + regexID;
	const size_t maxval = shm_per_client_regex.size / sizeof(bool);
	if(id > maxval)
	{
		log_err("get_per_client_regex(%u, %u): Out of bounds (%u > %u * %u, shm_per_client_regex.size = %zu)!",
		        clientID, regexID,
		        id, counters->clients, num_regex_tot, maxval);
		return false;
	}
	return ((bool*) shm_per_client_regex.ptr)[id];
}

void set_per_client_regex(const unsigned int clientID, const unsigned int regexID, const bool value)
{
	const unsigned int num_regex_tot = get_num_regex(REGEX_MAX); // total number
	const unsigned int id = clientID * num_regex_tot + regexID;
	const size_t maxval = shm_per_client_regex.size / sizeof(bool);
	if(id > maxval)
	{
		log_err("set_per_client_regex(%u, %u, %s): Out of bounds (%u > %u * %u, shm_per_client_regex.size = %zu)!",
		        clientID, regexID, value ? "true" : "false",
		        id, counters->clients, num_regex_tot, maxval);
		return;
	}
	((bool*) shm_per_client_regex.ptr)[id] = value;
}

static inline bool check_range(unsigned int ID, unsigned int MAXID, const char *type, const char *func, int line, const char *file)
{
	// Check bounds
	if(ID > MAXID)
	{
		if(debug_flags[DEBUG_ANY])
		{
			log_err("Trying to access %s ID %u, but maximum is %u", type, ID, MAXID);
			log_err("found in %s() (%s:%i)", func, short_path(file), line);
		}
		return false;
	}

	// Everything okay
	return true;
}

static inline bool check_magic(const unsigned int ID, const bool checkMagic, const unsigned char magic, const char *type, const char *func, const int line, const char *file)
{
	// Check magic only if requested (skipped for new entries which are uninitialized)
	if(checkMagic && magic != MAGICBYTE)
	{
		if(debug_flags[DEBUG_ANY])
		{
			log_err("Trying to access %s ID %u, but magic byte is %x", type, ID, magic);
			log_err("found in %s() (%s:%i)", func, short_path(file), line);
		}
		return false;
	}

	// Everything okay
	return true;
}

queriesData *_getQuery(const unsigned int queryID, const bool checkMagic, const int line, const char *func, const char *file)
{
	// We are not in a locked situation, return a NULL pointer
	if(config.debug.locks.v.b && !is_our_lock())
	{
		if(debug_flags[DEBUG_ANY])
		{
			log_err("Tried to obtain query pointer without lock in %s() (%s:%i)!",
			        func, short_path(file), line);
			generate_backtrace();
		}
		return NULL;
	}

	// Check allowed range
	if(!check_range(queryID, counters->queries_MAX, "query", func, line, file))
		return NULL;

	// May have been recycled, do not return recycled queries if we are checking
	// the magic byte
	if(checkMagic && queries[queryID].magic == 0x00)
		return NULL;

	// Check magic byte
	if(check_magic(queryID, checkMagic, queries[queryID].magic, "query", func, line, file))
		return &queries[queryID];

	return NULL;
}

clientsData *_getClient(const unsigned int clientID, const bool checkMagic, const int line, const char *func, const char *file)
{
	// We are not in a locked situation, return a NULL pointer
	if(config.debug.locks.v.b && !is_our_lock())
	{
		if(debug_flags[DEBUG_ANY])
		{
			log_err("Tried to obtain client pointer without lock in %s() (%s:%i)!",
			        func, short_path(file), line);
			generate_backtrace();
		}
		return NULL;
	}

	// Check allowed range
	if(!check_range(clientID, counters->clients_MAX, "client", func, line, file))
		return NULL;

	// May have been recycled, do not return recycled clients if we are checking
	// the magic byte
	if(checkMagic && clients[clientID].magic == 0x00)
		return NULL;

	// Check magic byte
	if(check_magic(clientID, checkMagic, clients[clientID].magic, "client", func, line, file))
		return &clients[clientID];

	return NULL;
}

domainsData *_getDomain(const unsigned int domainID, const bool checkMagic, const int line, const char *func, const char *file)
{
	// We are not in a locked situation, return a NULL pointer
	if(config.debug.locks.v.b && !is_our_lock())
	{
		if(debug_flags[DEBUG_ANY])
		{
			log_err("Tried to obtain domain pointer without lock in %s() (%s:%i)!",
			        func, short_path(file), line);
			generate_backtrace();
		}
		return NULL;
	}

	// Check allowed range
	if(!check_range(domainID, counters->domains_MAX, "domain", func, line, file))
		return NULL;

	// May have been recycled, do not return recycled domains if we are checking
	// the magic byte
	if(checkMagic && domains[domainID].magic == 0x00)
		return NULL;

	// Check magic byte
	if(check_magic(domainID, checkMagic, domains[domainID].magic, "domain", func, line, file))
		return &domains[domainID];

	return NULL;
}

upstreamsData *_getUpstream(const unsigned int upstreamID, const bool checkMagic, const int line, const char *func, const char *file)
{
	// We are not in a locked situation, return a NULL pointer
	if(config.debug.locks.v.b && !is_our_lock())
	{
		if(debug_flags[DEBUG_ANY])
		{
			log_err("Tried to obtain upstream pointer without lock in %s() (%s:%i)!",
			        func, short_path(file), line);
			generate_backtrace();
		}
		return NULL;
	}

	// Check allowed range
	if(!check_range(upstreamID, counters->upstreams_MAX, "upstream", func, line, file))
		return NULL;

	// May have been recycled, do not return recycled upstreams if we are checking
	// the magic byte
	if(checkMagic && upstreams[upstreamID].magic == 0x00)
		return NULL;

	// Check magic byte
	if(check_magic(upstreamID, checkMagic, upstreams[upstreamID].magic, "upstream", func, line, file))
		return &upstreams[upstreamID];

	return NULL;
}

DNSCacheData *_getDNSCache(const unsigned int cacheID, const bool checkMagic, const int line, const char *func, const char *file)
{
	// We are not in a locked situation, return a NULL pointer
	if(config.debug.locks.v.b && !is_our_lock())
	{
		if(debug_flags[DEBUG_ANY])
		{
			log_err("Tried to obtain cache pointer without lock in %s() (%s:%i)!",
			        func, short_path(file), line);
			generate_backtrace();
		}
		return NULL;
	}

	// Check allowed range
	if(!check_range(cacheID, counters->dns_cache_MAX, "dns_cache", func, line, file))
		return NULL;

	// May have been recycled, do not return recycled upstreams if we are checking
	// the magic byte
	if(checkMagic && dns_cache[cacheID].magic == 0x00)
		return NULL;

	// Check magic byte
	if(check_magic(cacheID, checkMagic, dns_cache[cacheID].magic, "dns_cache", func, line, file))
		return &dns_cache[cacheID];

	return NULL;
}

// Return 1 if this fd is associated with any shared memory object to avoid
// dnsmasq closing it during initialization
int __attribute__((pure)) is_shm_fd(const int fd)
{
	// Check all shared memory objects
	for(unsigned int i = 0; i < ArraySize(sharedMemories); i++)
		if(sharedMemories[i]->fd == fd)
			return 1;

	// Not found
	return 0;
}

// Update queries per second (qps) value
// This is done in shared memory to allow for both UDP and TCP workers to
// contribute.
void update_qps(const time_t timestamp)
{
	// Get the timeslot for the current timestamp
	const unsigned int slot = timestamp % QPS_AVGLEN;

	// Add the query
	shmSettings->qps[slot]++;
}

// Reset queries per second (qps) value for the timeslot following the current
// one
void reset_qps(const time_t timestamp)
{
	// Get the timeslot for the current timestamp
	const unsigned int slot = (timestamp + 1) % QPS_AVGLEN;

	// Reset the query count
	shmSettings->qps[slot] = 0;
}

// Compute queries per second (qps) value
double __attribute__((pure)) get_qps(void)
{
	// Compute the arithmetic mean of all slots
	//        1  N
	// QPS = --- Σ buf[i]
	//        N  i=0
	//
	double qps = 0.0;
	for(unsigned int i = 0; i < QPS_AVGLEN; i++)
		qps += shmSettings->qps[i];

	// Return the computed value divided by N (the number of slots)
	return qps / QPS_AVGLEN;
}

/**
 * @brief Retrieves the recycle table based on the specified memory type.
 *
 * This function returns a pointer to the appropriate recycle table
 * corresponding to the given memory type. The memory types can be
 * CLIENTS, DOMAINS, or DNS_CACHE. If the memory type does not match
 * any of these, the function returns NULL.
 *
 * @param type The memory type for which the recycle table is requested.
 *             It can be one of the following:
 *             - CLIENTS: Recycle table for clients.
 *             - DOMAINS: Recycle table for domains.
 *             - DNS_CACHE: Recycle table for DNS cache.
 * @param name A pointer to a string that will be set to the name of the
 *             recycle table corresponding to the given memory type.
 *
 * @return A pointer to the recycle table corresponding to the given
 *         memory type, or NULL if the memory type is not recognized.
 */
static struct recycle_table *get_recycle_table(const enum memory_type type, const char **name)
{
	if(type == CLIENTS)
	{
		*name = "clients";
		return &recycler->client;
	}
	else if(type == DOMAINS)
	{
		*name = "domains";
		return &recycler->domain;
	}
	else if(type == DNS_CACHE)
	{
		*name = "dns_cache";
		return &recycler->dns_cache;
	}

	return NULL;
}

/**
 * @brief Sets the next recycled ID for a given memory type.
 *
 * This function adds a new ID to the recycle table for the specified memory type.
 * If the recycle table is full or the memory type is invalid, the function will
 * log an appropriate message and return false.
 *
 * @param type The memory type for which the ID is being set.
 * @param id The ID to be added to the recycle table.
 * @return true if the ID was successfully added to the recycle table, false otherwise.
 */
bool set_next_recycled_ID(const enum memory_type type, const unsigned int id)
{
	// Get the correct table
	const char *name = NULL;
	struct recycle_table *rp = get_recycle_table(type, &name);

	if(rp == NULL)
	{
		log_err("set_next_recycled_ID(): Invalid memory type %i", type);
		return false;
	}

	// Check if we already have the maximum number of recycled entries
	if(rp->count >= RECYCLE_ARRAY_LEN)
	{
		// This is not strictly an error, but it is worth noting if in
		// debug mode as increasing RECYCLE_ARRAY_LEN may be useful in
		// this environment
		log_debug(DEBUG_SHMEM, "set_next_recycled_ID(): Recycle table[%s] is full", name);
		return false;
	}

	log_debug(DEBUG_GC, "RECYCLE[%s][%u] = %u SET", name, rp->count, id);

	// Set the id of the recycled entry and increment the count
	rp->id[rp->count] = id;
	rp->count++;

	return true;
}

/**
 * @brief Retrieves the next recycled ID from the recycle table for the specified memory type.
 *
 * This function fetches the next available recycled ID from the recycle table associated with the given memory type.
 * If there are no recycled IDs available or the memory type is invalid, the function returns false.
 *
 * @param type The memory type for which to retrieve the recycled ID.
 * @param id A pointer to an unsigned int where the retrieved recycled ID will be stored.
 * @return true if a recycled ID was successfully retrieved, false otherwise.
 */
bool get_next_recycled_ID(const enum memory_type type, unsigned int *id)
{
	// Get the correct table
	const char *name = NULL;
	struct recycle_table *rp = get_recycle_table(type, &name);

	if(rp == NULL)
	{
		log_err("get_next_recycled_ID(): Invalid memory type %i", type);
		return false;
	}


	// Check if we have any recycled entries
	if(rp->count == 0)
	{
		log_debug(DEBUG_GC, "RECYCLE[%s] is empty", name);
		return false;
	}

	// Take one away from the array
	rp->count--;

	// Get the ID of the recycled entry and decrement the count
	*id = rp->id[rp->count];

	// Unset the ID of the element just used
	rp->id[rp->count] = 0;

	log_debug(DEBUG_GC, "RECYCLE[%s][%u] = %u TAKE", name, rp->count, *id);

	return true;
}

/**
 * @brief Logs the fullness of various recycle lists.
 *
 * This function logs the fullness of the recycle lists for clients, domains,
 * and DNS cache. It provides the current count, the maximum capacity, and the
 * percentage of fullness for each list.
 *
 */
void print_recycle_list_fullness(void)
{
	log_info("Recycle list fullness:");
	log_info("  Clients: %u/%u (%.2f%%)", recycler->client.count, RECYCLE_ARRAY_LEN, (double)recycler->client.count / RECYCLE_ARRAY_LEN * 100.0);
	log_info("  Domains: %u/%u (%.2f%%)", recycler->domain.count, RECYCLE_ARRAY_LEN, (double)recycler->domain.count / RECYCLE_ARRAY_LEN * 100.0);
	log_info("  DNS Cache: %u/%u (%.2f%%)", recycler->dns_cache.count, RECYCLE_ARRAY_LEN, (double)recycler->dns_cache.count / RECYCLE_ARRAY_LEN * 100.0);
}

/**
 * @brief Dumps the string table to a temporary file.
 *
 * This function iterates over the string table and writes each string to a temporary file
 * located at "/tmp/stringdump.txt". It checks if each string is printable and escapes
 * non-printable strings before writing them to the file. Additionally, it logs the number
 * of non-printable strings and includes a human-readable timestamp in the output.
 *
 * The format of each line in the output file is:
 * "    " or "NONP" <string_index>: "<string_content>" (<current_position>/<string_length>)
 *
 * If the file cannot be opened for writing, an error message is logged.
 */
#define STRING_DUMPFILE "/tmp/stringdump.txt"
void dump_strings(void)
{
	// Dump string table to temporary file
	FILE *str_dumpfile = fopen(STRING_DUMPFILE, "a");
	if(str_dumpfile != NULL)
	{
		char timestring[TIMESTR_SIZE] = { 0 };
		get_timestr(timestring, time(NULL), true, false);
		fprintf(str_dumpfile, "String dump starting at %s\n", timestring);
		log_info("String dump to "STRING_DUMPFILE);

		size_t j = 0, non_print = 0;
		for(size_t i = 0; i < shmSettings->next_str_pos; i++)
		{
			char *sstr = (char*)getstr(i);
			const size_t len = strlen(sstr);
			char *buffer = sstr;
			i += len;
			j++;

			// Check if the string is printable
			bool string_is_printable = true;
			for(size_t k = 0; k < len; k++)
			{
				if(!isprint(sstr[k]))
				{
					string_is_printable = false;
					non_print++;
					break;
				}
			}

			// If the string is not printable, we escape it
			if(!string_is_printable)
				buffer = escape_data(sstr, len);

			// Print string to file
			fprintf(str_dumpfile, "%s %04zu: \"%s\" (%zu/%zu)\n", string_is_printable ? "    " : "NONP",
			        j, buffer, i, len);

			// Free buffer if it was allocated
			if(!string_is_printable)
				free(buffer);
		}

		// Print human-readable timestamp and number of strings which are not printable
		fprintf(str_dumpfile, "Summary: %zu strings\n", j);
		fprintf(str_dumpfile, "         %zu non-printable strings\n", non_print);
		fprintf(str_dumpfile, "\n");

		// Close file
		fclose(str_dumpfile);
	}
	else
		log_err("Cannot open "STRING_DUMPFILE" for writing: %s", strerror(errno));
}
