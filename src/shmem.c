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
#include "config.h"
// data getter functions
#include "datastructure.h"
// get_num_regex()
#include "regex_r.h"
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

/// The version of shared memory used
#define SHARED_MEMORY_VERSION 14

/// The name of the shared memory. Use this when connecting to the shared memory.
#define SHMEM_PATH "/dev/shm"
#define SHARED_LOCK_NAME "FTL-lock"
#define SHARED_STRINGS_NAME "FTL-strings"
#define SHARED_COUNTERS_NAME "FTL-counters"
#define SHARED_DOMAINS_NAME "FTL-domains"
#define SHARED_CLIENTS_NAME "FTL-clients"
#define SHARED_QUERIES_NAME "FTL-queries"
#define SHARED_UPSTREAMS_NAME "FTL-upstreams"
#define SHARED_OVERTIME_NAME "FTL-overTime"
#define SHARED_SETTINGS_NAME "FTL-settings"
#define SHARED_DNS_CACHE "FTL-dns-cache"
#define SHARED_PER_CLIENT_REGEX "FTL-per-client-regex"

// Allocation step for FTL-strings bucket. This is somewhat special as we use
// this as a general-purpose storage which should always be large enough. If,
// for some reason, more data than this step has to be stored (highly unlikely,
// close to impossible), the data will be properly truncated and we try again in
// the next lock round
#define STRINGS_ALLOC_STEP (10*pagesize)

// Global counters struct
countersStruct *counters = NULL;

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
                                          &shm_per_client_regex };
#define NUM_SHMEM (sizeof(sharedMemories)/sizeof(SharedMemory*))

// Variable size array structs
static queriesData *queries = NULL;
static clientsData *clients = NULL;
static domainsData *domains = NULL;
static upstreamsData *upstreams = NULL;
static DNSCacheData *dns_cache = NULL;

typedef struct {
	struct {
		pthread_mutex_t outer;
		pthread_mutex_t inner;
	} lock;
	struct {
		volatile pid_t pid;
		volatile pid_t tid;
	} owner;
} ShmLock;
static ShmLock *shmLock = NULL;
static ShmSettings *shmSettings = NULL;

static int pagesize;
static unsigned int local_shm_counter = 0;
static size_t used_shmem = 0u;
static size_t get_optimal_object_size(const size_t objsize, const size_t minsize);

// Private prototypes
static void *enlarge_shmem_struct(const char type);

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
	if(fd == -1)
	{
		logg("FATAL: chown_shmem(): Failed to open shared memory object \"%s\": %s",
			sharedMemory->name, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if(fchown(fd, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
	{
		logg("WARNING: chown_shmem(%d, %d, %d): failed for %s: %s (%d)",
		     fd, ent_pw->pw_uid, ent_pw->pw_gid, sharedMemory->name,
		     strerror(errno), errno);
		return false;
	}
	logg("Changing %s (%d) to %d:%d", sharedMemory->name, fd, ent_pw->pw_uid, ent_pw->pw_gid);
	// Close shared memory object file descriptor as it is no longer
	// needed after having called ftruncate()
	close(fd);
	return true;
}

// A function that duplicates a string and replaces all characters "s" by "r"
static char *__attribute__ ((malloc)) str_replace(const char *input,
                                                  const char s,
                                                  const char r,
                                                  unsigned int *N)
{
	// Duplicate string
	char *copy = strdup(input);
	if(!copy)
		return NULL;

	// Woring pointer
	char *ix = copy;
	// Loop over string until there are no further "s" chars in the string
	while((ix = strchr(ix, s)) != NULL)
	{
		*ix++ = r;
		(*N)++;
	}

	return copy;
}

char *__attribute__ ((malloc)) str_escape(const char *input, unsigned int *N)
{
	// If no escaping is done, this routine returns the original pointer
	// and N stays 0
	*N = 0;
	if(strchr(input, ' ') != NULL)
	{
		// Replace any spaces by ~ if we find them in the domain name
		// This is necessary as our telnet API uses space delimiters
		return str_replace(input, ' ', '~', N);
	}

	return strdup(input);
}

bool strcmp_escaped(const char *a, const char *b)
{
	unsigned int Na, Nb;

	// Input check
	if(a == NULL || b == NULL)
		return false;

	// Escape both inputs
	char *aa = str_escape(a, &Na);
	char *bb = str_escape(b, &Nb);

	// Check for memory errors
	if(!aa || !bb)
	{
		if(aa) free(aa);
		if(bb) free(bb);
		return false;
	}

	const char result = strcasecmp(aa, bb) == 0;

	free(aa);
	free(bb);

	return result;
}


size_t addstr(const char *input)
{
	if(input == NULL)
	{
		logg("WARN: Called addstr() with NULL pointer");
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
		logg("WARN: Shortening too long string (len %zu > pagesize %i)", len, pagesize);
		len = pagesize;
	}
	else if(len > (size_t)(avail_mem-1))
	{
		logg("WARN: Shortening too long string (len %zu > available memory %zu)", len, avail_mem);
		len = avail_mem;
	}

	unsigned int N = 0;
	char *str = str_escape(input, &N);

	if(N > 0)
		logg("INFO: FTL replaced %u invalid characters with ~ in the query \"%s\"", N, str);

	// Debugging output
	if(config.debug & DEBUG_SHMEM)
		logg("Adding \"%s\" (len %zu) to buffer. next_str_pos is %u", str, len, shmSettings->next_str_pos);

	// Copy the C string pointed by str into the shared string buffer
	strncpy(&((char*)shm_strings.ptr)[shmSettings->next_str_pos], str, len);
	free(str);

	// Increment string length counter
	shmSettings->next_str_pos += len;

	// Return start of stored string
	return (shmSettings->next_str_pos - len);
}

const char *_getstr(const size_t pos, const char *func, const int line, const char *file)
{
	// Only access the string memory if this memory region has already been set
	if(pos < shmSettings->next_str_pos)
		return &((const char*)shm_strings.ptr)[pos];
	else
	{
		logg("WARN: Tried to access %zu in %s() (%s:%i) but next_str_pos is %u", pos, func, file, line, shmSettings->next_str_pos);
		return "";
	}
}

/// Create a mutex for shared memory
static pthread_mutex_t create_mutex(void) {
	logg("Creating mutex");
	pthread_mutexattr_t lock_attr = {};
	pthread_mutex_t lock = {};

	// Initialize the lock attributes
	pthread_mutexattr_init(&lock_attr);

	// Allow the lock to be used by other processes
	pthread_mutexattr_setpshared(&lock_attr, PTHREAD_PROCESS_SHARED);

	// Make the lock robust against process death
	pthread_mutexattr_setrobust(&lock_attr, PTHREAD_MUTEX_ROBUST);

	// Initialize the lock
	pthread_mutex_init(&lock, &lock_attr);

	// Destroy the lock attributes since we're done with it
	pthread_mutexattr_destroy(&lock_attr);

	return lock;
}

static void remap_shm(void)
{
	// Remap shared object pointers which might have changed
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

	// Update local counter to reflect that we absorbed this change
	local_shm_counter = shmSettings->global_shm_counter;
}

// Obtain SHMEM lock
void _lock_shm(const char *func, const int line, const char *file)
{
	if(config.debug & DEBUG_LOCKS)
		logg("Waiting for SHM lock in %s() (%s:%i)", func, file, line);

	int result = pthread_mutex_lock(&shmLock->lock.outer);

	if(result != 0)
		logg("Error when obtaining outer SHM lock: %s", strerror(result));

	if(result == EOWNERDEAD) {
		// Try to make the lock consistent if the other process died while
		// holding the lock
		if(config.debug & DEBUG_LOCKS)
			logg("Owner of outer SHM lock died, making lock consistent");

		result = pthread_mutex_consistent(&shmLock->lock.outer);
		if(result != 0)
			logg("Failed to make outer SHM lock consistent: %s", strerror(result));
	}

	// Store lock owner after lock has been acquired and was made consistent (if required)
	shmLock->owner.pid = getpid();
	shmLock->owner.tid = gettid();

	// Check if this process needs to remap the shared memory objects
	if(shmSettings != NULL &&
	   local_shm_counter != shmSettings->global_shm_counter)
	{
		if(config.debug & DEBUG_SHMEM)
			logg("Remapping shared memory for current process %u %u",
		             local_shm_counter, shmSettings->global_shm_counter);
		remap_shm();
	}

	// Ensure we have enough shared memory available for new data
	shm_ensure_size();

	result = pthread_mutex_lock(&shmLock->lock.inner);

	if(config.debug & DEBUG_LOCKS)
		logg("Obtained SHM lock for %s() (%s:%i)", func, file, line);

	if(result != 0)
		logg("Error when obtaining inner SHM lock: %s", strerror(result));

	if(result == EOWNERDEAD) {
		// Try to make the lock consistent if the other process died while
		// holding the lock
		if(config.debug & DEBUG_LOCKS)
			logg("Owner of inner SHM lock died, making lock consistent");

		result = pthread_mutex_consistent(&shmLock->lock.inner);
		if(result != 0)
			logg("Failed to make inner SHM lock consistent: %s", strerror(result));
	}
}

// Release SHM lock
void _unlock_shm(const char* func, const int line, const char * file)
{
	if(config.debug & DEBUG_LOCKS && !is_our_lock())
	{
		logg("ERROR: Tried to unlock but lock is owned by %li/%li",
		     (long int)shmLock->owner.pid, (long int)shmLock->owner.tid);
	}

	// Unlock mutex
	int result = pthread_mutex_unlock(&shmLock->lock.inner);
	shmLock->owner.pid = 0;
	shmLock->owner.tid = 0;

	if(config.debug & DEBUG_LOCKS)
		logg("Removed lock in %s() (%s:%i)", func, file, line);

	if(result != 0)
		logg("Failed to unlock inner SHM lock: %s", strerror(result));

	result = pthread_mutex_unlock(&shmLock->lock.outer);
	if(result != 0)
		logg("Failed to unlock outer SHM lock: %s", strerror(result));
}

// Return if we locked this mutex (PID and TID match)
bool is_our_lock(void)
{
	if(shmLock->owner.pid == getpid() &&
	   shmLock->owner.tid == gettid())
		return true;
	return false;
}

bool init_shmem(bool create_new)
{
	// Get kernel's page size
	pagesize = getpagesize();

	/****************************** shared memory lock ******************************/
	// Try to create shared memory object
	shm_lock = create_shm(SHARED_LOCK_NAME, sizeof(ShmLock), create_new);
	if(shm_lock.ptr == NULL)
		return false;
	shmLock = (ShmLock*) shm_lock.ptr;
	if(create_new)
	{
		shmLock->lock.outer = create_mutex();
		shmLock->lock.inner = create_mutex();
	}

	/****************************** shared counters struct ******************************/
	// Try to create shared memory object
	shm_counters = create_shm(SHARED_COUNTERS_NAME, sizeof(countersStruct), create_new);
	if(shm_counters.ptr == NULL)
		return false;
	counters = (countersStruct*)shm_counters.ptr;

	/****************************** shared settings struct ******************************/
	// Try to create shared memory object
	shm_settings = create_shm(SHARED_SETTINGS_NAME, sizeof(ShmSettings), create_new);
	if(shm_settings.ptr == NULL)
		return false;
	shmSettings = (ShmSettings*)shm_settings.ptr;
	if(create_new)
	{
		shmSettings->version = SHARED_MEMORY_VERSION;
		shmSettings->global_shm_counter = 0;
	}
	else
	{
		if(shmSettings->version != SHARED_MEMORY_VERSION)
		{
			logg("Shared memory version mismatch, found %d, expected %d!",
			     shmSettings->version, SHARED_MEMORY_VERSION);
			return false;
		}
	}

	/****************************** shared strings buffer ******************************/
	// Try to create shared memory object
	shm_strings = create_shm(SHARED_STRINGS_NAME, STRINGS_ALLOC_STEP, create_new);
	if(shm_strings.ptr == NULL)
		return false;
	if(create_new)
	{
		counters->strings_MAX = shm_strings.size;

		// Initialize shared string object with an empty string at position zero
		((char*)shm_strings.ptr)[0] = '\0';
		shmSettings->next_str_pos = 1;
	}

	/****************************** shared domains struct ******************************/
	size_t size = get_optimal_object_size(sizeof(domainsData), 1);
	// Try to create shared memory object
	shm_domains = create_shm(SHARED_DOMAINS_NAME, size*sizeof(domainsData), create_new);
	if(shm_domains.ptr == NULL)
		return false;
	domains = (domainsData*)shm_domains.ptr;
	if(create_new)
		counters->domains_MAX = size;

	/****************************** shared clients struct ******************************/
	size = get_optimal_object_size(sizeof(clientsData), 1);
	// Try to create shared memory object
	shm_clients = create_shm(SHARED_CLIENTS_NAME, size*sizeof(clientsData), create_new);
	if(shm_clients.ptr == NULL)
		return false;
	clients = (clientsData*)shm_clients.ptr;
	if(create_new)
		counters->clients_MAX = size;

	/****************************** shared upstreams struct ******************************/
	size = get_optimal_object_size(sizeof(upstreamsData), 1);
	// Try to create shared memory object
	shm_upstreams = create_shm(SHARED_UPSTREAMS_NAME, size*sizeof(upstreamsData), create_new);
	if(shm_upstreams.ptr == NULL)
		return false;
	upstreams = (upstreamsData*)shm_upstreams.ptr;
	if(create_new)
		counters->upstreams_MAX = size;

	/****************************** shared queries struct ******************************/
	// Try to create shared memory object
	shm_queries = create_shm(SHARED_QUERIES_NAME, pagesize*sizeof(queriesData), create_new);
	if(shm_queries.ptr == NULL)
		return false;
	queries = (queriesData*)shm_queries.ptr;
	if(create_new)
		counters->queries_MAX = pagesize;

	/****************************** shared overTime struct ******************************/
	size = get_optimal_object_size(sizeof(overTimeData), OVERTIME_SLOTS);
	// Try to create shared memory object
	shm_overTime = create_shm(SHARED_OVERTIME_NAME, size*sizeof(overTimeData), create_new);
	if(shm_overTime.ptr == NULL)
		return false;
	if(create_new)
	{
		// set global pointer in overTime.c
		overTime = (overTimeData*)shm_overTime.ptr;
	}

	/****************************** shared DNS cache struct ******************************/
	size = get_optimal_object_size(sizeof(DNSCacheData), 1);
	// Try to create shared memory object
	shm_dns_cache = create_shm(SHARED_DNS_CACHE, size*sizeof(DNSCacheData), create_new);
	if(shm_dns_cache.ptr == NULL)
		return false;
	dns_cache = (DNSCacheData*)shm_dns_cache.ptr;
	if(create_new)
		counters->dns_cache_MAX = size;

	/****************************** shared per-client regex buffer ******************************/
	size = pagesize; // Allocate one pagesize initially. This may be expanded later on
	// Try to create shared memory object
	shm_per_client_regex = create_shm(SHARED_PER_CLIENT_REGEX, size, create_new);
	if(shm_per_client_regex.ptr == NULL)
		return false;
	if(create_new)
		counters->per_client_regex_MAX = size;

	return true;
}

// CHOWN all shared memory objects to supplied user/group
void chown_all_shmem(struct passwd *ent_pw)
{
	for(unsigned int i = 0; i < NUM_SHMEM; i++)
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
	for(unsigned int i = 0; i < NUM_SHMEM; i++)
		delete_shm(sharedMemories[i]);
}

/// Create shared memory
///
/// \param name the name of the shared memory
/// \param size the size to allocate
/// \param create_new true = delete old file, create new, false = connect to existing object or fail
/// \return a structure with a pointer to the mounted shared memory. The pointer
/// will always be valid, because if it failed FTL will have exited.
static SharedMemory create_shm(const char *name, const size_t size, bool create_new)
{
	char df[64] =  { 0 };
	const int percentage = get_dev_shm_usage(df);
	if(config.debug & DEBUG_SHMEM || (config.check.shmem > 0 && percentage > config.check.shmem))
	{
		logg("Creating shared memory with name \"%s\" and size %zu (%s)", name, size, df);
	}
	if(config.check.shmem > 0 && percentage > config.check.shmem)
		log_resource_shortage(-1.0, 0, percentage, -1, SHMEM_PATH, df);

	SharedMemory sharedMemory = {
		.name = name,
		.size = size,
		.ptr = NULL
	};

	// O_RDWR: Open the object for read-write access (we need to be able to modify the locks)
	// When creating a new shared memory object, we add to this
	//   - O_CREAT: Create the shared memory object if it does not exist.
	//   - O_EXCL: Return an error if a shared memory object with the given name already exists.
	const int shm_oflags = create_new ? O_RDWR | O_CREAT | O_EXCL : O_RDWR;

	// Create the shared memory file in read/write mode with 600 permissions
	errno = 0;
	const int fd = shm_open(sharedMemory.name, shm_oflags, S_IRUSR | S_IWUSR);

	// Check for `shm_open` error
	if(fd == -1)
	{
		logg("FATAL: create_shm(): Failed to %s shared memory object \"%s\": %s",
		     create_new ? "create" : "open", name, strerror(errno));
		return sharedMemory;
	}

	// Allocate shared memory object to specified size
	// Using f[tl]allocate() will ensure that there's actually space for
	// this file. Otherwise we end up with a sparse file that can give
	// SIGBUS if we run out of space while writing to it.
	const int ret = ftlallocate(fd, 0U, size);
	if(ret != 0)
	{
		logg("FATAL: create_shm(): Failed to resize \"%s\" (%i) to %zu: %s (%i)",
		     sharedMemory.name, fd, size, strerror(errno), ret);
		exit(EXIT_FAILURE);
	}

	// Update how much memory FTL uses
	// We only add here as this is a new file
	used_shmem += size;

	// Create shared memory mapping
	void *shm = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	// Check for `mmap` error
	if(shm == MAP_FAILED)
	{
		logg("FATAL: create_shm(): Failed to map shared memory object \"%s\" (%i): %s",
		     sharedMemory.name, fd, strerror(errno));
		return sharedMemory;
	}

	// Close shared memory object file descriptor as it is no longer
	// needed after having called mmap()
	close(fd);

	sharedMemory.ptr = shm;
	return sharedMemory;
}

static void *enlarge_shmem_struct(const char type)
{
	SharedMemory *sharedMemory = NULL;
	size_t sizeofobj, allocation_step;
	int *counter = NULL;

	// Select type of struct that should be enlarged
	switch(type)
	{
		case QUERIES:
			sharedMemory = &shm_queries;
			allocation_step = pagesize;
			sizeofobj = sizeof(queriesData);
			counter = &counters->queries_MAX;
			break;
		case CLIENTS:
			sharedMemory = &shm_clients;
			allocation_step = get_optimal_object_size(sizeof(clientsData), 1);
			sizeofobj = sizeof(clientsData);
			counter = &counters->clients_MAX;
			break;
		case DOMAINS:
			sharedMemory = &shm_domains;
			allocation_step = get_optimal_object_size(sizeof(domainsData), 1);
			sizeofobj = sizeof(domainsData);
			counter = &counters->domains_MAX;
			break;
		case UPSTREAMS:
			sharedMemory = &shm_upstreams;
			allocation_step = get_optimal_object_size(sizeof(upstreamsData), 1);
			sizeofobj = sizeof(upstreamsData);
			counter = &counters->upstreams_MAX;
			break;
		case DNS_CACHE:
			sharedMemory = &shm_dns_cache;
			allocation_step = get_optimal_object_size(sizeof(DNSCacheData), 1);
			sizeofobj = sizeof(DNSCacheData);
			counter = &counters->dns_cache_MAX;
			break;
		case STRINGS:
			sharedMemory = &shm_strings;
			allocation_step = STRINGS_ALLOC_STEP;
			sizeofobj = 1;
			counter = &counters->strings_MAX;
			break;
		default:
			logg("Invalid argument in enlarge_shmem_struct(%i)", type);
			return 0;
	}

	// Reallocate enough space for requested object
	const size_t current = sharedMemory->size/sizeofobj;
	realloc_shm(sharedMemory, current + allocation_step, sizeofobj, true);

	// Add allocated memory to corresponding counter
	*counter += allocation_step;

	return sharedMemory->ptr;
}

static bool realloc_shm(SharedMemory *sharedMemory, const size_t size1, const size_t size2, const bool resize)
{
	// Absolute target size
	const size_t size = size1 * size2;

	// Log that we are doing something here
	char df[64] =  { 0 };
	const int percentage = get_dev_shm_usage(df);

	// Log output
	if(resize)
		logg("Resizing \"%s\" from %zu to (%zu * %zu) == %zu (%s)",
		     sharedMemory->name, sharedMemory->size, size1, size2, size, df);
	else
		logg("Remapping \"%s\" from %zu to (%zu * %zu) == %zu",
		     sharedMemory->name, sharedMemory->size, size1, size2, size);

	if(config.check.shmem > 0 && percentage > config.check.shmem)
		log_resource_shortage(-1.0, 0, percentage, -1, SHMEM_PATH, df);

	// Resize shard memory object if requested
	// If not, we only remap a shared memory object which might have changed
	// in another process. This happens when pihole-FTL forks due to incoming
	// TCP requests.
	if(resize)
	{
		// Open shared memory object
		const int fd = shm_open(sharedMemory->name, O_RDWR, S_IRUSR | S_IWUSR);
		if(fd == -1)
		{
			logg("FATAL: realloc_shm(): Failed to open shared memory object \"%s\": %s",
			     sharedMemory->name, strerror(errno));
			exit(EXIT_FAILURE);
		}

		// Allocate shared memory object to specified size
		// Using f[tl]allocate() will ensure that there's actually space for
		// this file. Otherwise we end up with a sparse file that can give
		// SIGBUS if we run out of space while writing to it.
		const int ret = ftlallocate(fd, 0U, size);
		if(ret != 0)
		{
			logg("FATAL: realloc_shm(): Failed to resize \"%s\" (%i) to %zu: %s (%i)",
			     sharedMemory->name, fd, size, strerror(errno), ret);
			exit(EXIT_FAILURE);
		}

		// Close shared memory object file descriptor as it is no longer
		// needed after having called f[tl]allocate()
		close(fd);

		// Update shm counters to indicate that at least one shared memory object changed
		shmSettings->global_shm_counter++;
		local_shm_counter++;
	}

	void *new_ptr = mremap(sharedMemory->ptr, sharedMemory->size, size, MREMAP_MAYMOVE);
	if(new_ptr == MAP_FAILED)
	{
		logg("FATAL: realloc_shm(): mremap(%p, %zu, %zu, MREMAP_MAYMOVE): Failed to reallocate \"%s\": %s",
		     sharedMemory->ptr, sharedMemory->size, size, sharedMemory->name,
		     strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Update how much memory FTL uses
	// We add the difference between updated and previous size
	used_shmem += (size - sharedMemory->size);

	if(config.debug & DEBUG_SHMEM)
	{
		if(sharedMemory->ptr == new_ptr)
			logg("SHMEM pointer not updated: %p (%zu %zu)",
			     sharedMemory->ptr, sharedMemory->size, size);
		else
			logg("SHMEM pointer updated: %p -> %p (%zu %zu)",
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
		if(munmap(sharedMemory->ptr, sharedMemory->size) != 0)
			logg("delete_shm(): munmap(%p, %zu) failed: %s", sharedMemory->ptr, sharedMemory->size, strerror(errno));
	}

	// Now you can no longer `shm_open` the memory, and once all others
	// unlink, it will be destroyed.
	if(shm_unlink(sharedMemory->name) != 0)
		logg("delete_shm(): shm_unlink(%s) failed: %s", sharedMemory->name, strerror(errno));
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
		if(config.debug & DEBUG_SHMEM)
		{
			logg("DEBUG: LCM(%i, %zu) == %zu < %zu",
			     pagesize, objsize,
			     optsize*objsize,
			     minsize*objsize);
		}

		// Upscale optimal size by a certain factor
		// Logic of this computation:
		// First part: Integer division, may cause clipping, e.g., 5/3 = 1
		// Second part: Catch a possibly happened clipping event by adding
		//              one to the number: (5 % 3 != 0) is 1
		const size_t multiplier = (minsize/optsize) + ((minsize % optsize != 0) ? 1u : 0u);
		if(config.debug & DEBUG_SHMEM)
		{
			logg("DEBUG: Using %zu*%zu == %zu >= %zu",
			     multiplier, optsize*objsize,
			     multiplier*optsize*objsize,
			     minsize*objsize);
		}
		// As optsize ensures perfect page-alignment,
		// any multiple of it will be aligned as well
		return multiplier*optsize;
	}
	else
	{
		if(config.debug & DEBUG_SHMEM)
		{
			logg("DEBUG: LCM(%i, %zu) == %zu >= %zu",
			     pagesize, objsize,
			     optsize*objsize,
			     minsize*objsize);
		}

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
			logg("FATAL: Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->upstreams >= counters->upstreams_MAX-1)
	{
		// Have to reallocate shared memory
		upstreams = enlarge_shmem_struct(UPSTREAMS);
		if(upstreams == NULL)
		{
			logg("FATAL: Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->clients >= counters->clients_MAX-1)
	{
		// Have to reallocate shared memory
		clients = enlarge_shmem_struct(CLIENTS);
		if(clients == NULL)
		{
			logg("FATAL: Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->domains >= counters->domains_MAX-1)
	{
		// Have to reallocate shared memory
		domains = enlarge_shmem_struct(DOMAINS);
		if(domains == NULL)
		{
			logg("FATAL: Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(counters->dns_cache_size >= counters->dns_cache_MAX-1)
	{
		// Have to reallocate shared memory
		dns_cache = enlarge_shmem_struct(DNS_CACHE);
		if(dns_cache == NULL)
		{
			logg("FATAL: Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
	if(shmSettings->next_str_pos + STRINGS_ALLOC_STEP >= shm_strings.size)
	{
		// Have to reallocate shared memory
		if(enlarge_shmem_struct(STRINGS) == NULL)
		{
			logg("FATAL: Memory allocation failed! Exiting");
			exit(EXIT_FAILURE);
		}
	}
}

void reset_per_client_regex(const int clientID)
{
	const unsigned int num_regex_tot = get_num_regex(REGEX_MAX); // total number
	for(unsigned int i = 0u; i < num_regex_tot; i++)
	{
		// Zero-initialize/reset (= false) all regex (white + black)
		set_per_client_regex(clientID, i, false);
	}
}

void add_per_client_regex(unsigned int clientID)
{
	const unsigned int num_regex_tot = get_num_regex(REGEX_MAX); // total number
	const size_t size = get_optimal_object_size(1, counters->clients * num_regex_tot);
	if(size > shm_per_client_regex.size &&
	   realloc_shm(&shm_per_client_regex, 1, size, true))
	{
		reset_per_client_regex(clientID);
		counters->per_client_regex_MAX = size;
	}
}

bool get_per_client_regex(const int clientID, const int regexID)
{
	const unsigned int num_regex_tot = get_num_regex(REGEX_MAX); // total number
	const unsigned int id = clientID * num_regex_tot + regexID;
	const size_t maxval = shm_per_client_regex.size / sizeof(bool);
	if(id > maxval)
	{
		logg("ERROR: get_per_client_regex(%d, %d): Out of bounds (%d > %d * %d, shm_per_client_regex.size = %zd)!",
		     clientID, regexID,
		     id, counters->clients, num_regex_tot, maxval);
		return false;
	}
	return ((bool*) shm_per_client_regex.ptr)[id];
}

void set_per_client_regex(const int clientID, const int regexID, const bool value)
{
	const unsigned int num_regex_tot = get_num_regex(REGEX_MAX); // total number
	const unsigned int id = clientID * num_regex_tot + regexID;
	const size_t maxval = shm_per_client_regex.size / sizeof(bool);
	if(id > maxval)
	{
		logg("ERROR: set_per_client_regex(%d, %d, %s): Out of bounds (%d > %d * %d, shm_per_client_regex.size = %zd)!",
		     clientID, regexID, value ? "true" : "false",
		     id, counters->clients, num_regex_tot, maxval);
		return;
	}
	((bool*) shm_per_client_regex.ptr)[id] = value;
}

static inline bool check_range(int ID, int MAXID, const char* type, const char *func, int line, const char *file)
{
	// Check bounds
	if(ID < 0 || ID > MAXID)
	{
		logg("ERROR: Trying to access %s ID %i, but maximum is %i", type, ID, MAXID);
		logg("       found in %s() (%s:%i)", func, short_path(file), line);
		return false;
	}

	// Everything okay
	return true;
}

static inline bool check_magic(int ID, bool checkMagic, unsigned char magic, const char *type, const char *func, int line, const char *file)
{
	// Check magic only if requested (skipped for new entries which are uninitialized)
	if(checkMagic && magic != MAGICBYTE)
	{
		logg("ERROR: Trying to access %s ID %i, but magic byte is %x", type, ID, magic);
		logg("       found in %s() (%s:%i)", func, short_path(file), line);
		return false;
	}

	// Everything okay
	return true;
}

queriesData* _getQuery(int queryID, bool checkMagic, int line, const char *func, const char *file)
{
	// This does not exist, return a NULL pointer
	if(queryID == -1)
		return NULL;

	// We are not in a locked situation, return a NULL pointer
	if(config.debug & DEBUG_LOCKS && !is_our_lock())
	{
		logg("ERROR: Tried to obtain query pointer without lock in %s() (%s:%i)!",
		     func, short_path(file), line);
		generate_backtrace();
		return NULL;
	}

	if(check_range(queryID, counters->queries_MAX, "query", func, line, file) &&
	   check_magic(queryID, checkMagic, queries[queryID].magic, "query", func, line, file))
		return &queries[queryID];
	else
		return NULL;
}

clientsData* _getClient(int clientID, bool checkMagic, int line, const char *func, const char *file)
{
	// This does not exist, we return a NULL pointer
	if(clientID == -1)
		return NULL;

	// We are not in a locked situation, return a NULL pointer
	if(config.debug & DEBUG_LOCKS && !is_our_lock())
	{
		logg("ERROR: Tried to obtain client pointer without lock in %s() (%s:%i)!",
		     func, short_path(file), line);
		generate_backtrace();
		return NULL;
	}

	if(check_range(clientID, counters->clients_MAX, "client", func, line, file) &&
	   check_magic(clientID, checkMagic, clients[clientID].magic, "client", func, line, file))
		return &clients[clientID];
	else
		return NULL;
}

domainsData* _getDomain(int domainID, bool checkMagic, int line, const char *func, const char *file)
{
	// This does not exist, we return a NULL pointer
	if(domainID == -1)
		return NULL;

	// We are not in a locked situation, return a NULL pointer
	if(config.debug & DEBUG_LOCKS && !is_our_lock())
	{
		logg("ERROR: Tried to obtain domain pointer without lock in %s() (%s:%i)!",
		     func, short_path(file), line);
		generate_backtrace();
		return NULL;
	}

	if(check_range(domainID, counters->domains_MAX, "domain", func, line, file) &&
	   check_magic(domainID, checkMagic, domains[domainID].magic, "domain", func, line, file))
		return &domains[domainID];
	else
		return NULL;
}

upstreamsData* _getUpstream(int upstreamID, bool checkMagic, int line, const char *func, const char *file)
{
	// This does not exist, we return a NULL pointer
	if(upstreamID == -1)
		return NULL;

	// We are not in a locked situation, return a NULL pointer
	if(config.debug & DEBUG_LOCKS && !is_our_lock())
	{
		logg("ERROR: Tried to obtain upstream pointer without lock in %s() (%s:%i)!",
		     func, short_path(file), line);
		generate_backtrace();
		return NULL;
	}

	if(check_range(upstreamID, counters->upstreams_MAX, "upstream", func, line, file) &&
	   check_magic(upstreamID, checkMagic, upstreams[upstreamID].magic, "upstream", func, line, file))
		return &upstreams[upstreamID];
	else
		return NULL;
}

DNSCacheData* _getDNSCache(int cacheID, bool checkMagic, int line, const char *func, const char *file)
{
	// This does not exist, we return a NULL pointer
	if(cacheID == -1)
		return NULL;

	// We are not in a locked situation, return a NULL pointer
	if(config.debug & DEBUG_LOCKS && !is_our_lock())
	{
		logg("ERROR: Tried to obtain cache pointer without lock in %s() (%s:%i)!",
		     func, short_path(file), line);
		generate_backtrace();
		return NULL;
	}

	if(check_range(cacheID, counters->dns_cache_MAX, "dns_cache", func, line, file) &&
	   check_magic(cacheID, checkMagic, dns_cache[cacheID].magic, "dns_cache", func, line, file))
		return &dns_cache[cacheID];
	else
		return NULL;
}
