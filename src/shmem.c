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
#include "shmem.h"
#include "overTime.h"
#include "log.h"
#include "memory.h"
#include "config.h"
// data getter functions
#include "datastructure.h"
// fifologData
#include "fifo.h"
// statvfs()
#include <sys/statvfs.h>

/// The version of shared memory used
#define SHARED_MEMORY_VERSION 10

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

// Limit from which on we warn users about space running out in SHMEM_PATH
// default: 90%
#define SHMEM_WARN_LIMIT 90

// Global counters struct
countersStruct *counters = NULL;
#define SHARED_FIFO_LOG_NAME "/FTL-fifo-log"

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

// Variable size array structs
static queriesData *queries = NULL;
static clientsData *clients = NULL;
static domainsData *domains = NULL;
static upstreamsData *upstreams = NULL;
static DNSCacheData *dns_cache = NULL;

typedef struct {
	pthread_mutex_t lock;
	bool waitingForLock;
} ShmLock;
static ShmLock *shmLock = NULL;
static ShmSettings *shmSettings = NULL;

static int pagesize;
static unsigned int local_shm_counter = 0;

static size_t get_optimal_object_size(const size_t objsize, const size_t minsize);

static int get_dev_shm_usage(char buffer[64])
{
	// Get filesystem information about /dev/shm (typically a tmpfs)
	struct statvfs f;
	if(statvfs(SHMEM_PATH, &f) != 0)
	{
		// If statvfs() failed, we return the error instead
		strncpy(buffer, strerror(errno), 64);
		buffer[63] = '\0';
		return 0;
	}

	// Explicitly cast the block counts to unsigned long long to avoid
	// overflowing with drives larger than 4 GB on 32bit systems
	const unsigned long long size = (unsigned long long)f.f_blocks * f.f_frsize;
	const unsigned long long free = (unsigned long long)f.f_bavail * f.f_bsize;
	const unsigned long long used = size - free;

	// Create human-readable total size
	char prefix_size[2] = { 0 };
	double formated_size = 0.0;
	format_memory_size(prefix_size, size, &formated_size);

	// Generate human-readable used size
	char prefix_used[2] = { 0 };
	double formated_used = 0.0;
	format_memory_size(prefix_used, used, &formated_used);

	// Print result into buffer passed to this subroutine
	snprintf(buffer, 64, SHMEM_PATH": %.1f%sB used, %.1f%sB total", formated_used, prefix_used, formated_size, prefix_size);

	// Return percentage of used shared memory
	// Adding 1 avoids FPE if the size turns out to be zero
	return (used*100)/(size + 1);
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

void chown_all_shmem(struct passwd *ent_pw)
{
	chown_shmem(&shm_lock, ent_pw);
	chown_shmem(&shm_strings, ent_pw);
	chown_shmem(&shm_counters, ent_pw);
	chown_shmem(&shm_domains, ent_pw);
	chown_shmem(&shm_clients, ent_pw);
	chown_shmem(&shm_queries, ent_pw);
	chown_shmem(&shm_upstreams, ent_pw);
	chown_shmem(&shm_overTime, ent_pw);
	chown_shmem(&shm_settings, ent_pw);
	chown_shmem(&shm_dns_cache, ent_pw);
	chown_shmem(&shm_per_client_regex, ent_pw);
}

size_t addstr(const char *str)
{
	if(str == NULL)
	{
		logg("WARN: Called addstr() with NULL pointer");
		return 0;
	}

	// Get string length, add terminating character
	size_t len = strlen(str) + 1;

	// If this is an empty string (only the terminating character is present),
	// use the shared memory string at position zero instead of creating a new
	// entry here. We also ensure that the given string is not too long to
	// prevent possible memory corruption caused by strncpy() further down
	if(len == 1) {
		return 0;
	}
	else if(len > (size_t)(pagesize-1))
	{
		logg("WARN: Shortening too long string (len %zu)", len);
		len = pagesize;
	}

	// Debugging output
	if(config.debug & DEBUG_SHMEM)
		logg("Adding \"%s\" (len %zu) to buffer. next_str_pos is %u", str, len, shmSettings->next_str_pos);

	// Reserve additional memory if necessary
	if(shmSettings->next_str_pos + len > shm_strings.size &&
	   !realloc_shm(&shm_strings, shm_strings.size + pagesize, sizeof(char), true))
		return 0;

	// Store new string buffer size in corresponding counters entry
	// for re-using when we need to re-map shared memory objects
	counters->strings_MAX = shm_strings.size;

	// Copy the C string pointed by str into the shared string buffer
	strncpy(&((char*)shm_strings.ptr)[shmSettings->next_str_pos], str, len);

	// Increment string length counter
	shmSettings->next_str_pos += len;

	// Return start of stored string
	return (shmSettings->next_str_pos - len);
}

const char *getstr(const size_t pos)
{
	// Only access the string memory if this memory region has already been set
	if(pos < shmSettings->next_str_pos)
		return &((const char*)shm_strings.ptr)[pos];
	else
	{
		logg("WARN: Tried to access %zu but next_str_pos is %u", pos, shmSettings->next_str_pos);
		return "";
	}
}

/// Create a mutex for shared memory
static pthread_mutex_t create_mutex(void) {
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

	realloc_shm(&shm_strings, counters->strings_MAX, sizeof(char), false);
	// strings are not exposed by a global pointer

	// Update local counter to reflect that we absorbed this change
	local_shm_counter = shmSettings->global_shm_counter;
}

void _lock_shm(const char* func, const int line, const char * file) {
	// Signal that FTL is waiting for a lock
	shmLock->waitingForLock = true;

	if(config.debug & DEBUG_LOCKS)
		logg("Waiting for lock in %s() (%s:%i)", func, file, line);

	int result = pthread_mutex_lock(&shmLock->lock);

	if(config.debug & DEBUG_LOCKS)
		logg("Obtained lock for %s() (%s:%i)", func, file, line);

	// Check if this process needs to remap the shared memory objects
	if(shmSettings != NULL &&
	   local_shm_counter != shmSettings->global_shm_counter)
	{
		if(config.debug & DEBUG_SHMEM)
			logg("Remapping shared memory for current process %u %u",
		             local_shm_counter, shmSettings->global_shm_counter);
		remap_shm();
	}

	// Turn off the waiting for lock signal to notify everyone who was
	// deferring to FTL that they can jump in the lock queue.
	shmLock->waitingForLock = false;

	if(result == EOWNERDEAD) {
		// Try to make the lock consistent if the other process died while
		// holding the lock
		result = pthread_mutex_consistent(&shmLock->lock);
	}

	if(result != 0)
		logg("Failed to obtain SHM lock: %s in %s() (%s:%i)", strerror(result), func, file, line);
}

void _unlock_shm(const char* func, const int line, const char * file) {
	int result = pthread_mutex_unlock(&shmLock->lock);

	if(config.debug & DEBUG_LOCKS)
		logg("Removed lock in %s() (%s:%i)", func, file, line);

	if(result != 0)
		logg("Failed to unlock SHM lock: %s in %s() (%s:%i)", strerror(result), func, file, line);
}

bool init_shmem(void)
{
	// Get kernel's page size
	pagesize = getpagesize();

	/****************************** shared memory lock ******************************/
	// Try to create shared memory object
	shm_lock = create_shm(SHARED_LOCK_NAME, sizeof(ShmLock));
	shmLock = (ShmLock*) shm_lock.ptr;
	shmLock->lock = create_mutex();
	shmLock->waitingForLock = false;

	/****************************** shared counters struct ******************************/
	// Try to create shared memory object
	shm_counters = create_shm(SHARED_COUNTERS_NAME, sizeof(countersStruct));
	counters = (countersStruct*)shm_counters.ptr;

	/****************************** shared settings struct ******************************/
	// Try to create shared memory object
	shm_settings = create_shm(SHARED_SETTINGS_NAME, sizeof(ShmSettings));
	shmSettings = (ShmSettings*)shm_settings.ptr;
	shmSettings->version = SHARED_MEMORY_VERSION;
	shmSettings->global_shm_counter = 0;

	/****************************** shared strings buffer ******************************/
	// Try to create shared memory object
	shm_strings = create_shm(SHARED_STRINGS_NAME, pagesize);
	counters->strings_MAX = pagesize;

	// Initialize shared string object with an empty string at position zero
	((char*)shm_strings.ptr)[0] = '\0';
	shmSettings->next_str_pos = 1;

	/****************************** shared domains struct ******************************/
	// Try to create shared memory object
	shm_domains = create_shm(SHARED_DOMAINS_NAME, pagesize*sizeof(domainsData));
	domains = (domainsData*)shm_domains.ptr;
	counters->domains_MAX = pagesize;

	/****************************** shared clients struct ******************************/
	size_t size = get_optimal_object_size(sizeof(clientsData), 1);
	// Try to create shared memory object
	shm_clients = create_shm(SHARED_CLIENTS_NAME, size*sizeof(clientsData));
	clients = (clientsData*)shm_clients.ptr;
	counters->clients_MAX = size;

	/****************************** shared upstreams struct ******************************/
	size = get_optimal_object_size(sizeof(upstreamsData), 1);
	// Try to create shared memory object
	shm_upstreams = create_shm(SHARED_UPSTREAMS_NAME, size*sizeof(upstreamsData));
	upstreams = (upstreamsData*)shm_upstreams.ptr;
	counters->upstreams_MAX = size;

	/****************************** shared queries struct ******************************/
	// Try to create shared memory object
	shm_queries = create_shm(SHARED_QUERIES_NAME, pagesize*sizeof(queriesData));
	queries = (queriesData*)shm_queries.ptr;
	counters->queries_MAX = pagesize;

	/****************************** shared overTime struct ******************************/
	size = get_optimal_object_size(sizeof(overTimeData), OVERTIME_SLOTS);
	// Try to create shared memory object
	shm_overTime = create_shm(SHARED_OVERTIME_NAME, size*sizeof(overTimeData));
	overTime = (overTimeData*)shm_overTime.ptr;
	initOverTime();

	/****************************** shared DNS cache struct ******************************/
	size = get_optimal_object_size(sizeof(DNSCacheData), 1);
	// Try to create shared memory object
	shm_dns_cache = create_shm(SHARED_DNS_CACHE, size*sizeof(DNSCacheData));
	dns_cache = (DNSCacheData*)shm_dns_cache.ptr;
	counters->dns_cache_MAX = size;

	/****************************** shared per-client regex buffer ******************************/
	size = get_optimal_object_size(1, 2);
	// Try to create shared memory object
	shm_per_client_regex = create_shm(SHARED_PER_CLIENT_REGEX, size);

	/****************************** shared fifo_buffer struct ******************************/
	// Try to create shared memory object
	shm_fifo_log = create_shm(SHARED_FIFO_LOG_NAME, sizeof(fifologData));
	fifo_log = (fifologData*)shm_fifo_log.ptr;

	return true;
}

void destroy_shmem(void)
{
	if(&shmLock->lock != NULL)
		pthread_mutex_destroy(&shmLock->lock);
	shmLock = NULL;

	delete_shm(&shm_lock);
	delete_shm(&shm_strings);
	delete_shm(&shm_counters);
	delete_shm(&shm_domains);
	delete_shm(&shm_clients);
	delete_shm(&shm_queries);
	delete_shm(&shm_upstreams);
	delete_shm(&shm_overTime);
	delete_shm(&shm_settings);
	delete_shm(&shm_dns_cache);
	delete_shm(&shm_per_client_regex);
	delete_shm(&shm_fifo_log);
}

SharedMemory create_shm(const char *name, const size_t size)
{
	char df[64] =  { 0 };
	const int percentage = get_dev_shm_usage(df);
	if(config.debug & DEBUG_SHMEM || percentage > SHMEM_WARN_LIMIT)
	{
		logg("Creating shared memory with name \"%s\" and size %zu (%s)", name, size, df);
	}
	if(percentage > SHMEM_WARN_LIMIT)
		logg("WARNING: More than %u%% of "SHMEM_PATH" is used", SHMEM_WARN_LIMIT);

	SharedMemory sharedMemory = {
		.name = name,
		.size = size,
		.ptr = NULL
	};

	// Try unlinking the shared memory object before creating a new one.
	// If the object is still existing, e.g., due to a past unclean exit
	// of FTL, shm_open() would fail with error "File exists"
	int ret = shm_unlink(name);
	// Check return code. shm_unlink() returns -1 on error and sets errno
	// We specifically ignore ENOENT (No such file or directory) as this is not an
	// error in our use case (we only want the file to be deleted when existing)
	if(ret != 0 && errno != ENOENT)
		logg("create_shm(): shm_unlink(\"%s\") failed: %s (%i)", name, strerror(errno), errno);

	// Create the shared memory file in read/write mode with 600 permissions
	int fd = shm_open(sharedMemory.name, O_CREAT | O_EXCL | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);

	// Check for `shm_open` error
	if(fd == -1)
	{
		logg("FATAL: create_shm(): Failed to create_shm shared memory object \"%s\": %s",
		     name, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Allocate shared memory object to specified size
	// Using fallocate() will ensure that there's actually space for
	// this file. Otherwise we end up with a sparse file that can give
	// SIGBUS if we run out of space while writing to it.
	ret = fallocate(fd, 0, 0U, size);
	if(ret != 0)
	{
		logg("FATAL: create_shm(): Failed to resize \"%s\" (%i) to %zu: %s (%i)",
		     sharedMemory.name, fd, size, strerror(errno), ret);
		exit(EXIT_FAILURE);
	}

	// Create shared memory mapping
	void *shm = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	// Check for `mmap` error
	if(shm == MAP_FAILED)
	{
		logg("FATAL: create_shm(): Failed to map shared memory object \"%s\" (%i): %s",
		     sharedMemory.name, fd, strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Close shared memory object file descriptor as it is no longer
	// needed after having called mmap()
	close(fd);

	sharedMemory.ptr = shm;
	return sharedMemory;
}

void *enlarge_shmem_struct(const char type)
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
			allocation_step = pagesize;
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
		default:
			logg("Invalid argument in enlarge_shmem_struct(%i)", type);
			return 0;
	}

	// Reallocate enough space for requested object
	realloc_shm(sharedMemory, sharedMemory->size/sizeofobj + allocation_step, sizeofobj, true);

	// Add allocated memory to corresponding counter
	*counter += allocation_step;

	return sharedMemory->ptr;
}

bool realloc_shm(SharedMemory *sharedMemory, const size_t size1, const size_t size2, const bool resize)
{
	// Absolute target size
	const size_t size = size1 * size2;
	// Check if we can skip this routine as nothing is to be done
	// when an object is not to be resized and its size didn't
	// change elsewhere
	if(!resize && size == sharedMemory->size)
		return true;

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

	if(percentage > SHMEM_WARN_LIMIT)
		logg("WARNING: More than %u%% of "SHMEM_PATH" is used", SHMEM_WARN_LIMIT);

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
		// Using fallocate() will ensure that there's actually space for
		// this file. Otherwise we end up with a sparse file that can give
		// SIGBUS if we run out of space while writing to it.
		const int ret = fallocate(fd, 0, 0U, size);
		if(ret != 0)
		{
			logg("FATAL: realloc_shm(): Failed to resize \"%s\" (%i) to %zu: %s (%i)",
			     sharedMemory->name, fd, size, strerror(errno), ret);
			exit(EXIT_FAILURE);
		}

		// Close shared memory object file descriptor as it is no longer
		// needed after having called fallocate()
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

	sharedMemory->ptr = new_ptr;
	sharedMemory->size = size;

	return true;
}

void delete_shm(SharedMemory *sharedMemory)
{
	// Unmap shared memory
	int ret = munmap(sharedMemory->ptr, sharedMemory->size);
	if(ret != 0)
		logg("delete_shm(): munmap(%p, %zu) failed: %s", sharedMemory->ptr, sharedMemory->size, strerror(errno));

	// Now you can no longer `shm_open` the memory,
	// and once all others unlink, it will be destroyed.
	ret = shm_unlink(sharedMemory->name);
	if(ret != 0)
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

void memory_check(const enum memory_type which)
{
	switch(which)
	{
		case QUERIES:
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
			break;
		case UPSTREAMS:
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
			break;
		case CLIENTS:
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
			break;
		case DOMAINS:
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
			break;
		case DNS_CACHE:
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
			break;
		case OVERTIME: // fall through
		default:
			/* That cannot happen */
			logg("Fatal error in memory_check(%i)", which);
			exit(EXIT_FAILURE);
			break;
	}
}

void reset_per_client_regex(const int clientID)
{
	const unsigned int num_regex_tot = counters->num_regex[REGEX_BLACKLIST] +
	                                   counters->num_regex[REGEX_WHITELIST];
	for(unsigned int i = 0u; i < num_regex_tot; i++)
	{
		// Zero-initialize/reset (= false) all regex (white + black)
		set_per_client_regex(clientID, i, false);
	}
}

void add_per_client_regex(unsigned int clientID)
{
	const unsigned int num_regex_tot = counters->num_regex[REGEX_BLACKLIST] +
	                                   counters->num_regex[REGEX_WHITELIST];
	const size_t size = counters->clients * num_regex_tot;
	if(size > shm_per_client_regex.size &&
	   realloc_shm(&shm_per_client_regex, counters->clients, num_regex_tot, true))
	{
		reset_per_client_regex(clientID);
	}
}

bool get_per_client_regex(const int clientID, const int regexID)
{
	const unsigned int num_regex_tot = counters->num_regex[REGEX_BLACKLIST] +
	                                   counters->num_regex[REGEX_WHITELIST];
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
	const unsigned int num_regex_tot = counters->num_regex[REGEX_BLACKLIST] +
	                                   counters->num_regex[REGEX_WHITELIST];
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

static inline bool check_range(int ID, int MAXID, const char* type, int line, const char * function, const char * file)
{
	if(ID < 0 || ID > MAXID)
	{
		// Check bounds
		logg("FATAL: Trying to access %s ID %i, but maximum is %i", type, ID, MAXID);
		logg("       found in %s() (%s:%i)", function, file, line);
		return false;
	}
	// Everything okay
	return true;
}

static inline bool check_magic(int ID, bool checkMagic, unsigned char magic, const char* type, int line, const char * function, const char * file)
{
	if(checkMagic && magic != MAGICBYTE)
	{
		// Check magic only if requested (skipped for new entries which are uninitialized)
		logg("FATAL: Trying to access %s ID %i, but magic byte is %x", type, ID, magic);
		logg("       found in %s() (%s:%i)", function, file, line);
		return false;
	}
	// Everything okay
	return true;
}

queriesData* _getQuery(int queryID, bool checkMagic, int line, const char * function, const char * file)
{
	if(check_range(queryID, counters->queries_MAX, "query", line, function, file) &&
	   check_magic(queryID, checkMagic, queries[queryID].magic, "query", line, function, file))
		return &queries[queryID];
	else
		return NULL;
}

clientsData* _getClient(int clientID, bool checkMagic, int line, const char * function, const char * file)
{
	if(check_range(clientID, counters->clients_MAX, "client", line, function, file) &&
	   check_magic(clientID, checkMagic, clients[clientID].magic, "client", line, function, file))
		return &clients[clientID];
	else
		return NULL;
}

domainsData* _getDomain(int domainID, bool checkMagic, int line, const char * function, const char * file)
{
	if(check_range(domainID, counters->domains_MAX, "domain", line, function, file) &&
	   check_magic(domainID, checkMagic, domains[domainID].magic, "domain", line, function, file))
		return &domains[domainID];
	else
		return NULL;
}

upstreamsData* _getUpstream(int upstreamID, bool checkMagic, int line, const char * function, const char * file)
{
	if(check_range(upstreamID, counters->upstreams_MAX, "upstream", line, function, file) &&
	   check_magic(upstreamID, checkMagic, upstreams[upstreamID].magic, "upstream", line, function, file))
		return &upstreams[upstreamID];
	else
		return NULL;
}

DNSCacheData* _getDNSCache(int cacheID, bool checkMagic, int line, const char * function, const char * file)
{
	if(check_range(cacheID, counters->dns_cache_MAX, "dns_cache", line, function, file) &&
	   check_magic(cacheID, checkMagic, dns_cache[cacheID].magic, "dns_cache", line, function, file))
		return &dns_cache[cacheID];
	else
		return NULL;
}
