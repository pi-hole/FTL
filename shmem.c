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

/// The version of shared memory used
#define SHARED_MEMORY_VERSION 4

/// The name of the shared memory. Use this when connecting to the shared memory.
#define SHARED_LOCK_NAME "/FTL-lock"
#define SHARED_STRINGS_NAME "/FTL-strings"
#define SHARED_COUNTERS_NAME "/FTL-counters"
#define SHARED_DOMAINS_NAME "/FTL-domains"
#define SHARED_CLIENTS_NAME "/FTL-clients"
#define SHARED_QUERIES_NAME "/FTL-queries"
#define SHARED_FORWARDED_NAME "/FTL-forwarded"
#define SHARED_OVERTIME_NAME "/FTL-overTime"
#define SHARED_SETTINGS_NAME "/FTL-settings"

/// The pointer in shared memory to the shared string buffer
static SharedMemory shm_lock = { 0 };
static SharedMemory shm_strings = { 0 };
static SharedMemory shm_counters = { 0 };
static SharedMemory shm_domains = { 0 };
static SharedMemory shm_clients = { 0 };
static SharedMemory shm_queries = { 0 };
static SharedMemory shm_forwarded = { 0 };
static SharedMemory shm_overTime = { 0 };
static SharedMemory shm_settings = { 0 };

typedef struct {
	pthread_mutex_t lock;
	bool waitingForLock;
} ShmLock;
static ShmLock *shmLock = NULL;
static ShmSettings *shmSettings = NULL;

static int pagesize;
static unsigned int local_shm_counter = 0;

static size_t get_optimal_object_size(size_t objsize, size_t minsize);

unsigned long long addstr(const char *str)
{
	if(str == NULL)
	{
		logg("WARN: Called addstr() with NULL pointer");
		return 0;
	}

	// Get string length
	size_t len = strlen(str);

	// If this is an empty string, use the one at position zero
	if(len == 0) {
		return 0;
	}

	// Debugging output
	if(config.debug & DEBUG_SHMEM)
		logg("Adding \"%s\" (len %zu) to buffer. next_str_pos is %u", str, len, shmSettings->next_str_pos);

	// Reserve additional memory if necessary
	size_t required_size = shmSettings->next_str_pos + len + 1;
	// Need to cast to long long because size_t calculations cannot be negative
	if((long long)required_size-(long long)shm_strings.size > 0 &&
	   !realloc_shm(&shm_strings, shm_strings.size + pagesize, true))
		return 0;

	// Store new string buffer size in corresponding counters entry
	// for re-using when we need to re-map shared memory objects
	counters->strings_MAX = shm_strings.size;

	// Copy the C string pointed by str into the shared string buffer
	strncpy(&((char*)shm_strings.ptr)[shmSettings->next_str_pos], str, len);
	((char*)shm_strings.ptr)[shmSettings->next_str_pos + len] = '\0';

	// Increment string length counter
	shmSettings->next_str_pos += len+1;

	// Return start of stored string
	return (shmSettings->next_str_pos - (len + 1));
}

const char *getstr(unsigned long long pos)
{
	// Only access the string memory if this memory region has already been set
	if(pos < shmSettings->next_str_pos)
		return &((const char*)shm_strings.ptr)[pos];
	else
	{
		logg("WARN: Tried to access %llu but next_str_pos is %u", pos, shmSettings->next_str_pos);
		return "";
	}
}

/// Create a mutex for shared memory
pthread_mutex_t create_mutex() {
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

void remap_shm(void)
{
	// Remap shared object pointers which might have changed
	realloc_shm(&shm_queries, counters->queries_MAX*sizeof(queriesDataStruct), false);
	queries = (queriesDataStruct*)shm_queries.ptr;
	realloc_shm(&shm_domains, counters->domains_MAX*sizeof(domainsDataStruct), false);
	domains = (domainsDataStruct*)shm_domains.ptr;
	realloc_shm(&shm_clients, counters->clients_MAX*sizeof(clientsDataStruct), false);
	clients = (clientsDataStruct*)shm_clients.ptr;
	realloc_shm(&shm_forwarded, counters->forwarded_MAX*sizeof(forwardedDataStruct), false);
	forwarded = (forwardedDataStruct*)shm_forwarded.ptr;
	realloc_shm(&shm_strings, counters->strings_MAX, false);
	// strings are not exposed by a global pointer

	// Update local counter to reflect that we absorbed this change
	local_shm_counter = shmSettings->global_shm_counter;
}

void _lock_shm(const char* function, const int line, const char * file) {
	// Signal that FTL is waiting for a lock
	shmLock->waitingForLock = true;

	if(config.debug & DEBUG_LOCKS)
		logg("Waiting for lock in %s() (%s:%i)", function, file, line);

	int result = pthread_mutex_lock(&shmLock->lock);

	if(config.debug & DEBUG_LOCKS)
		logg("Obtained lock for %s() (%s:%i)", function, file, line);

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
		logg("Failed to obtain SHM lock: %s", strerror(result));
}

void _unlock_shm(const char* function, const int line, const char * file) {
	int result = pthread_mutex_unlock(&shmLock->lock);

	if(config.debug & DEBUG_LOCKS)
		logg("Removed lock in %s() (%s:%i)", function, file, line);

	if(result != 0)
		logg("Failed to unlock SHM lock: %s", strerror(result));
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
	shm_domains = create_shm(SHARED_DOMAINS_NAME, pagesize*sizeof(domainsDataStruct));
	domains = (domainsDataStruct*)shm_domains.ptr;
	counters->domains_MAX = pagesize;

	/****************************** shared clients struct ******************************/
	size_t size = get_optimal_object_size(sizeof(clientsDataStruct), 1);
	// Try to create shared memory object
	shm_clients = create_shm(SHARED_CLIENTS_NAME, size*sizeof(clientsDataStruct));
	clients = (clientsDataStruct*)shm_clients.ptr;
	counters->clients_MAX = size;

	/****************************** shared forwarded struct ******************************/
	size = get_optimal_object_size(sizeof(forwardedDataStruct), 1);
	// Try to create shared memory object
	shm_forwarded = create_shm(SHARED_FORWARDED_NAME, size*sizeof(forwardedDataStruct));
	forwarded = (forwardedDataStruct*)shm_forwarded.ptr;
	counters->forwarded_MAX = size;

	/****************************** shared queries struct ******************************/
	// Try to create shared memory object
	shm_queries = create_shm(SHARED_QUERIES_NAME, pagesize*sizeof(queriesDataStruct));
	queries = (queriesDataStruct*)shm_queries.ptr;
	counters->queries_MAX = pagesize;

	/****************************** shared overTime struct ******************************/
	size = get_optimal_object_size(sizeof(overTimeDataStruct), OVERTIME_SLOTS);
	// Try to create shared memory object
	shm_overTime = create_shm(SHARED_OVERTIME_NAME, size*sizeof(overTimeDataStruct));
	overTime = (overTimeDataStruct*)shm_overTime.ptr;
	initOverTime();

	return true;
}

void destroy_shmem(void)
{
	pthread_mutex_destroy(&shmLock->lock);
	shmLock = NULL;

	delete_shm(&shm_lock);
	delete_shm(&shm_strings);
	delete_shm(&shm_counters);
	delete_shm(&shm_domains);
	delete_shm(&shm_clients);
	delete_shm(&shm_queries);
	delete_shm(&shm_forwarded);
	delete_shm(&shm_overTime);
	delete_shm(&shm_settings);
}

SharedMemory create_shm(char *name, size_t size)
{
	if(config.debug & DEBUG_SHMEM)
		logg("Creating shared memory with name \"%s\" and size %zu", name, size);

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

	// Resize shared memory file
	int result = ftruncate(fd, size);

	// Check for `ftruncate` error
	if(result == -1)
	{
		logg("FATAL: create_shm(): ftruncate(%i, %zu): Failed to resize shared memory object \"%s\": %s",
		     fd, size, sharedMemory.name, strerror(errno));
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

void *enlarge_shmem_struct(char type)
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
			sizeofobj = sizeof(queriesDataStruct);
			counter = &counters->queries_MAX;
			break;
		case CLIENTS:
			sharedMemory = &shm_clients;
			allocation_step = get_optimal_object_size(sizeof(clientsDataStruct), 1);
			sizeofobj = sizeof(clientsDataStruct);
			counter = &counters->clients_MAX;
			break;
		case DOMAINS:
			sharedMemory = &shm_domains;
			allocation_step = pagesize;
			sizeofobj = sizeof(domainsDataStruct);
			counter = &counters->domains_MAX;
			break;
		case FORWARDED:
			sharedMemory = &shm_forwarded;
			allocation_step = get_optimal_object_size(sizeof(forwardedDataStruct), 1);
			sizeofobj = sizeof(forwardedDataStruct);
			counter = &counters->forwarded_MAX;
			break;
		default:
			logg("Invalid argument in enlarge_shmem_struct(): %i", type);
			return 0;
	}

	// Reallocate enough space for 4096 instances of requested object
	realloc_shm(sharedMemory, sharedMemory->size + allocation_step*sizeofobj, true);

	// Add allocated memory to corresponding counter
	*counter += allocation_step;

	return sharedMemory->ptr;
}

bool realloc_shm(SharedMemory *sharedMemory, size_t size, bool resize)
{
	// Check if we can skip this routine as nothing is to be done
	// when an object is not to be resized and its size didn't
	// change elsewhere
	if(!resize && size == sharedMemory->size)
		return true;

	// Log that we are doing something here
	logg("%s \"%s\" from %zu to %zu", resize ? "Resizing" : "Remapping", sharedMemory->name, sharedMemory->size, size);

	// Resize shard memory object if requested
	// If not, we only remap a shared memory object which might have changed
	// in another process. This happens when pihole-FTL forks due to incoming
	// TCP requests.
	if(resize)
	{
		// Open shared memory object
		int fd = shm_open(sharedMemory->name, O_RDWR, S_IRUSR | S_IWUSR);
		if(fd == -1)
		{
			logg("FATAL: realloc_shm(): Failed to open shared memory object \"%s\": %s",
			     sharedMemory->name, strerror(errno));
			exit(EXIT_FAILURE);
		}

		// Truncate shared memory object to specified size
		int result = ftruncate(fd, size);
		if(result == -1) {
			logg("FATAL: realloc_shm(): ftruncate(%i, %zu): Failed to resize \"%s\": %s",
			     fd, size, sharedMemory->name, strerror(errno));
			exit(EXIT_FAILURE);
		}

		// Close shared memory object file descriptor as it is no longer
		// needed after having called ftruncate()
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
	int ret;
	ret = munmap(sharedMemory->ptr, sharedMemory->size);
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
static size_t get_optimal_object_size(size_t objsize, size_t minsize)
{
	size_t optsize = pagesize / gcd(pagesize, objsize);
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
		size_t multiplier = (minsize/optsize) + ((minsize % optsize != 0) ? 1u : 0u);
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
