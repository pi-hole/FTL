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

/// The name of the shared memory. Use this when connecting to the shared memory.
#define SHARED_LOCK_NAME "/FTL-lock"
#define SHARED_STRINGS_NAME "/FTL-strings"
#define SHARED_COUNTERS_NAME "/FTL-counters"
#define SHARED_DOMAINS_NAME "/FTL-domains"
#define SHARED_CLIENTS_NAME "/FTL-clients"
#define SHARED_QUERIES_NAME "/FTL-queries"
#define SHARED_FORWARDED_NAME "/FTL-forwarded"
#define SHARED_OVERTIME_NAME "/FTL-overTime"
#define SHARED_OVERTIMECLIENT_PREFIX "/FTL-client-"

/// The pointer in shared memory to the shared string buffer
static SharedMemory shm_lock = { 0 };
static SharedMemory shm_strings = { 0 };
static SharedMemory shm_counters = { 0 };
static SharedMemory shm_domains = { 0 };
static SharedMemory shm_clients = { 0 };
static SharedMemory shm_queries = { 0 };
static SharedMemory shm_forwarded = { 0 };
static SharedMemory shm_overTime = { 0 };

static SharedMemory *shm_overTimeClients = NULL;
static int overTimeClientCount = 0;

typedef struct {
	pthread_mutex_t lock;
	bool waitingForLock;
} ShmLock;
static ShmLock *shmLock = NULL;

static int pagesize;
static unsigned int next_pos = 0;

unsigned long long addstr(const char *str)
{
	if(str == NULL)
	{
		logg("WARN: Called addstr() with NULL pointer");
		return 0;
	}

	// Get string length
	size_t len = strlen(str);

	if(debug) logg("Adding \"%s\" (len %i) to buffer. next_pos is %i", str, len, next_pos);

	// Reserve additional memory if necessary
	size_t required_size = next_pos + len + 1;
	// Need to cast to long long because size_t calculations cannot be negative
	if((long long)required_size-(long long)shm_strings.size > 0 &&
	   !realloc_shm(&shm_strings, shm_strings.size + pagesize))
		return 0;

	// Copy the C string pointed by str into the shared string buffer
	strncpy(&((char*)shm_strings.ptr)[next_pos], str, len);
	((char*)shm_strings.ptr)[next_pos + len] = '\0';

	// Increment string length counter
	next_pos += len+1;

	// Return start of stored string
	return (next_pos - (len + 1));
}

char *getstr(unsigned long long pos)
{
	return &((char*)shm_strings.ptr)[pos];
}

static char *clientShmName(int id) {
	int name_len = 1 + snprintf(NULL, 0, "%s%d", SHARED_OVERTIMECLIENT_PREFIX, id);
	char *name = malloc(sizeof(char) * name_len);
	snprintf(name, (size_t) name_len, "%s%d", SHARED_OVERTIMECLIENT_PREFIX, id);

	return name;
}

void newOverTimeClient() {
	// Get the name of the new shared memory.
	// This will be used in the struct, so it should not be immediately freed.
	char *name = clientShmName(overTimeClientCount);

	// Create the shared memory with enough space for the current overTime slots
	shm_unlink(name);
	SharedMemory shm = create_shm(name, (counters->overTime/pagesize + 1)*pagesize*sizeof(int));
	if(shm.ptr == NULL) {
		free(shm.name);
		logg("Failed to initialize new overTime client %d", overTimeClientCount);
		return;
	}

	// Make space for the new shared memory
	shm_overTimeClients = realloc(shm_overTimeClients, sizeof(SharedMemory) * (overTimeClientCount + 1));
	overTimeClientCount++;
	shm_overTimeClients[overTimeClientCount-1] = shm;

	// Add to overTimeClientData
	overTimeClientData = realloc(overTimeClientData, sizeof(int*) * (overTimeClientCount));
	overTimeClientData[overTimeClientCount-1] = shm.ptr;
}

void addOverTimeClientSlot() {
	// For each client slot, add pagesize overTime slots
	for(int i = 0; i < overTimeClientCount; i++)
	{
		// Only increase the size of the shm object if needed
		// shm_overTimeClients[i].size stores the size of the memory in bytes whereas
		// counters->overTime (effectively) stores the number of slots each overTime
		// client should have. Hence, counters->overTime needs to be multiplied by
		// sizeof(int) to get the actual requested memory size
		if(shm_overTimeClients[i].size > (size_t)counters->overTime*sizeof(int))
			continue;

		// Reallocate with one more slot
		realloc_shm(&shm_overTimeClients[i], (counters->overTime + pagesize)*sizeof(int));

		// Update overTimeClientData
		overTimeClientData[i] = shm_overTimeClients[i].ptr;
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

void _lock_shm(const char* function, const int line, const char * file) {
	// Signal that FTL is waiting for a lock
	shmLock->waitingForLock = true;

	if(debug) logg("Waiting for lock in %s() (%s:%i)", function, file, line);

	int result = pthread_mutex_lock(&shmLock->lock);

	if(debug) logg("Obtained lock for %s() (%s:%i)", function, file, line);

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

	if(debug) logg("Removed lock in %s() (%s:%i)", function, file, line);

	if(result != 0)
		logg("Failed to unlock SHM lock: %s", strerror(result));
}

bool init_shmem(void)
{
	// Get kernel's page size
	pagesize = getpagesize();

	/****************************** shared memory lock ******************************/
	shm_unlink(SHARED_LOCK_NAME);
	// Try to create shared memory object
	shm_lock = create_shm(SHARED_LOCK_NAME, sizeof(ShmLock));
	if(shm_lock.ptr == NULL)
		return false;
	shmLock = (ShmLock*) shm_lock.ptr;
	shmLock->lock = create_mutex();
	shmLock->waitingForLock = false;

	/****************************** shared strings buffer ******************************/
	// Try unlinking the shared memory object before creating a new one
	// If the object is still existing, e.g., due to a past unclean exit
	// of FTL, shm_open() would fail with error "File exists"
	shm_unlink(SHARED_STRINGS_NAME);
	// Try to create shared memory object
	shm_strings = create_shm(SHARED_STRINGS_NAME, pagesize);
	if(shm_strings.ptr == NULL)
		return false;

	// Initialize shared string object with an empty string at position zero
	((char*)shm_strings.ptr)[0] = '\0';
	next_pos = 1;

	/****************************** shared counters struct ******************************/
	shm_unlink(SHARED_COUNTERS_NAME);
	// Try to create shared memory object
	shm_counters = create_shm(SHARED_COUNTERS_NAME, sizeof(countersStruct));
	if(shm_counters.ptr == NULL)
		return false;
	counters = (countersStruct*)shm_counters.ptr;

	/****************************** shared domains struct ******************************/
	shm_unlink(SHARED_DOMAINS_NAME);
	// Try to create shared memory object
	shm_domains = create_shm(SHARED_DOMAINS_NAME, pagesize*sizeof(domainsDataStruct));
	if(shm_domains.ptr == NULL)
		return false;
	domains = (domainsDataStruct*)shm_domains.ptr;
	counters->domains_MAX = pagesize;

	/****************************** shared clients struct ******************************/
	shm_unlink(SHARED_CLIENTS_NAME);
	// Try to create shared memory object
	shm_clients = create_shm(SHARED_CLIENTS_NAME, pagesize*sizeof(clientsDataStruct));
	if(shm_clients.ptr == NULL)
		return false;
	clients = (clientsDataStruct*)shm_clients.ptr;
	counters->clients_MAX = pagesize;

	/****************************** shared forwarded struct ******************************/
	shm_unlink(SHARED_FORWARDED_NAME);
	// Try to create shared memory object
	shm_forwarded = create_shm(SHARED_FORWARDED_NAME, pagesize*sizeof(forwardedDataStruct));
	if(shm_forwarded.ptr == NULL)
		return false;
	forwarded = (forwardedDataStruct*)shm_forwarded.ptr;
	counters->forwarded_MAX = pagesize;

	/****************************** shared queries struct ******************************/
	shm_unlink(SHARED_QUERIES_NAME);
	// Try to create shared memory object
	shm_queries = create_shm(SHARED_QUERIES_NAME, pagesize*sizeof(queriesDataStruct));
	if(shm_queries.ptr == NULL)
		return false;
	queries = (queriesDataStruct*)shm_queries.ptr;
	counters->queries_MAX = pagesize;

	/****************************** shared overTime struct ******************************/
	shm_unlink(SHARED_OVERTIME_NAME);
	// Try to create shared memory object
	shm_overTime = create_shm(SHARED_OVERTIME_NAME, pagesize*sizeof(overTimeDataStruct));
	if(shm_overTime.ptr == NULL)
		return false;
	overTime = (overTimeDataStruct*)shm_overTime.ptr;
	counters->overTime_MAX = pagesize;

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

	for(int i = 0; i < overTimeClientCount; i++) {
		delete_shm(&shm_overTimeClients[i]);
		free(shm_overTimeClients[i].name);
	}
}

SharedMemory create_shm(char *name, size_t size)
{
	if(debug) logg("Creating shared memory with name \"%s\" and size %zu", name, size);

	SharedMemory sharedMemory = {
		.name = name,
		.size = size,
		.ptr = NULL
	};

	// Create the shared memory file in read/write mode with 600 permissions
	int fd = shm_open(sharedMemory.name, O_CREAT | O_EXCL | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);

	// Check for `shm_open` error
	if(fd == -1)
	{
		logg("create_shm(): Failed to create_shm shared memory object \"%s\": %s",
		     name, strerror(errno));
		return sharedMemory;
	}

	// Resize shared memory file
	int result = ftruncate(fd, size);

	// Check for `ftruncate` error
	if(result == -1)
	{
		logg("create_shm(): ftruncate(%i, %zu): Failed to resize shared memory object \"%s\": %s",
		     fd, size, sharedMemory.name, strerror(errno));
		return sharedMemory;
	}

	// Create shared memory mapping
	void *shm = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	// Check for `mmap` error
	if(shm == MAP_FAILED)
	{
		logg("create_shm(): Failed to map shared memory object \"%s\" (%i): %s",
		     sharedMemory.name, fd, strerror(errno));
		return sharedMemory;
	}

	// Close shared memory object file descriptor as it is no longer
	// needed after having called mmap()
	close(fd);

	sharedMemory.ptr = shm;
	return sharedMemory;
}

void *enlarge_shmem_struct(char type)
{
	SharedMemory *sharedMemory;
	size_t sizeofobj;
	int *counter;

	// Select type of struct that should be enlarged
	switch(type)
	{
		case QUERIES:
			sharedMemory = &shm_queries;
			sizeofobj = sizeof(queriesDataStruct);
			counter = &counters->queries_MAX;
			break;
		case CLIENTS:
			sharedMemory = &shm_clients;
			sizeofobj = sizeof(clientsDataStruct);
			counter = &counters->clients_MAX;
			break;
		case DOMAINS:
			sharedMemory = &shm_domains;
			sizeofobj = sizeof(domainsDataStruct);
			counter = &counters->domains_MAX;
			break;
		case FORWARDED:
			sharedMemory = &shm_forwarded;
			sizeofobj = sizeof(forwardedDataStruct);
			counter = &counters->forwarded_MAX;
			break;
		case OVERTIME:
			sharedMemory = &shm_overTime;
			sizeofobj = sizeof(overTimeDataStruct);
			counter = &counters->overTime_MAX;
			break;
		default:
			logg("Invalid argument in enlarge_shmem_struct(): %i", type);
			return 0;
	}

	// Reallocate enough space for 4096 instances of requested object
	realloc_shm(sharedMemory, sharedMemory->size + pagesize*sizeofobj);

	// Add allocated memory to corresponding counter
	*counter += pagesize;

	return sharedMemory->ptr;
}

bool realloc_shm(SharedMemory *sharedMemory, size_t size) {
	logg("Resizing \"%s\" from %zu to %zu", sharedMemory->name, sharedMemory->size, size);

	int result = munmap(sharedMemory->ptr, sharedMemory->size);
	if(result != 0)
		logg("realloc_shm(): munmap(%p, %zu) failed: %s", sharedMemory->ptr, sharedMemory->size, strerror(errno));

	// Open shared memory object
	int fd = shm_open(sharedMemory->name, O_RDWR, S_IRUSR | S_IWUSR);
	if(fd == -1)
	{
		logg("realloc_shm(): Failed to open shared memory object \"%s\": %s",
		     sharedMemory->name, strerror(errno));
		return false;
	}

	// Resize shard memory object to requested size
	result = ftruncate(fd, size);
	if(result == -1) {
		logg("realloc_shm(): ftruncate(%i, %zu): Failed to resize \"%s\": %s",
		     fd, size, sharedMemory->name, strerror(errno));
		return false;
	}

//	void *new_ptr = mremap(sharedMemory->ptr, sharedMemory->size, size, MREMAP_MAYMOVE);
	void *new_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if(new_ptr == MAP_FAILED)
	{
		logg("realloc_shm(): mremap(%p, %zu, %zu, MREMAP_MAYMOVE): Failed to reallocate \"%s\" (%i): %s",
		     sharedMemory->ptr, sharedMemory->size, size, sharedMemory->name, fd,
		     strerror(errno));
		return false;
	}

	// Close shared memory object file descriptor as it is no longer
	// needed after having called mmap()
	close(fd);

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
		logg("delete_shm(): munmap(%s) failed: %s", sharedMemory->name, strerror(errno));
}
