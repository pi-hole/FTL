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
#define SHARED_STRINGS_NAME "FTL-strings"
#define SHARED_DOMAINS_NAME "FTL-domains"

/// The pointer in shared memory to the shared string buffer
static SharedMemory shm_strings = { 0 };
static SharedMemory shm_domains = { 0 };

static int pagesize;
static unsigned int next_pos = 0;

unsigned int addstr(const char *str)
{
	if(str == NULL)
	{
		logg("WARN: Called addstr() with NULL pointer");
		return 0;
	}

	// Get string length
	int len = strlen(str);

	if(debug) logg("Adding \"%s\" (len %i) to buffer. next_pos is %i", str, len, next_pos);

	// Reserve additional memory if necessary
	size_t required_size = next_pos + len + 1;
	// Need to cast to long long because size_t calculations cannot be negative
	if((long long)required_size-(long long)shm_strings.size > 0 && !realloc_shm(&shm_strings, shm_strings.size + pagesize))
		return 0;

	// Copy the C string pointed by str into the shared string buffer
	strncpy(&shm_strings.ptr[next_pos], str, len);
	shm_strings.ptr[next_pos + len] = '\0';

	// Increment string length counter
	next_pos += len+2;

	// Return start of stored string
	return (next_pos - (len+2));
}

char *getstr(unsigned int pos)
{
	return shm_strings.ptr + pos;
}

bool init_shmem(void)
{
	// Get kernel's page size
	pagesize = getpagesize();

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
	shm_strings.ptr[0] = '\0';
	next_pos = 1;

	/****************************** shared domains struct ******************************/
	shm_unlink(SHARED_DOMAINS_NAME);

	// Try to create shared memory object
	shm_domains = create_shm(SHARED_DOMAINS_NAME, 1);
	if(shm_domains.ptr == NULL)
		return false;

	return true;
}

SharedMemory create_shm(char *name, size_t size)
{
	if(debug) logg("Creating shared memory with name \"%s\" and size %zu", name, size);

	SharedMemory sharedMemory = {
		.fd = 0,
		.name = name,
		.size = size,
		.ptr = NULL
	};

	// Create the shared memory file in read/write mode with 600 permissions
	sharedMemory.fd = shm_open(name, O_CREAT | O_EXCL | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);

	// Check for `shm_open` error
	if(sharedMemory.fd == -1)
	{
		logg("create_shm(): Failed to create_shm shared memory object \"%s\": %s",
		     name, strerror(errno));
		return sharedMemory;
	}

	// Resize shared memory file
	int result = ftruncate(sharedMemory.fd, size);

	// Check for `ftruncate` error
	if(result == -1)
	{
		logg("create_shm(): ftruncate(%i, %zu): Failed to resize shared memory object \"%s\": %s",
		     sharedMemory.fd, size, sharedMemory.name, strerror(errno));
		return sharedMemory;
	}

	// Create shared memory mapping
	void *shm = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, sharedMemory.fd, 0);

	// Check for `mmap` error
	if(shm == MAP_FAILED)
	{
		logg("create_shm(): Failed to map shared memory object \"%s\" (%i): %s",
		     sharedMemory.name, sharedMemory.fd, strerror(errno));
		return sharedMemory;
	}

	sharedMemory.ptr = shm;
	return sharedMemory;
}

bool realloc_shm(SharedMemory *sharedMemory, size_t size) {
	if(debug) logg("Resizing \"%s\" from %zu to %zu", sharedMemory->name, sharedMemory->size, size);

	int result = ftruncate(sharedMemory->fd, size);
	if(result == -1) {
		logg("realloc_shm(%i, %zu): ftruncate(%i, %zu): Failed to resize \"%s\": %s",
		     sharedMemory->fd, size, sharedMemory->name, strerror(errno));
		return false;
	}

#if 1
	void *new_ptr = mremap(sharedMemory->ptr, sharedMemory->size, size, MREMAP_MAYMOVE);
#else
	result = munmap(sharedMemory->ptr, sharedMemory->size);
	if(result != 0)
		logg("realloc_shm(): munmap(%p, %zu) failed: %s", sharedMemory->ptr, sharedMemory->size, strerror(errno));

	void *new_ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, sharedMemory->fd, 0);
#endif
	if(new_ptr == MAP_FAILED)
	{
		logg("realloc_shm(): mremap(%p, %zu, %zu, MREMAP_MAYMOVE): Failed to reallocate \"%s\" (%i): %s",
		     sharedMemory->ptr, sharedMemory->size, size, sharedMemory->name, sharedMemory->fd,
		     strerror(errno));
		return false;
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
		logg("delete_shm(): munmap(%s) failed: %s", sharedMemory->name, strerror(errno));
}
