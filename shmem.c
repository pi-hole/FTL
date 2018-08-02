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

/// The pointer in shared memory to the shared string buffer
static SharedMemory strBuffer = { 0 };

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

	// Reserve memory (will later be replaced for shmem)
	if(!realloc_shm(&strBuffer, next_pos + len + 1))
		return 0;
	strBuffer.size = next_pos + len + 1;

	// Copy the C string pointed by str into the shared string buffer
	char *buffer = strBuffer.ptr + next_pos;
	strncpy(buffer, str, len);
	buffer[len] = '\0';

	// Increment string length counter
	next_pos += len+2;

	// Return start of stored string
	return (next_pos - (len+2));
}

char *getstr(unsigned int pos)
{
	return strBuffer.ptr + pos;
}

bool init_shmem(void)
{
	// Try unlinking the shared memory object before creating a new one
	// If the object is still existing, e.g., due to a past unclean exit
	// of FTL, shm_open() would fail with error "File exists"
	shm_unlink(SHARED_STRINGS_NAME);

	// Try to create shared memory object
	strBuffer = create_shm(SHARED_STRINGS_NAME, 1);
	if(strBuffer.ptr == NULL)
		return false;

	logg("Created shared memory with name \"%s\" (%i)", strBuffer.name, strBuffer.fd);

	// Initialize shared string object with an empty string at position zero
	char *buffer = strBuffer.ptr;
	buffer[0] = '\0';
	next_pos = 1;

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
		if(debug) logg("Failed to create_shm shared memory: %s", strerror(errno));
		return sharedMemory;
	}

	// Resize shared memory file
	int result = ftruncate(sharedMemory.fd, size);

	// Check for `ftruncate` error
	if(result == -1)
	{
		if(debug) logg("Failed to resize shared memory: %s", strerror(errno));
		return sharedMemory;
	}

	// Create shared memory mapping
	void *shm = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, sharedMemory.fd, 0);

	// Check for `mmap` error
	if(shm == MAP_FAILED)
	{
		if(debug) logg("Failed to map shared memory: %s", strerror(errno));
		return sharedMemory;
	}

	sharedMemory.ptr = shm;
	return sharedMemory;
}

bool realloc_shm(SharedMemory *sharedMemory, size_t size) {
	if(debug) logg("Resizing \"%s\" from %zu to %zu", sharedMemory->name, sharedMemory->size, size);

	int result = ftruncate(sharedMemory->fd, size);

	if(result == -1) {
		if(debug) logg("Failed to resize \"%s\" (%i): %s", sharedMemory->name, sharedMemory->fd, strerror(errno));
		return false;
	}

	void *new_ptr = mremap(sharedMemory->ptr, sharedMemory->size, size, MREMAP_MAYMOVE);

	if(new_ptr == MAP_FAILED)
	{
		if(debug) logg("Failed to reallocate \"%s\" (%i): %s", sharedMemory->name, sharedMemory->fd, strerror(errno));
		return false;
	}

	sharedMemory->ptr = new_ptr;
	sharedMemory->size = size;

	return true;
}

void delete_shm(SharedMemory *sharedMemory)
{
	// Unmap shared memory
	munmap(sharedMemory->ptr, sharedMemory->size);

	// Now you can no longer `shm_open` the memory,
	// and once all others unlink, it will be destroyed.
	shm_unlink(sharedMemory->name);
}
