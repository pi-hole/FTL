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

typedef struct {
    const char *name;
    size_t size;
    void *ptr;
} SharedMemory;

/// Create shared memory
///
/// \param name the name of the shared memory
/// \param size the size to allocate
/// \return a structure with a pointer to the mounted shared memory. The pointer
/// will always be valid, because if it failed FTL will have exited.
SharedMemory create_shm(const char *name, const size_t size);

/// Reallocate shared memory
///
/// \param sharedMemory the shared memory struct
/// \param size the new size
/// \param resize whether the object should be resized or only remapped
/// \return if reallocation was successful
bool realloc_shm(SharedMemory *sharedMemory, const size_t size, const bool resize);

/// Disconnect from shared memory. If there are no other connections to shared memory, it will be deleted.
///
/// \param sharedMemory the shared memory struct
void delete_shm(SharedMemory *sharedMemory);

/// Block until a lock can be obtained
#define lock_shm() _lock_shm(__FUNCTION__, __LINE__, __FILE__);
void _lock_shm(const char* func, const int line, const char* file);

/// Unlock the lock. Only call this if there is an active lock.
#define unlock_shm() _unlock_shm(__FUNCTION__, __LINE__, __FILE__);
void _unlock_shm(const char* func, const int line, const char* file);

#endif //SHARED_MEMORY_SERVER_H
