/* Pi-hole: A black hole for Internet advertisements
 *  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
 *  Network-wide ad blocking via your own hardware.
 *
 *  FTL Engine
 *  In-memory tar reading routines
 *
 *  This file is copyright under the latest version of the EUPL.
 *  Please see LICENSE file for your rights under this license. */

#include "zip/tar.h"
#include "log.h"

// TAR offsets
#define TAR_NAME_OFFSET 0
#define TAR_SIZE_OFFSET 124
#define TAR_MAGIC_OFFSET 257

// TAR constants
#define TAR_BLOCK_SIZE 512
#define TAR_NAME_SIZE 100
#define TAR_SIZE_SIZE 12
#define TAR_MAGIC_SIZE 5

static const char MAGIC_CONST[] = "ustar"; // Modern GNU tar's magic const */

/**
 * Find a file in a TAR archive
 * @param tarData Pointer to the TAR archive in memory
 * @param tarSize Size of the TAR archive in memory in bytes
 * @param fileName Name of the file to find
 * @param fileSize Pointer to a size_t variable to store the file size in
 * @return Pointer to the file data or NULL if not found
 */
const char * __attribute__((nonnull (1,3,4))) find_file_in_tar(const uint8_t *tarData, const size_t tarSize,
                                                               const char *fileName, size_t *fileSize)
{
	bool found = false;
	size_t size, p = 0, newOffset = 0;

	// Convert to char * to be able to do pointer arithmetic more easily
	const char *tar = (const char *)tarData;

	// Initialize fileSize to 0
	*fileSize = 0;

	// Loop through TAR file
	do
	{
		// "Load" data from tar - just point to passed memory
		const char *name = tar + TAR_NAME_OFFSET + p + newOffset;
		const char *sz = tar + TAR_SIZE_OFFSET + p + newOffset; // size str
		p += newOffset; // pointer to current file's data in TAR

		// Check for supported TAR version or end of TAR
		for (size_t i = 0; i < TAR_MAGIC_SIZE; i++)
			if (tar[i + TAR_MAGIC_OFFSET + p] != MAGIC_CONST[i])
				return NULL;

		// Convert file size from string into integer
		size = 0;
		for (ssize_t i = TAR_SIZE_SIZE - 2, mul = 1; i >= 0; mul *= 8, i--) // Octal str to int
			if ((sz[i] >= '1') && (sz[i] <= '9'))
				size += (sz[i] - '0') * mul;

		//Offset size in bytes. Depends on file size and TAR block size
		newOffset = (1 + size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE; //trim by block
		if ((size % TAR_BLOCK_SIZE) > 0)
			newOffset += TAR_BLOCK_SIZE;

		found = strncmp(name, fileName, TAR_NAME_SIZE) == 0;
	} while (!found && (p + newOffset + TAR_BLOCK_SIZE <= tarSize));

	if (!found)
		return NULL; // No file found in TAR - return NULL

	// File found in TAR - return pointer to file data and set fileSize
	*fileSize = size;
	return tar + p + TAR_BLOCK_SIZE;
}

/**
 * List all files in a TAR archive
 * @param tarData Pointer to the TAR archive in memory
 * @param tarSize Size of the TAR archive in memory in bytes
 * @return Pointer to a cJSON array containing all file names with file size
 */
cJSON * __attribute__((nonnull (1))) list_files_in_tar(const uint8_t *tarData, const size_t tarSize)
{
	cJSON *files = cJSON_CreateArray();
	size_t size, p = 0, newOffset = 0;

	// Convert to char * to be able to do pointer arithmetic more easily
	const char *tar = (const char *)tarData;

	// Loop through TAR file
	do
	{
		// "Load" data from tar - just point to passed memory
		const char *name = tar + TAR_NAME_OFFSET + p + newOffset;
		const char *sz = tar + TAR_SIZE_OFFSET + p + newOffset; // size str
		p += newOffset; // pointer to current file's data in TAR

		// Check for supported TAR version or end of TAR
		for (size_t i = 0; i < TAR_MAGIC_SIZE; i++)
			if (tar[i + TAR_MAGIC_OFFSET + p] != MAGIC_CONST[i])
				return files;

		// Convert file size from string into integer
		size = 0;
		for (ssize_t i = TAR_SIZE_SIZE - 2, mul = 1; i >= 0; mul *= 8, i--) // Octal str to int
			if ((sz[i] >= '1') && (sz[i] <= '9'))
				size += (sz[i] - '0') * mul;

		//Offset size in bytes. Depends on file size and TAR block size
		newOffset = (1 + size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE; //trim by block
		if ((size % TAR_BLOCK_SIZE) > 0)
			newOffset += TAR_BLOCK_SIZE;

		// Add file name to cJSON array
		cJSON *file = cJSON_CreateObject();
		cJSON_AddItemToObject(file, "name", cJSON_CreateString(name));
		cJSON_AddItemToObject(file, "size", cJSON_CreateNumber(size));
		cJSON_AddItemToArray(files, file);
	} while (p + newOffset + TAR_BLOCK_SIZE <= tarSize);

	return files;
}