/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Teleporter un-/compression routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "miniz/teleporter.h"
#include "config/config.h"

const char *generate_teleporter_zip(mz_zip_archive *zip, void *ptr, size_t *size)
{
	// Initialize ZIP archive
	memset(zip, 0, sizeof(*zip));

	// Start with 64KB allocation size (pihole.TOML is slightly larger than 32KB
	// at the time of writing thjs)
	if(!mz_zip_writer_init_heap(zip, 0, 64*1024))
	{
		return "Failed creating heap ZIP archive";
	}

	// Add pihole.toml to the ZIP archive
	const char *file_comment = "Pi-hole's configuration";
	if(!mz_zip_writer_add_file(zip, "pihole.toml", GLOBALTOMLPATH, file_comment, (uint16_t)strlen(file_comment), MZ_BEST_COMPRESSION))
	{
		mz_zip_writer_end(zip);
		return "Failed to add "GLOBALTOMLPATH" to heap ZIP archive!";
	}

	// Get the heap data so we can send it to the requesting client
	if(!mz_zip_writer_finalize_heap_archive(zip, ptr, size))
	{
		mz_zip_writer_end(zip);
		return "Failed to finalize heap ZIP archive!";
	}

	// Everything worked well
	return NULL;
}

bool free_teleporter_zip(mz_zip_archive *zip)
{
	return mz_zip_writer_end(zip);
}