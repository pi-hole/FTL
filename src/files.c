/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  File operation routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "files.h"
#include "memory.h"
#include "config.h"
#include "setupVars.h"
#include "log.h"

// chmod_file() changes the file mode bits of a given file (relative
// to the directory file descriptor) according to mode. mode is an
// octal number representing the bit pattern for the new mode bits
bool chmod_file(const char *filename, const mode_t mode)
{
	if(chmod(filename, mode) < 0)
	{
		logg("WARNING: chmod(%s, %d): chmod() failed: %s (%d)", filename, mode, strerror(errno), errno);
		return false;
	}

	struct stat st;
	if(stat(filename, &st) < 0)
	{
		logg("WARNING: chmod(%s, %d): stat() failed: %s (%d)", filename, mode, strerror(errno), errno);
		return false;
	}

	// We need to apply a bitmask on st.st_mode as the upper bits may contain random data
	// 0x1FF = 0b111_111_111 corresponding to the three-digit octal mode number
	if((st.st_mode & 0x1FF) != mode)
	{
		logg("WARNING: chmod(%s, %d): Verification failed, %d != %d", filename, mode, st.st_mode, mode);
		return false;
	}

	return true;
}

bool file_exists(const char *filename)
{
	struct stat st;
	return stat(filename, &st) == 0;
}

long int get_FTL_db_filesize(void)
{
	struct stat st;
	if(stat(FTLfiles.FTL_db, &st) != 0)
	{
		// stat() failed (maybe the DB file does not exist?)
		return 0;
	}
	return st.st_size;
}
