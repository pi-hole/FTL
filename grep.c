/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  grep-like routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

void read_gravity_files(void)
{
	// Get number of domains being blocked
	int gravity = countlines(files.gravity);
	int blacklist = countlines(files.blacklist);

	if(gravity < 0)
	{
		logg_str("Error: failed to read ", (char*)files.gravity);
	}
	logg_int("Gravity list entries: ",gravity);

	// Test if blacklist exists and has entries in it
	if(blacklist > 0)
	{
		gravity += blacklist;
	}
	logg_int("Blacklist entries: ", blacklist);

	counters.gravity = gravity;
}

int countlines(const char* fname)
{
	FILE *fp;
	int ch = 0;
	int lines = 0;

	if((fp = fopen(fname, "r")) == NULL) {
		return -1;
	}

	while ((ch = fgetc(fp)) != EOF)
		if (ch=='\n')
			++lines;

	// Close the file
	if(fp) {
		fclose(fp);
	}

	return lines;
}

int countlineswith(const char* str, const char* fname)
{
	FILE *fp;
	int found = 0;
	char buffer[512];

	if((fp = fopen(fname, "r")) == NULL) {
		return -1;
	}

	// Search through file
	// fgets reads a string from the specified file up to either a newline character or EOF
	while(fgets(buffer, sizeof(buffer), fp) != NULL)
		if((strstr(buffer, str)) != NULL)
			found++;

	// Close the file
	if(fp) {
		fclose(fp);
	}

	return found;
}
