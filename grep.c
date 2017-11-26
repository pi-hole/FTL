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

void readWildcardsList();

char ** wildcarddomains = NULL;

void read_gravity_files(void)
{
	// Get number of domains being blocked
	int gravity = countlines(files.gravity);
	int blacklist = countlines(files.blacklist);

	if(gravity < 0)
	{
		logg("Error: failed to read %s", files.gravity);
	}
	logg("Gravity list entries: %i", gravity);

	// Test if blacklist exists and has entries in it
	if(blacklist > 0)
	{
		gravity += blacklist;
		logg("Blacklist entries: %i", blacklist);
	}
	else
	{
		logg("No blacklist present");
	}

	counters.gravity = gravity;

	// Read array of wildcards
	readWildcardsList();
	if(counters.wildcarddomains > 0)
	{
		logg("Wildcard blocking list entries: %i", counters.wildcarddomains);
	}
	else
	{
		logg("No wildcard blocking list present");
	}

	// Get blocking status
	check_blocking_status();
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
	fclose(fp);

	return lines;
}

void readWildcardsList()
{
	FILE *fp;
	char *domain = NULL, *buffer = NULL, *linebuffer = NULL;
	size_t size = 0;
	int i;

	if((fp = fopen(files.wildcards, "r")) == NULL) {
		counters.wildcarddomains = -1;
		return;
	}
	else
	{
		// Opening of the wildcards file succeeded - reset wildcard counter
		if(counters.wildcarddomains < 0) counters.wildcarddomains = 0;
	}

	// Search through file
	errno = 0;
	while(getline(&linebuffer, &size, fp) != -1)
	{
		// the read line has always to be larger than what we want to extract, so
		// we can use the length as an upper limit for allocating memory for the buffer

		buffer = calloc(size, 1);
		if(buffer == NULL)
		{
			logg("WARN: readWildcardsList failed to allocate memory");
			fclose(fp);

			// Free allocated memory
			free(linebuffer);

			return;
		}
		// Try to read up to 511 characters
		if(sscanf(linebuffer, "address=/%511[^/]/%*[^\n]\n", buffer) > 0)
		{
			unsigned long int addrbuffer = 0;
			// Skip leading '.' by incrementing memory location step by step until the first
			// character is not a '.' anymore
			while(*(buffer+addrbuffer) == '.' && addrbuffer < strlen(buffer)) addrbuffer++;
			if(strlen(buffer+addrbuffer) == 0)
			{
				logg("WARNING: Invalid wildcard list entry found: %s", buffer);
			}
			else
			{
				bool known = false;
				// Get pointer to string with stripped leading '.'
				domain = buffer+addrbuffer;
				for(i=0; i < counters.wildcarddomains; i++)
				{
					if(strcmp(wildcarddomains[i], domain) == 0)
					{
						// We know this domain already, let's skip it
						known = true;
						break;
					}
				}
				if(known)
				{
					// Free allocated memory
					free(buffer);
					buffer = NULL;
					continue;
				}

				// Add wildcard entry
				// Enlarge wildcarddomains pointer array
				memory_check(WILDCARD);
				// Allocate space for new domain entry and save domain
				wildcarddomains[counters.wildcarddomains] = calloc(strlen(domain)+1,sizeof(char));
				memory.wildcarddomains += (strlen(domain) + 1) * sizeof(char);
				strcpy(wildcarddomains[counters.wildcarddomains], domain);

				// Increase number of stored wildcards by one
				counters.wildcarddomains++;
			}
		}

		// Free allocated memory
		free(buffer);
		buffer = NULL;
	}

	if(errno == ENOMEM)
		logg("WARN: readWildcardsList failed: could not allocate memory for getline");

	// Free allocated memory
	if(linebuffer != NULL)
	{
		free(linebuffer);
		linebuffer = NULL;
	}

	// Close the file
	fclose(fp);

}

int countlineswith(const char* str, const char* fname)
{
	FILE *fp;
	int found = 0;
	char *buffer = NULL;
	size_t size = 0;

	if((fp = fopen(fname, "r")) == NULL) {
		return -1;
	}

	// Search through file
	// getline reads a string from the specified file up to either a newline character or EOF
	while(getline(&buffer, &size, fp) != -1)
		if((strstr(buffer, str)) != NULL)
			found++;

	// Free allocated memory
	if(buffer != NULL)
	{
		free(buffer);
		buffer = NULL;
	}

	// Close the file
	fclose(fp);

	return found;
}

void check_blocking_status(void)
{
	int disabled = countlineswith("#addn-hosts=/etc/pihole/gravity.list",files.dnsmasqconfig);

	if(disabled < 0)
		// Failed to open file -> unknown status
		blockingstatus = 2;
	else if(disabled > 0)
		// Disabled
		blockingstatus = 0;
	else
		// Enabled
		blockingstatus = 1;
}
