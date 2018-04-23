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

char ** wildcarddomains = NULL;
unsigned char blockingstatus = 2;

// Private prototype
void readWildcardsList(void);

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

int readnumberfromfile(const char* fname)
{
	FILE *fp;
	int num;

	if((fp = fopen(fname, "r")) == NULL)
	{
		return -1;
	}

	if(fscanf(fp,"%i",&num) != 1)
	{
		num = -1;
	}

	fclose(fp);
	return num;
}

void readGravityFiles(void)
{
	// Get number of domains being blocked by wildcards
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

void readWildcardsList(void)
{
	FILE *fp;
	char *domain = NULL, *buffer = NULL, *linebuffer = NULL;
	size_t size = 0;
	int i;

	// Free maybe already allocated wildcard domains
	if(counters.wildcarddomains > 0) freeWildcards();

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

		// Trim off the newline (could even be CR-LF)
		linebuffer[strcspn(linebuffer, "\r\n")] = 0;

		// Try to read up to 511 characters
		if(sscanf(linebuffer, "address=/%511[^/]/", buffer) > 0)
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
				if(wildcarddomains[counters.wildcarddomains] == NULL) return;
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

void freeWildcards(void)
{
	// wildcarddomains struct: Free allocated substructure
	int i;
	for(i=0;i<counters.wildcarddomains;i++)
	{
		free(wildcarddomains[i]);
	}
	free(wildcarddomains);
	wildcarddomains = NULL;
	memory.wildcarddomains = 0;
	counters.wildcarddomains = 0;
	counters.wildcarddomains_MAX = 0;
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
	// getline reads a string from the specified file up to either a
	// newline character or EOF
	while(getline(&buffer, &size, fp) != -1)
	{
		// Strip potential newline character at the end of line we just read
		if(buffer[strlen(buffer)-1] == '\n')
			buffer[strlen(buffer)-1] = '\0';

		// Search for exact match
		if(strcmp(buffer, str) == 0)
		{
			found++;
			continue;
		}

		// If line starts with *, search for partial match of
		// needle "buffer+1" in haystack "str"
		if(buffer[0] == '*')
		{
			char * buf = strstr(str, buffer+1);
			// The  strstr() function finds the first occurrence of
			// the substring buffer+1 in the string str.
			// These functions return a pointer to the beginning of
			// the located substring, or NULL if the substring is not
			// found. Hence, we compare the length of the substring to
			// the wildcard entry to rule out the possiblity that
			// there is anything behind the wildcard. This avoids that given
			// "*example.com" "example.com.xxxxx" would also match.
			if(buf != NULL && strlen(buf) == strlen(buffer+1))
				found++;
		}
	}

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
