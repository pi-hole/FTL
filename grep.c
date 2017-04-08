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
	char *buffer, *domain;
	char linebuffer[512];
	int i;

	if((fp = fopen(files.wildcards, "r")) == NULL) {
		counters.wildcarddomains = -1;
		return;
	}

	// Search through file
	while(fgets(linebuffer, 511, fp))
	{
		buffer = calloc(512,sizeof(char));
		// Try to read up to 511 characters
		if(sscanf(linebuffer, "address=/%511[^/]/%*[^\n]\n", buffer) > 0)
		{
			int addrbuffer = 0;
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
				if(known) continue;
				// Add wildcard entry
				// Enlarge wildcarddomains pointer array
				wildcarddomains = realloc(wildcarddomains, (counters.wildcarddomains+1)*sizeof(*wildcarddomains));
				// Allocate space for new domain entry and save domain
				wildcarddomains[counters.wildcarddomains] = calloc(strlen(domain)+1,sizeof(char));
				memory.wildcarddomains += (strlen(domain) + 1) * sizeof(char);
				strcpy(wildcarddomains[counters.wildcarddomains], domain);

				// Increase number of stored wildcards by one
				counters.wildcarddomains++;
			}
		}
		free(buffer);
		buffer = NULL;
	}

	// Close the file
	fclose(fp);

}

// int countlineswith(const char* str, const char* fname)
// {
// 	FILE *fp;
// 	int found = 0;
// 	char buffer[512];

// 	if((fp = fopen(fname, "r")) == NULL) {
// 		return -1;
// 	}

// 	// Search through file
// 	// fgets reads a string from the specified file up to either a newline character or EOF
// 	while(fgets(buffer, sizeof(buffer), fp) != NULL)
// 		if((strstr(buffer, str)) != NULL)
// 			found++;

// 	// Close the file
// 	if(fp) {
// 		fclose(fp);
// 	}

// 	return found;
// }
