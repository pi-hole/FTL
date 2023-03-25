/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Gravity tools collection routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "gravity-tools.h"
#include "args.h"
#include <regex.h>

// Define valid domain patterns
// No need to include uppercase letters, as we convert to lowercase in gravity_ParseFileIntoDomains() already
// Adapted from https://stackoverflow.com/a/30007882
// - Added "(?:...)" to form non-capturing groups (slighly faster)
#define VALID_DOMAIN_REXEX "([a-z0-9]([a-z0-9_-]{0,61}[a-z0-9]){0,1}\\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"

// supported ABP style: ||subdomain.domain.tlp^
#define ABP_DOMAIN_REXEX "\\|\\|"VALID_DOMAIN_REXEX"\\^"

// A list of items of common local hostnames not to report as unusable
// Some lists (i.e StevenBlack's) contain these as they are supposed to be used as HOST files
// but flagging them as unusable causes more confusion than it's worth - so we suppress them from the output
#define FALSE_POSITIVES "localhost|localhost.localdomain|local|broadcasthost|localhost|ip6-localhost|ip6-loopback|lo0 localhost|ip6-localnet|ip6-mcastprefix|ip6-allnodes|ip6-allrouters|ip6-allhosts"

// Print progress for files larger than 10 MB
// This is to avoid printing progress for small files
// which would be printed too often as affect performance
#define PRINT_PROGRESS_THRESHOLD 10*1000*1000

// Number of invalid domains to print before skipping the rest
#define MAX_INVALID_DOMAINS 5

int gravity_parseList(const char *infile, const char *outfile, const char *adlistID)
{
	// Open input file
	FILE *fpin = fopen(infile, "r");
	if(fpin == NULL)
	{
		printf("WARNING: Unable to open %s for reading\n", infile);
		return EXIT_FAILURE;
	}

	// Open output file
	FILE *fpout = fopen(outfile, "a");
	if(fpout == NULL)
	{
		printf("WARNING: Unable to open %s for appending\n", outfile);
		fclose(fpin);
		return EXIT_FAILURE;
	}

	// Get size of input file
	fseek(fpin, 0L, SEEK_END);
	const size_t fsize = ftell(fpin);
	rewind(fpin);

	// Compile regular expression to validate domains
	regex_t exact_regex, abp_regex, false_positives_regex;
	if(regcomp(&exact_regex, VALID_DOMAIN_REXEX, REG_EXTENDED) != 0)
	{
		printf("WARNING: Unable to compile regular expression to validate exact domains\n");
		fclose(fpin);
		fclose(fpout);
		return EXIT_FAILURE;
	}
	if(regcomp(&abp_regex, ABP_DOMAIN_REXEX, REG_EXTENDED) != 0)
	{
		printf("WARNING: Unable to compile regular expression to validate ABP-style domains\n");
		fclose(fpin);
		fclose(fpout);
		return EXIT_FAILURE;
	}
	if(regcomp(&false_positives_regex, FALSE_POSITIVES, REG_EXTENDED | REG_NOSUB) != 0)
	{
		printf("WARNING: Unable to compile regular expression to identify false positives\n");
		fclose(fpin);
		fclose(fpout);
		return EXIT_FAILURE;
	}

	// Generate adlistID tail
	char adlistIDtail[16];
	snprintf(adlistIDtail, sizeof(adlistIDtail), ",%s\n", adlistID);
	adlistIDtail[sizeof(adlistIDtail)-1] = '\0';

	// Parse list file line by line
	char *line = NULL;
	size_t len = 0;
	ssize_t read = 0;
	size_t total_read = 0;
	int last_progress = 0;
	char *invalid_domains_list[MAX_INVALID_DOMAINS] = { NULL };
	const char *info = cli_info();
	unsigned int invalid_domains_list_len = 0;
	unsigned int exact_domains = 0, abp_domains = 0, invalid_domains = 0;
	while((read = getline(&line, &len, fpin)) != -1)
	{
		// Update total read bytes
		total_read += read;

		// Skip comments
		if(line[0] == '#')
			continue;

		// Remove trailing newline
		if(line[read-1] == '\n')
			line[read-1] = '\0';

		// Skip empty lines
		const int line_len = strlen(line);
		if(line_len == 0)
			continue;

		regmatch_t match = { 0 };
		// Validate line
		if(line[0] != '|' &&                                 // <- Not an ABP-style match
		   regexec(&exact_regex, line, 1, &match, 0) == 0 && // <- Regex match
		   match.rm_so == 0 && match.rm_eo == line_len)      // <- Match covers entire line
		{
			// Exact match found
			// Write domain to output file ...
			fputs(line, fpout);
			// ... and append ,adlistID
			fputs(adlistIDtail, fpout);
			// Increment counter
			exact_domains++;
		}
		else if(line[0] == '|' &&                               // <- ABP-style match
		        regexec(&abp_regex, line, 1, &match, 0) == 0 && // <- Regex match
		        match.rm_so == 0 && match.rm_eo == line_len)    // <- Match covers entire line
		{
			// ABP-style match (see comments above)
			fputs(line, fpout);
			fputs(adlistIDtail, fpout);
			abp_domains++;
		}
		else
		{
			// No match - add to list of invalid domains
			if(invalid_domains_list_len < MAX_INVALID_DOMAINS)
			{
				// Check if we have this domain already
				bool found = false;
				for(unsigned int i = 0; i < invalid_domains_list_len; i++)
				{
					if(strcmp(invalid_domains_list[i], line) == 0)
					{
						found = true;
						break;
					}
				}

				// If not found, check if this is a false
				// positive and add it to the list if it is not
				if(!found && regexec(&false_positives_regex, line, 0, NULL, 0) != 0)
					invalid_domains_list[invalid_domains_list_len++] = strdup(line);
			}
			invalid_domains++;
		}

		// Print progress if the file is large enough
		if(fsize > PRINT_PROGRESS_THRESHOLD)
		{
			// Calculate progress
			const int progress = (int)(100.0*total_read/fsize);
			// Print progress if it has changed
			if(progress > last_progress)
			{
				printf("\r  %s Parsed %i%% of downloaded list", info, progress);
				fflush(stdout);
				last_progress = progress;
			}
		}
	}

	// Print summary
	printf("\r  %s Parsed %u exact domains and %u ABP-style domains (ignored %u non-domain entries)\n", cli_tick(), exact_domains, abp_domains, invalid_domains);
	if(invalid_domains_list_len > 0)
	{
		printf("      Sample of non-domain entries:\n");
		for(unsigned int i = 0; i < invalid_domains_list_len; i++)
			printf("        - %s\n", invalid_domains_list[i]);
	}

	// Free memory
	free(line);
	regfree(&exact_regex);
	regfree(&abp_regex);
	for(unsigned int i = 0; i < invalid_domains_list_len; i++)
		if(invalid_domains_list[i] != NULL)
			free(invalid_domains_list[i]);

	// Close files
	fclose(fpin);
	fclose(fpout);

	return EXIT_SUCCESS;
}