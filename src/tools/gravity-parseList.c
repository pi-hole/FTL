/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Gravity parseList routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "tools/gravity-parseList.h"
#include "args.h"
#include <regex.h>
#include "database/sqlite3.h"

// Define valid domain patterns
// No need to include uppercase letters, as we convert to lowercase in gravity_ParseFileIntoDomains() already
// Adapted from https://stackoverflow.com/a/30007882
// - Added "(?:...)" to form non-capturing groups (slightly faster)
#define TLD_PATTERN "[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
#define SUBDOMAIN_PATTERN "([a-z0-9_-]{0,63}\\.)"

// supported exact style: subdomain.domain.tld
// SUBDOMAIN_PATTERN is mandatory for exact style, disallowing TLD blocking
#define VALID_DOMAIN_REXEX SUBDOMAIN_PATTERN"+"TLD_PATTERN

// supported ABP style: ||subdomain.domain.tlp^
// SUBDOMAIN_PATTERN is optional for ABP style, allowing TLD blocking: ||tld^
// See https://github.com/pi-hole/pi-hole/pull/5240
#define ABP_DOMAIN_REXEX "\\|\\|"SUBDOMAIN_PATTERN"*"TLD_PATTERN"\\^"

// A list of items of common local hostnames not to report as unusable
// Some lists (i.e StevenBlack's) contain these as they are supposed to be used as HOST files
// but flagging them as unusable causes more confusion than it's worth - so we suppress them from the output
#define FALSE_POSITIVES "^(localhost|localhost.localdomain|local|broadcasthost|localhost|ip6-localhost|ip6-loopback|lo0 localhost|ip6-localnet|ip6-mcastprefix|ip6-allnodes|ip6-allrouters|ip6-allhosts)$"

// Print progress for files larger than 10 MB
// This is to avoid printing progress for small files
// which would be printed too often as affect performance
#define PRINT_PROGRESS_THRESHOLD 10*1000*1000

// Number of invalid domains to print before skipping the rest
#define MAX_INVALID_DOMAINS 5

int gravity_parseList(const char *infile, const char *outfile, const char *adlistIDstr)
{
	const char *info = cli_info();
	const char *tick = cli_tick();
	const char *cross = cli_cross();
	const char *over = cli_over();

	// Open input file
	FILE *fpin = fopen(infile, "r");
	if(fpin == NULL)
	{
		printf("%s  %s Unable to open %s for reading\n", over, cross, infile);
		return EXIT_FAILURE;
	}

	// Open output file
	sqlite3 *db = NULL;
	sqlite3_stmt *stmt = NULL;
	if(sqlite3_open_v2(outfile, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to open database file %s for writing\n", over, cross, outfile);
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
		printf("%s  %s Unable to compile regular expression to validate exact domains\n",
		       over, cross);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}
	if(regcomp(&abp_regex, ABP_DOMAIN_REXEX, REG_EXTENDED) != 0)
	{
		printf("%s  %s Unable to compile regular expression to validate ABP-style domains\n",
		       over, cross);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}
	if(regcomp(&false_positives_regex, FALSE_POSITIVES, REG_EXTENDED | REG_NOSUB) != 0)
	{
		printf("%s  %s Unable to compile regular expression to identify false positives\n",
		       over, cross);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Begin transaction
	if(sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to begin transaction to insert domains into database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Prepare SQL statement
	const char *sql = "INSERT INTO gravity (domain, adlist_id) VALUES (?, ?);";
	if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to prepare SQL statement to insert domains into database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Bind adlistID
	const int adlistID = atoi(adlistIDstr);
	if(sqlite3_bind_int(stmt, 2, adlistID) != SQLITE_OK)
	{
		printf("%s  %s Unable to bind adlistID to SQL statement to insert domains into database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Parse list file line by line
	char *line = NULL;
	size_t lineno = 0;
	size_t len = 0;
	ssize_t read = 0;
	size_t total_read = 0;
	int last_progress = 0;
	char *invalid_domains_list[MAX_INVALID_DOMAINS] = { NULL };
	unsigned int invalid_domains_list_len = 0;
	unsigned int exact_domains = 0, abp_domains = 0, invalid_domains = 0;
	while((read = getline(&line, &len, fpin)) != -1)
	{
		// Update total read bytes
		total_read += read;
		lineno++;

		// Remove trailing newline
		if(line[read-1] == '\n')
			line[--read] = '\0';

		// Remove trailing dot (convert FQDN to domain)
		if(line[read-1] == '.')
			line[--read] = '\0';


		regmatch_t match = { 0 };
		// Validate line
		if(line[0] != '|' &&                                 // <- Not an ABP-style match
		   regexec(&exact_regex, line, 1, &match, 0) == 0 && // <- Regex match
		   match.rm_so == 0 && match.rm_eo == read)          // <- Match covers entire line
		{
			// Exact match found
			// Append domain to database using prepared statement
			if(sqlite3_bind_text(stmt, 1, line, -1, SQLITE_STATIC) != SQLITE_OK)
			{
				printf("%s  %s Unable to bind domain to SQL statement to insert domains into database file %s\n",
				       over, cross, outfile);
				fclose(fpin);
				sqlite3_close(db);
				return EXIT_FAILURE;
			}
			if(sqlite3_step(stmt) != SQLITE_DONE)
			{
				printf("%s  %s Unable to insert domain into database file %s\n", over, cross, outfile);
				fclose(fpin);
				sqlite3_close(db);
				return EXIT_FAILURE;
			}
			sqlite3_reset(stmt);
			// Increment counter
			exact_domains++;
		}
		else if(line[0] == '|' &&                               // <- ABP-style match
		        regexec(&abp_regex, line, 1, &match, 0) == 0 && // <- Regex match
		        match.rm_so == 0 && match.rm_eo == read)        // <- Match covers entire line
		{
			// ABP-style match (see comments above)

			// Append pattern to database using prepared statement
			if(sqlite3_bind_text(stmt, 1, line, -1, SQLITE_STATIC) != SQLITE_OK)
			{
				printf("%s  %s Unable to bind domain to SQL statement to insert domains into database file %s\n",
				       over, cross, outfile);
				fclose(fpin);
				sqlite3_close(db);
				return EXIT_FAILURE;
			}
			if(sqlite3_step(stmt) != SQLITE_DONE)
			{
				printf("%s  %s Unable to insert domain into database file %s\n", over, cross, outfile);
				fclose(fpin);
				sqlite3_close(db);
				return EXIT_FAILURE;
			}
			sqlite3_reset(stmt);
			abp_domains++;
		}
		else
		{
			// No match - This is an invalid domain or a false positive

			// Ignore false positives - they don't count as invalid domains
			if(regexec(&false_positives_regex, line, 0, NULL, 0) != 0)
			{
				// Add the domain to invalid_domains_list only
				// if the list contains < MAX_INVALID_DOMAINS
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

					// If not found, add it to the list
					if(!found)
						invalid_domains_list[invalid_domains_list_len++] = strdup(line);

				}
				invalid_domains++;
			}
		}

		// Print progress if the file is large enough every 100 lines
		if(fsize > PRINT_PROGRESS_THRESHOLD && lineno % 100 == 1)
		{
			// Calculate progress
			const int progress = (int)(100.0*total_read/fsize);
			// Print progress if it has changed
			if(progress > last_progress)
			{
				printf("%s  %s Processed %i%% of downloaded list", over, info, progress);
				fflush(stdout);
				last_progress = progress;
			}
		}
	}

	// Finalize SQL statement
	if(sqlite3_finalize(stmt) != SQLITE_OK)
	{
		printf("%s  %s Unable to finalize SQL statement to insert domains into database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Update database properties
	// Are ABP patterns used?
	if(abp_domains > 0)
	{
		sql = "INSERT OR REPLACE INTO info (property,value) VALUES ('abp_domains',1);";
		if(sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK)
		{
			printf("%s  %s Unable to update database properties in database file %s\n",
			       over, cross, outfile);
			fclose(fpin);
			sqlite3_close(db);
			return EXIT_FAILURE;
		}
	}

	// Update number of domains and update timestamp on this list
	sql = "UPDATE adlist SET number = ?, invalid_domains = ?, date_updated = cast(strftime('%s', 'now') as int) WHERE id = ?;";
	if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to prepare SQL statement to update adlist properties in database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Update date
	if(sqlite3_bind_int(stmt, 1, exact_domains) != SQLITE_OK)
	{
		printf("%s  %s Unable to bind number of domains to SQL statement to update adlist properties in database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}
	if(sqlite3_bind_int(stmt, 2, invalid_domains) != SQLITE_OK)
	{
		printf("%s  %s Unable to bind number of invalid domains to SQL statement to update adlist properties in database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}
	if(sqlite3_bind_int(stmt, 3, adlistID) != SQLITE_OK)
	{
		printf("%s  %s Unable to bind adlist ID to SQL statement to update adlist properties in database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}
	if(sqlite3_step(stmt) != SQLITE_DONE)
	{
		printf("%s  %s Unable to update adlist properties in database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}
	if(sqlite3_finalize(stmt) != SQLITE_OK)
	{
		printf("%s  %s Unable to finalize SQL statement to update adlist properties in database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// End transaction
	if(sqlite3_exec(db, "END TRANSACTION", NULL, NULL, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to end transaction to insert domains into database file %s (database file may be corrupted)\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Print summary
	printf("%s  %s Parsed %u exact domains and %u ABP-style domains (ignored %u non-domain entries)\n",
	       over, tick, exact_domains, abp_domains, invalid_domains);
	if(invalid_domains_list_len > 0)
	{
		puts("      Sample of non-domain entries:");
		for(unsigned int i = 0; i < invalid_domains_list_len; i++)
			printf("        - \"%s\"\n", invalid_domains_list[i]);
		puts("");
	}

	// Free memory
	free(line);
	regfree(&exact_regex);
	regfree(&abp_regex);
	regfree(&false_positives_regex);
	for(unsigned int i = 0; i < invalid_domains_list_len; i++)
		if(invalid_domains_list[i] != NULL)
			free(invalid_domains_list[i]);

	// Close files
	fclose(fpin);
	sqlite3_close(db);

	// Return success
	return EXIT_SUCCESS;
}
