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
#include "database/sqlite3.h"

// A list of items of common local hostnames not to report as unusable
// Some lists (i.e StevenBlack's) contain these as they are supposed to be used as HOST files
// but flagging them as unusable causes more confusion than it's worth - so we suppress them from the output
static const char *false_positives[] = {
	"localhost",
	"localhost.localdomain",
	"local",
	"broadcasthost",
	"localhost",
	"ip6-localhost",
	"ip6-loopback",
	"lo0 localhost",
	"ip6-localnet",
	"ip6-mcastprefix",
	"ip6-allnodes",
	"ip6-allrouters",
	"ip6-allhosts"
};

// Print progress for files larger than 10 MB
// This is to avoid printing progress for small files
// which would be printed too often as affect performance
#define PRINT_PROGRESS_THRESHOLD 10*1000*1000

// Number of invalid domains to print before skipping the rest
#define MAX_INVALID_DOMAINS 5

// Validate domain name
inline bool __attribute__((pure)) valid_domain(const char *domain, const size_t len, const bool fqdn_only)
{
	// Domain must not be NULL or empty, and they should not be longer than
	// 255 characters
	if(domain == NULL || len == 0 || len > 255)
		return false;

	// Loop over line and check for invalid characters
	int last_dot = -1;
	for(unsigned int i = 0; i < len; i++)
	{
		// Domain must not contain any character other than [a-zA-Z0-9.-_]
		if(domain[i] != '-' && domain[i] != '.' && domain[i] != '_' &&
		   (domain[i] < 'a' || domain[i] > 'z') &&
		   (domain[i] < 'A' || domain[i] > 'Z') &&
		   (domain[i] < '0' || domain[i] > '9'))
			return false;

		// Individual label length check
		if(domain[i] == '.')
		{
			// Label must be longer than 0 characters, i.e., two consecutive
			// dots are not allowed
			if(i - last_dot == 1)
				return false;

			// Label must not be longer than 63 characters
			// (actually 64 because the dot at the end of the label
			// is included here)
			if(i - last_dot > 64)
				return false;

			// Label must be at least 1 character long
			// We did already check above to not have two
			// consecutive dots

			// Update last_dot to this dot
			last_dot = i;
		}
	}

	// TLD checks

	// There must be at least two labels (i.e. one dot)
	// e.g., "example.com" but not "localhost" for exact domain
	// We do not enforce this for ABP domains and domainlist input
	// (see https://github.com/pi-hole/pi-hole/pull/5240)
	if(last_dot == -1 && fqdn_only)
		return false;

	// TLD must not start or end with a hyphen
	if(domain[last_dot + 1] == '-' || domain[len - 1] == '-')
		return false;

	return true;
}

// Validate ABP domain name
static inline bool __attribute__((pure)) valid_abp_domain(const char *line, const size_t len, const bool antigravity)
{
	if(antigravity)
	{

		// The line must be at least 5 characters long
		if(len < 5)
			return false;

		// First four characters must be "@@||"
		if(line[0] != '@' || line[1] != '@' || line[2] != '|' || line[3] != '|')
			return false;

		// Last character must be "^"
		if(line[len-1] != '^')
			return false;

		// Domain must be valid
		return valid_domain(line+4, len-5, false);
	}
	else
	{
		// The line must be at least 3 characters long
		if(len < 3)
			return false;

		// First two characters must be "||"
		if(line[0] != '|' || line[1] != '|')
			return false;

		// Last character must be "^"
		if(line[len-1] != '^')
			return false;

		// Domain must be valid
		return valid_domain(line+2, len-3, false);
	}
}

// Check if a line is a false positive
static inline bool is_false_positive(const char *line)
{
	for(unsigned int i = 0; i < sizeof(false_positives)/sizeof(false_positives[0]); i++)
		if(strcmp(line, false_positives[i]) == 0)
			return true;
	return false;
}

// Print domain (escape non-printable characters)
static void print_escaped(const char *str, const ssize_t len)
{
	for(ssize_t j = 0; j < len; j++)
		if(isgraph(str[j]))
			putchar(str[j]);
		else
			// Escape non-printable characters
			printf("\\x%02x", (unsigned char)str[j]);
}

int gravity_parseList(const char *infile, const char *outfile, const char *adlistIDstr,
                      const bool checkOnly, const bool antigravity)
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

	// Open output file (database)
	sqlite3 *db = NULL;
	sqlite3_stmt *stmt = NULL;
	if(!checkOnly && sqlite3_open_v2(outfile, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to open database file %s for writing\n", over, cross, outfile);
		fclose(fpin);
		return EXIT_FAILURE;
	}

	// Disable journaling
	// Journaling is used to prevent database corruption in case of a power
	// loss or operating system crash. However, this is not needed for the
	// gravity database the database is created from scratch at every run
	// of pihole -g.
	// The OFF journaling mode disables the rollback journal completely. No
	// rollback journal is ever created and hence there is never a rollback
	// journal to delete.
	if(!checkOnly && sqlite3_exec(db, "PRAGMA journal_mode = OFF;", NULL, NULL, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to disable journaling in database file %s\n", over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Disable synchronous mode
	// With synchronous OFF (0), SQLite continues without syncing as soon as
	// it has handed data off to the operating system. If the application
	// running SQLite crashes, the data will be safe, but the database might
	// become corrupted if the operating system crashes or the computer
	// loses power before that data has been written to the disk surface. On
	// the other hand, commits can be orders of magnitude faster with
	// synchronous OFF.
	// See https://www.sqlite.org/pragma.html#pragma_synchronous
	// If a power loss (or operating system crash) happens, the database
	// created here will never be swapped into action and is discarded at
	// the next run of pihole -g.
	if(!checkOnly && sqlite3_exec(db, "PRAGMA synchronous = OFF;", NULL, NULL, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to disable synchronous mode in database file %s\n", over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Get size of input file
	fseek(fpin, 0L, SEEK_END);
	const size_t fsize = ftell(fpin);
	rewind(fpin);

	// Begin transaction
	if(!checkOnly && sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to begin transaction to insert domains into database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Prepare SQL statement
	const char *sql = antigravity ?
		"INSERT INTO antigravity (domain, adlist_id) VALUES (?, ?);" :
		"INSERT INTO gravity (domain, adlist_id) VALUES (?, ?);";
	if(!checkOnly && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to prepare SQL statement to insert domains into database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Bind adlistID
	const int adlistID = atoi(adlistIDstr);
	if(!checkOnly && sqlite3_bind_int(stmt, 2, adlistID) != SQLITE_OK)
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
	size_t total_read = 0, last_print = 0;
	const size_t print_step = fsize / 20; // Print progress every 100/20 = 5%
	int last_progress = 0;
	char *invalid_domains_list[MAX_INVALID_DOMAINS] = { NULL };
	ssize_t invalid_domains_list_lengths[MAX_INVALID_DOMAINS] = { -1 };
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

		// Validate line
		if(line[0] != (antigravity ? '@' : '|') &&           // <- Not an ABP-style match
		   valid_domain(line, read, true))
		{
			// Exact match found
			if(checkOnly)
			{
				// Increment counter
				exact_domains++;
				continue;
			}

			// else: Append domain to database using prepared statement
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
		else if(line[0] == (antigravity ? '@' : '|') &&         // <- ABP-style match
		        valid_abp_domain(line, read, antigravity))      // <- Valid ABP domain
		{
			// ABP-style match (see comments above)
			if(checkOnly)
			{
				// Increment counter
				abp_domains++;
				continue;
			}

			// else: Append pattern to database using prepared statement
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
			if(!is_false_positive(line))
			{
				if(checkOnly)
				{
					// Increment counter
					invalid_domains++;
					printf("%s  %s Invalid domain on line %zu: ", over, cross, lineno);
					print_escaped(line, read);
					puts("");
					continue;
				}
				// Add the domain to invalid_domains_list only
				// if the list contains < MAX_INVALID_DOMAINS
				if(invalid_domains_list_len < MAX_INVALID_DOMAINS)
				{
					// Check if we have this domain already
					bool found = false;
					for(unsigned int i = 0; i < invalid_domains_list_len; i++)
					{
						// Do not compare against unset entries
						if(invalid_domains_list[i] == NULL || invalid_domains_list_lengths[i] == -1)
							break;

						// Compare against the current domain
						if(memcmp(invalid_domains_list[i], line, min(read, invalid_domains_list_lengths[i])) == 0)
						{
							found = true;
							break;
						}
					}

					// If not found, add it to the list
					if(!found)
					{
						invalid_domains_list[invalid_domains_list_len] = calloc(read + 1, sizeof(char));
						if(invalid_domains_list[invalid_domains_list_len] == NULL)
						{
							printf("%s  %s Unable to allocate memory for invalid domains list\n", over, cross);
							fclose(fpin);
							sqlite3_close(db);
							return EXIT_FAILURE;
						}
						memcpy(invalid_domains_list[invalid_domains_list_len], line, read);
						invalid_domains_list[invalid_domains_list_len][read] = '\0';
						invalid_domains_list_lengths[invalid_domains_list_len] = read;
						invalid_domains_list_len++;
					}

				}
				invalid_domains++;
			}
		}

		// Print progress if the file is large enough every 100 lines
		// This code cannot be reached if checkOnly is true
		if(fsize > PRINT_PROGRESS_THRESHOLD && total_read - last_print > print_step)
		{
			last_print = total_read;
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

	// Skip to end of parseList if we are only checking the list
	if(checkOnly)
		goto end_of_parseList;

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
	sql = "UPDATE adlist SET number = ?, invalid_domains = ?, abp_entries = ?, date_updated = cast(strftime('%s', 'now') as int) WHERE id = ?;";
	if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		printf("%s  %s Unable to prepare SQL statement to update adlist properties in database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	if(sqlite3_bind_int(stmt, 1, exact_domains + abp_domains) != SQLITE_OK)
	{
		printf("%s  %s Unable to bind number of entries to SQL statement to update adlist properties in database file %s\n",
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
	if(sqlite3_bind_int(stmt, 3, abp_domains) != SQLITE_OK)
	{
		printf("%s  %s Unable to bind number of ABP entries to SQL statement to update adlist properties in database file %s\n",
		       over, cross, outfile);
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}
	if(sqlite3_bind_int(stmt, 4, adlistID) != SQLITE_OK)
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

end_of_parseList:
	// Print summary
	printf("%s  %s Parsed %u exact domains and %u ABP-style domains (%sing, ignored %u non-domain entries)\n",
	       over, tick, exact_domains, abp_domains, antigravity ? "allow" : "block", invalid_domains);
	if(invalid_domains_list_len > 0)
	{
		puts("      Sample of non-domain entries:");
		for(unsigned int i = 0; i < invalid_domains_list_len; i++)
		{
			// Print indentation
			printf("        - ");
			print_escaped(invalid_domains_list[i], invalid_domains_list_lengths[i]);
			// Print newline
			puts("");
		}
	}

	// Free memory
	free(line);
	for(unsigned int i = 0; i < invalid_domains_list_len; i++)
		if(invalid_domains_list[i] != NULL)
			free(invalid_domains_list[i]);

	// Close files
	fclose(fpin);
	if(db != NULL)
		sqlite3_close(db);

	// Return success
	return EXIT_SUCCESS;
}
