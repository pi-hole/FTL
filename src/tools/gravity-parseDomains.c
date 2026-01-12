/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Gravity parseDomains routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "tools/gravity-parseDomains.h"
#include "tools/gravity-parseList.h" // Reuse valid_domain()
#include "args.h"
#include "database/sqlite3.h"
#include <string.h>
#include <strings.h>

// Parse domain list type from string
domainlist_type_t parse_domainlist_type(const char *type_str)
{
	if(type_str == NULL)
		return DOMAINLIST_TYPE_INVALID;

	// Case-insensitive matching
	if(strcasecmp(type_str, "whitelist") == 0 || strcasecmp(type_str, "white") == 0)
		return DOMAINLIST_TYPE_WHITELIST;

	if(strcasecmp(type_str, "blacklist") == 0 || strcasecmp(type_str, "black") == 0)
		return DOMAINLIST_TYPE_BLACKLIST;

	if(strcasecmp(type_str, "regex_white") == 0 || strcasecmp(type_str, "regex_whitelist") == 0)
		return DOMAINLIST_TYPE_REGEX_WHITE;

	if(strcasecmp(type_str, "regex_black") == 0 || strcasecmp(type_str, "regex_blacklist") == 0 ||
	   strcasecmp(type_str, "regex") == 0) // "regex" defaults to blacklist
		return DOMAINLIST_TYPE_REGEX_BLACK;

	return DOMAINLIST_TYPE_INVALID;
}

// Validate regex pattern (basic check - compile test)
static bool valid_regex(const char *pattern, const size_t len)
{
	// Basic sanity checks
	if(pattern == NULL || len == 0 || len > 1024)
		return false;

	// TODO: For production, use PCRE2 to actually compile and validate
	// For now, just check it's not empty and has reasonable length
	// This is a placeholder - real implementation should use:
	// pcre2_code *re = pcre2_compile((PCRE2_SPTR)pattern, len, 0, &errcode, &erroffset, NULL);
	// bool valid = (re != NULL);
	// pcre2_code_free(re);

	return true; // Accept all for now
}

// Import domains from file into domainlist table
int gravity_parseDomains(const char *infile, const char *outfile,
                         const char *type_str, const char *comment)
{
	// Parse type string to enum
	const domainlist_type_t list_type = parse_domainlist_type(type_str);
	if(list_type == DOMAINLIST_TYPE_INVALID)
	{
		printf("ERROR: Invalid domain list type '%s'\n", type_str);
		printf("Valid types: whitelist, blacklist, regex_white, regex_black (regex)\n");
		return EXIT_FAILURE;
	}

	const bool is_regex = (list_type == DOMAINLIST_TYPE_REGEX_WHITE ||
	                       list_type == DOMAINLIST_TYPE_REGEX_BLACK);

	// Open input file
	FILE *fpin = fopen(infile, "r");
	if(fpin == NULL)
	{
		printf("ERROR: Unable to open input file %s\n", infile);
		return EXIT_FAILURE;
	}

	// Get file size for progress reporting
	fseek(fpin, 0L, SEEK_END);
	const size_t fsize = ftell(fpin);
	rewind(fpin);

	// Open database
	sqlite3 *db = NULL;
	if(sqlite3_open_v2(outfile, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
	{
		printf("ERROR: Unable to open database file %s: %s\n",
		       outfile, sqlite3_errmsg(db));
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Begin transaction
	if(sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL) != SQLITE_OK)
	{
		printf("ERROR: Unable to begin transaction: %s\n", sqlite3_errmsg(db));
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Prepare SQL statement
	// Note: date_added and date_modified use SQLite's strftime for current timestamp
	const char *sql =
		"INSERT OR IGNORE INTO domainlist "
		"(type, domain, enabled, date_added, date_modified, comment) "
		"VALUES (?, ?, 1, cast(strftime('%s', 'now') as int), "
		"cast(strftime('%s', 'now') as int), ?);";

	sqlite3_stmt *stmt = NULL;
	if(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
	{
		printf("ERROR: Unable to prepare SQL statement: %s\n", sqlite3_errmsg(db));
		fclose(fpin);
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	// Parse file line by line
	char *line = NULL;
	size_t len = 0;
	ssize_t read = 0;
	size_t lineno = 0;
	size_t total_read = 0, last_print = 0;
	const size_t print_step = fsize / 20; // Print progress every 5%
	unsigned int valid_entries = 0, invalid_entries = 0, duplicate_entries = 0;
	bool first_line = true;

	printf("  Parsing %s domains from %s...\n",
	       is_regex ? "regex" : "exact", infile);

	while((read = getline(&line, &len, fpin)) != -1)
	{
		lineno++;
		total_read += read;

		// Handle UTF-8 BOM (Byte Order Mark) if present on first line
		if(first_line)
		{
			first_line = false;
			if(read >= 3 &&
			   (unsigned char)line[0] == 0xEF &&
			   (unsigned char)line[1] == 0xBB &&
			   (unsigned char)line[2] == 0xBF)
			{
				// Skip BOM
				memmove(line, line + 3, read - 3 + 1);
				read -= 3;
			}
		}

		// Strip trailing whitespace/newlines
		while(read > 0 && (line[read-1] == '\n' || line[read-1] == '\r' ||
		                   line[read-1] == ' ' || line[read-1] == '\t'))
		{
			line[--read] = '\0';
		}

		// Skip empty lines
		if(read == 0)
			continue;

		// Skip comments
		if(line[0] == '#' || line[0] == ';')
			continue;

		// Strip leading whitespace
		char *domain = line;
		while(*domain == ' ' || *domain == '\t')
		{
			domain++;
			read--;
		}

		if(read == 0)
			continue;

		// Validate entry based on type
		bool valid = false;
		if(is_regex)
		{
			valid = valid_regex(domain, read);
		}
		else
		{
			// Reuse domain validation from gravity-parseList.c
			// fqdn_only = false to allow single-label domains
			valid = valid_domain(domain, read, false);
		}

		if(!valid)
		{
			invalid_entries++;
			if(invalid_entries <= 5) // Only print first 5
			{
				printf("  WARNING: Invalid %s at line %zu: %s\n",
				       is_regex ? "regex" : "domain", lineno, domain);
			}
			continue;
		}

		// Bind parameters
		sqlite3_reset(stmt);
		sqlite3_clear_bindings(stmt);

		if(sqlite3_bind_int(stmt, 1, (int)list_type) != SQLITE_OK ||
		   sqlite3_bind_text(stmt, 2, domain, -1, SQLITE_TRANSIENT) != SQLITE_OK ||
		   sqlite3_bind_text(stmt, 3, comment ? comment : "", -1, SQLITE_TRANSIENT) != SQLITE_OK)
		{
			printf("ERROR: Unable to bind parameters: %s\n", sqlite3_errmsg(db));
			invalid_entries++;
			continue;
		}

		// Execute statement
		int rc = sqlite3_step(stmt);
		if(rc == SQLITE_DONE)
		{
			// Check if actually inserted (not duplicate)
			if(sqlite3_changes(db) > 0)
				valid_entries++;
			else
				duplicate_entries++;
		}
		else
		{
			printf("ERROR: Failed to insert domain at line %zu: %s\n",
			       lineno, sqlite3_errmsg(db));
			invalid_entries++;
		}

		// Progress reporting for large files (>10MB)
		if(fsize > 10*1000*1000 && total_read - last_print > print_step)
		{
			last_print = total_read;
			int progress = (int)((total_read * 100) / fsize);
			printf("  Progress: %d%%\r", progress);
			fflush(stdout);
		}
	}

	// Cleanup
	free(line);
	sqlite3_finalize(stmt);
	fclose(fpin);

	// Commit transaction
	if(sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK)
	{
		printf("ERROR: Unable to commit transaction: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		return EXIT_FAILURE;
	}

	sqlite3_close(db);

	// Print summary
	printf("  Successfully imported %u %s entries\n",
	       valid_entries, is_regex ? "regex" : "domain");
	if(duplicate_entries > 0)
		printf("  Skipped %u duplicate entries\n", duplicate_entries);
	if(invalid_entries > 0)
		printf("  Skipped %u invalid entries\n", invalid_entries);

	return EXIT_SUCCESS;
}
