/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Message table routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "database/message-table.h"
#include "database/common.h"
// logging routines
#include "log.h"
// get_group_names()
#include "gravity-db.h"
// cli_mode
#include "args.h"
// cleanup()
#include "daemon.h"
// main_pid()
#include "signals.h"
// struct config
#include "config/config.h"
// get_rate_limit_turnaround()
#include "gc.h"
// get_filesystem_details()
#include "files.h"
// get_memdb()
#include "database/query-table.h"
// escape_html()
#include "webserver/http-common.h"

static const char *get_message_type_str(const enum message_type type)
{
	switch(type)
	{
		case REGEX_MESSAGE:
			return "REGEX";
		case SUBNET_MESSAGE:
			return "SUBNET";
		case HOSTNAME_MESSAGE:
			return "HOSTNAME";
		case DNSMASQ_CONFIG_MESSAGE:
			return "DNSMASQ_CONFIG";
		case RATE_LIMIT_MESSAGE:
			return "RATE_LIMIT";
		case DNSMASQ_WARN_MESSAGE:
			return "DNSMASQ_WARN";
		case LOAD_MESSAGE:
			return "LOAD";
		case SHMEM_MESSAGE:
			return "SHMEM";
		case DISK_MESSAGE:
			return "DISK";
		case INACCESSIBLE_ADLIST_MESSAGE:
			return "LIST";
		case DISK_MESSAGE_EXTENDED:
			return "DISK_EXTENDED";
		case CERTIFICATE_DOMAIN_MISMATCH_MESSAGE:
			return "CERTIFICATE_DOMAIN_MISMATCH";
		case MAX_MESSAGE:
		default:
			return "UNKNOWN";
	}
}

static enum message_type get_message_type_from_string(const char *typestr)
{
	if (strcmp(typestr, "REGEX") == 0)
		return REGEX_MESSAGE;
	else if (strcmp(typestr, "SUBNET") == 0)
		return SUBNET_MESSAGE;
	else if (strcmp(typestr, "HOSTNAME") == 0)
		return HOSTNAME_MESSAGE;
	else if (strcmp(typestr, "DNSMASQ_CONFIG") == 0)
		return DNSMASQ_CONFIG_MESSAGE;
	else if (strcmp(typestr, "RATE_LIMIT") == 0)
		return RATE_LIMIT_MESSAGE;
	else if (strcmp(typestr, "DNSMASQ_WARN") == 0)
		return DNSMASQ_WARN_MESSAGE;
	else if (strcmp(typestr, "LOAD") == 0)
		return LOAD_MESSAGE;
	else if (strcmp(typestr, "SHMEM") == 0)
		return SHMEM_MESSAGE;
	else if (strcmp(typestr, "DISK") == 0)
		return DISK_MESSAGE;
	else if (strcmp(typestr, "LIST") == 0)
		return INACCESSIBLE_ADLIST_MESSAGE;
	else if (strcmp(typestr, "DISK_EXTENDED") == 0)
		return DISK_MESSAGE_EXTENDED;
	else if (strcmp(typestr, "CERTIFICATE_DOMAIN_MISMATCH") == 0)
		return CERTIFICATE_DOMAIN_MISMATCH_MESSAGE;
	else
		return MAX_MESSAGE;
}

static unsigned char message_blob_types[MAX_MESSAGE][5] =
	{
		{	// REGEX_MESSAGE: The message column contains the regex warning text
			SQLITE_TEXT, // regex type ("deny", "allow")
			SQLITE_TEXT, // regex text (the erroring regex filter itself)
			SQLITE_INTEGER, // database index of regex (so the dashboard can show a link)
			SQLITE_NULL, // not used
			SQLITE_NULL // not used
		},
		{	// SUBNET_MESSAGE: The message column contains the IP address of the client in question
			SQLITE_INTEGER, // number of matching
			SQLITE_TEXT, // comma-separated list of matching subnets (text representation)
			SQLITE_TEXT, // comma-separated list of matching subnets (database IDs)
			SQLITE_TEXT, // chosen subnet (text representation)
			SQLITE_INTEGER // chosen subnet (database ID)
		},
		{	// HOSTNAME_MESSAGE: The message column contains the IP address of the device
			SQLITE_TEXT, // Obtained host name
			SQLITE_INTEGER, // Position of error in string
			SQLITE_NULL, // not used
			SQLITE_NULL, // not used
			SQLITE_NULL // not used
		},
		{	// DNSMASQ_CONFIG_MESSAGE: The message column contains the full message itself
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL  // Not used
		},
		{	// RATE_LIMIT_MESSAGE: The message column contains the IP address of the client in question
			SQLITE_INTEGER, // Configured maximum number of queries
			SQLITE_INTEGER, // Configured rate-limiting interval [seconds]
			SQLITE_INTEGER, // Turnaround time [seconds]
			SQLITE_NULL, // Not used
			SQLITE_NULL  // Not used
		},
		{	// DNSMASQ_WARN_MESSAGE: The message column contains the full message itself
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL  // Not used
		},
		{	// LOAD_MESSAGE: The message column contains a general message
			SQLITE_FLOAT, // 15min load average
			SQLITE_INTEGER, // Number of cores
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL  // Not used
		},
		{	// SHMEM_MESSAGE: The message column contains the corresponding path
			SQLITE_INTEGER, // Percentage currently used
			SQLITE_TEXT, // Human-readable details about memory/disk usage
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL  // Not used
		},
		{	// DISK_MESSAGE: The message column contains the corresponding path
			SQLITE_INTEGER, // Percentage currently used
			SQLITE_TEXT, // Human-readable details about memory/disk usage
			SQLITE_NULL, // Not used
			SQLITE_NULL, // Not used
			SQLITE_NULL  // Not used
		},
		{	// INACCESSIBLE_ADLIST_MESSAGE: The message column contains the corresponding adlist URL
			SQLITE_INTEGER, // database index of the adlist (so the dashboard can show a link)
			SQLITE_NULL, // not used
			SQLITE_NULL, // not used
			SQLITE_NULL, // not used
			SQLITE_NULL // not used
		},
		{
			// DISK_MESSAGE_EXTENDED: The message column contains the corresponding path
			SQLITE_INTEGER, // Percentage currently used
			SQLITE_TEXT, // Human-readable details about memory/disk usage
			SQLITE_TEXT, // File system type
			SQLITE_TEXT, // Directory mounted on
			SQLITE_NULL // not used
		},
		{
			// CERTIFICATE_DOMAIN_MISMATCH_MESSAGE: The message column contains the certificate file
			SQLITE_TEXT, // domain
			SQLITE_NULL, // not used
			SQLITE_NULL, // not used
			SQLITE_NULL, // not used
			SQLITE_NULL // not used
		}
	};
// Create message table in the database
bool create_message_table(sqlite3 *db)
{
	// Start transaction
	SQL_bool(db, "BEGIN TRANSACTION");

	// The blob fields can hold arbitrary data. Their type is specified through the type.
	SQL_bool(db, "CREATE TABLE message ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
	                                    "timestamp INTEGER NOT NULL, "
	                                    "type TEXT NOT NULL, "
	                                    "message TEXT NOT NULL, "
	                                    "blob1 BLOB, "
	                                    "blob2 BLOB, "
	                                    "blob3 BLOB, "
	                                    "blob4 BLOB, "
	                                    "blob5 BLOB );");

	// Update database version to 6
	if(!db_set_FTL_property(db, DB_VERSION, 6))
	{
		log_err("create_message_table(): Failed to update database version!");
		return false;
	}

	// End transaction
	SQL_bool(db, "COMMIT");

	return true;
}

// Flush message table
bool flush_message_table(void)
{
	sqlite3 *memdb = get_memdb();

	// Flush message table
	SQL_bool(memdb, "DELETE FROM disk.message;");

	return true;
}

static int add_message(const enum message_type type,
                       const char *message, const int count,...)
{
	int rowid = -1;
	// Return early if database is known to be broken
	if(FTLDBerror())
		return rowid;

	sqlite3 *db;
	// Open database connection
	if((db = dbopen(false, false)) == NULL)
	{
		log_err("add_message() - Failed to open DB");
		return rowid;
	}

	// Ensure there are no duplicates when adding messages
	sqlite3_stmt* stmt = NULL;
	const char *querystr = "DELETE FROM message WHERE type = ?1 AND message = ?2";
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("add_message(type=%u, message=%s) - SQL error prepare DELETE: %s",
		        type, message, sqlite3_errstr(rc));
		goto end_of_add_message;
	}

	// Bind type to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, get_message_type_str(type), -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("add_message(type=%u, message=%s) - Failed to bind type DELETE: %s",
			type, message, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		goto end_of_add_message;
	}

	// Bind message to prepared statement
	if((rc = sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("add_message(type=%u, message=%s) - Failed to bind message DELETE: %s",
			type, message, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		goto end_of_add_message;
	}

	// Execute and finalize
	if((rc = sqlite3_step(stmt)) != SQLITE_OK && rc != SQLITE_DONE)
	{
		log_err("add_message(type=%u, message=%s) - SQL error step DELETE: %s",
			type, message, sqlite3_errstr(rc));
		goto end_of_add_message;
	}
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);
	stmt = NULL;

	// Prepare SQLite statement
	querystr = "INSERT INTO message (timestamp,type,message,blob1,blob2,blob3,blob4,blob5) "
	           "VALUES ((cast(strftime('%s', 'now') as int)),?,?,?,?,?,?,?);";
	rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK )
	{
		log_err("add_message(type=%u, message=%s) - SQL error prepare: %s",
		        type, message, sqlite3_errstr(rc));
		goto end_of_add_message;
	}

	// Bind type to prepared statement
	if((rc = sqlite3_bind_text(stmt, 1, get_message_type_str(type), -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("add_message(type=%u, message=%s) - Failed to bind type: %s",
		        type, message, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		goto end_of_add_message;
	}

	// Bind message to prepared statement
	if((rc = sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("add_message(type=%u, message=%s) - Failed to bind message: %s",
		        type, message, sqlite3_errstr(rc));
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);
		goto end_of_add_message;
	}

	va_list ap;
	va_start(ap, count);
	for (int j = 0; j < count; j++)
	{
		const unsigned char datatype = message_blob_types[type][j];
		switch (datatype)
		{
			case SQLITE_INTEGER:
				rc = sqlite3_bind_int(stmt, 3 + j, va_arg(ap, int));
				break;

			case SQLITE_FLOAT:
				rc = sqlite3_bind_double(stmt, 3 + j, va_arg(ap, double));
				break;

			case SQLITE_TEXT:
				rc = sqlite3_bind_text(stmt, 3 + j, va_arg(ap, char*), -1, SQLITE_STATIC);
				break;

			case SQLITE_NULL: /* Fall through */
			default:
				log_warn("add_message(type=%s, message=%s) - Excess property, binding NULL",
				         get_message_type_str(type), message);
				rc = sqlite3_bind_null(stmt, 3 + j);
				break;
		}

		// Bind message to prepared statement
		if(rc != SQLITE_OK)
		{
			log_err("add_message(type=%u, message=%s) - Failed to bind argument %d (type %u): %s",
			        type, message, 3 + j, datatype, sqlite3_errstr(rc));
			sqlite3_reset(stmt);
			sqlite3_finalize(stmt);
			checkFTLDBrc(rc);
			va_end(ap);
			goto end_of_add_message;
		}
	}
	va_end(ap);

	// Step and check if successful
	rc = sqlite3_step(stmt);

	if(rc != SQLITE_DONE)
	{
		log_err("Encountered error while trying to store message in long-term database: %s", sqlite3_errstr(rc));
		checkFTLDBrc(rc);
		goto end_of_add_message;
	}

	// Final database handling
	sqlite3_clear_bindings(stmt);
	sqlite3_reset(stmt);
	sqlite3_finalize(stmt);

	// Get row ID of the newly added message
	rowid = sqlite3_last_insert_rowid(db);

end_of_add_message: // Close database connection
	dbclose(&db);

	return rowid;
}

bool delete_message(cJSON *ids, int *deleted)
{
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	sqlite3 *db;
	// Open database connection
	if((db = dbopen(false, false)) == NULL)
	{
		log_err("delete_message() - Failed to open DB");
		return false;
	}

	sqlite3_stmt *res = NULL;
	if(sqlite3_prepare_v2(db, "DELETE FROM message WHERE id = ?;", -1, &res, 0) != SQLITE_OK)
	{
		log_err("SQL error (%i): %s", sqlite3_errcode(db), sqlite3_errmsg(db));
		return false;
	}

	// Loop over id in ids array
	cJSON *id = NULL;
	cJSON_ArrayForEach(id, ids)
	{
		// Bind id to prepared statement
		const int idval = cJSON_GetNumberValue(id);
		sqlite3_bind_int(res, 1, idval);

		// Execute and finalize
		if(sqlite3_step(res) != SQLITE_DONE)
		{
			log_err("SQL error (%i): %s", sqlite3_errcode(db), sqlite3_errmsg(db));
			return false;
		}

		// Add to deleted count
		*deleted += sqlite3_changes(db);

		sqlite3_reset(res);
		sqlite3_clear_bindings(res);
	}
	sqlite3_finalize(res);

	// Close database connection
	dbclose(&db);

	return true;
}

static void format_regex_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *type, const char *regex, const char *warning, const int dbindex)
{
	if(snprintf(plain, sizeof_plain, "Invalid regex %s filter \"%s\": %s",
	            type, regex, warning) > sizeof_plain)
		log_warn("format_regex_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_regex = escape_html(regex);
	char *escaped_warning = escape_html(warning);

	if(snprintf(html, sizeof_html, "Encountered an error when processing <a href=\"groups-domains.lp?domainid=%d\">regex %s filter with ID %d</a>: <pre>%s</pre>Error message: <pre>%s</pre>",
	            dbindex, type, dbindex, escaped_regex, escaped_warning))
		log_warn("format_regex_message(): Buffer too small to hold HTML message, warning truncated");

	if(escaped_regex != NULL)
		free(escaped_regex);
	if(escaped_warning != NULL)
		free(escaped_warning);
}

static void format_subnet_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *ip, const int matching_count, const char *names, const char *matching_ids, const char *chosen_match_text, const int chosen_match_id)
{
	if(snprintf(plain, sizeof_plain, "Client %s is managed by %i groups (IDs %s), all describing the same subnet. "
	            "FTL chose the most recent entry %s (ID %i) to obtain the group configuration for this client.",
	            ip, matching_count, matching_ids,
	            chosen_match_text, chosen_match_id) > sizeof_plain)
		log_warn("format_subnet_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_ip = escape_html(ip);
	char *escaped_ids = escape_html(matching_ids);
	char *escaped_names = escape_html(names);

	if(snprintf(html, sizeof_html, "Client <code>%s</code> is managed by %i groups (IDs [%s]), all describing the same subnet:<pre>%s</pre>"
	            "FTL chose the most recent entry (ID %i) to obtain the group configuration for this client.",
	            escaped_ip, matching_count, escaped_ids, escaped_names, chosen_match_id) > sizeof_html)
		log_warn("format_subnet_message(): Buffer too small to hold HTML message, warning truncated");

	if(escaped_ip != NULL)
		free(escaped_ip);
	if(escaped_ids != NULL)
		free(escaped_ids);
	if(escaped_names != NULL)
		free(escaped_names);
}

static void format_hostname_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *ip, const char *name, const int pos)
{
	char *namep = escape_json(name);
	if(namep == NULL)
	{
		log_err("format_hostname_message(): Failed to JSON escape host name \"%s\" of client \"%s\"", name, ip);
		return;
	}

	// Check if the position is within the string before proceeding
	// This is a safety measure to prevent buffer overflows caused by
	// malicious database records
	if(pos > (int)strlen(name))
	{
		log_err("format_hostname_message(): Invalid position %i for host name \"%s\" of client \"%s\"", pos, namep, ip);
		if(namep != NULL)
			free(namep);
		return;
	}

	// Format the plain text message (the JSON string is already escaped and
	// contains "" around the string)
	if(snprintf(plain, sizeof_plain, "Host name of client \"%s\" => %s contains (at least) one invalid character (hex %02x) at position %i",
			ip, namep, (unsigned char)name[pos], pos) > sizeof_plain)
		log_warn("format_hostname_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
	{
		if(namep != NULL)
			free(namep);
		return;
	}

	char *escaped_ip = escape_html(ip);
	char *escaped_name = escape_html(namep);

	if(snprintf(html, sizeof_html, "Host name of client <code>%s</code> => <code>%s</code> contains (at least) one invalid character (hex %02x) at position %i",
			escaped_ip, escaped_name, (unsigned char)name[pos], pos) > sizeof_html)
		log_warn("format_hostname_message(): Buffer too small to hold HTML message, warning truncated");

	if(escaped_ip != NULL)
		free(escaped_ip);
	if(escaped_name != NULL)
		free(escaped_name);
	if(namep != NULL)
		free(namep);
}

static void format_dnsmasq_config_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *message)
{
	if(snprintf(plain, sizeof_plain, "Error in dnsmasq configuration: %s", message) > sizeof_plain)
		log_warn("format_dnsmasq_config_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_message = escape_html(message);

	if(snprintf(html, sizeof_html, "FTL failed to start due to %s.", escaped_message) > sizeof_html)
		log_warn("format_dnsmasq_config_message(): Buffer too small to hold HTML message, warning truncated");

	if(escaped_message != NULL)
		free(escaped_message);
}

static void format_rate_limit_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *clientIP, const unsigned int count, const unsigned int interval, const time_t turnaround)
{
	if(snprintf(plain, sizeof_plain, "Rate-limiting %s for at least %lu second%s",
			clientIP, (unsigned long int)turnaround, turnaround == 1 ? "" : "s") > sizeof_plain)
		log_warn("format_rate_limit_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_clientIP = escape_html(clientIP);

	if(snprintf(html, sizeof_html, "Client <code>%s</code> has been rate-limited for at least %lu second%s (current limit: %u queries per %u seconds)",
			escaped_clientIP, (unsigned long int)turnaround, turnaround == 1 ? "" : "s", count, interval) > sizeof_html)
		log_warn("format_rate_limit_message(): Buffer too small to hold HTML message, warning truncated");

	if(escaped_clientIP != NULL)
		free(escaped_clientIP);
}

static void format_dnsmasq_warn_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *message)
{
	if(snprintf(plain, sizeof_plain, "WARNING in dnsmasq core: %s", message) > sizeof_plain)
		log_warn("format_dnsmasq_warn_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	if(snprintf(html, sizeof_html, "Warning in <code>dnsmasq</code> core:<pre>%s</pre>Check out <a href=\"https://docs.pi-hole.net/ftldns/dnsmasq_warn/\" target=\"_blank\">our documentation</a> for further information.", message) > sizeof_html)
		log_warn("format_dnsmasq_warn_message(): Buffer too small to hold HTML message, warning truncated");
}

static void format_load_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const double load, const int nprocs)
{
	if(snprintf(plain, sizeof_plain, "Long-term load (15min avg) larger than number of processors: %.1f > %d",
	            load, nprocs) > sizeof_plain)
		log_warn("format_load_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	if(snprintf(html, sizeof_html, "Long-term load (15min avg) larger than number of processors: <strong>%.1f &gt; %d</strong><br>This may slow down DNS resolution and can cause bottlenecks.",
	            load, nprocs) > sizeof_html)
		log_warn("format_load_message(): Buffer too small to hold HTML message, warning truncated");
}

static void format_shmem_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *path, int shmem, const char *msg)
{
	if(snprintf(plain, sizeof_plain, "Shared memory shortage (%s) ahead: %d%% is used (%s)",
	            path, shmem, msg) > sizeof_plain)
		log_warn("format_messages(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_path = escape_html(path);
	char *escaped_msg = escape_html(msg);

	if(snprintf(html, sizeof_html, "Shared memory shortage (<code>%s</code>) ahead: <strong>%d%%</strong> is used<br>%s",
	            escaped_path, shmem, escaped_msg) > sizeof_html)
		log_warn("log_resource_shortage(): Buffer too small to hold HTML message, warning truncated");

	if(escaped_path != NULL)
		free(escaped_path);
	if(escaped_msg != NULL)
		free(escaped_msg);
}

static void format_disk_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html,
                                const char *path, const int disk, const char *msg)
{
	if(snprintf(plain, sizeof_plain, "Disk shortage ahead: %d%% is used (%s) on partition containing the file %s",
	            disk, msg, path) > sizeof_plain)
		log_warn("format_disk_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_path = escape_html(path);
	char *escaped_msg = escape_html(msg);


	if(snprintf(html, sizeof_html, "Disk shortage ahead: <strong>%d%%</strong> is used (%s) on partition containing the file <code>%s</code>",
	            disk, escaped_msg, escaped_path) > sizeof_html)
		log_warn("format_disk_message(): Buffer too small to hold HTML message, warning truncated");
}

static void format_disk_message_extended(char *plain, const int sizeof_plain, char *html, const int sizeof_html,
                                         const int disk, const char *msg, const char *mnt_type, const char *mnt_dir)
{
	if(snprintf(plain, sizeof_plain, "Disk shortage ahead: %d%% is used (%s) on %s filesystem mounted at %s",
	            disk, msg, mnt_type, mnt_dir) > sizeof_plain)
		log_warn("format_disk_message_extended(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_mnt_type = escape_html(mnt_type);
	char *escaped_mnt_dir = escape_html(mnt_dir);
	char *escaped_msg = escape_html(msg);

	if(snprintf(html, sizeof_html, "Disk shortage ahead: <strong>%d%%</strong> is used (%s) on %s filesystem mounted at <code>%s</code>",
	            disk, escaped_msg, escaped_mnt_type, escaped_mnt_dir) > sizeof_html)
		log_warn("format_disk_message_extended(): Buffer too small to hold HTML message, warning truncated");

	if(escaped_mnt_type != NULL)
		free(escaped_mnt_type);
	if(escaped_mnt_dir != NULL)
		free(escaped_mnt_dir);
	if(escaped_msg != NULL)
		free(escaped_msg);
}

static void format_inaccessible_adlist_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html,
                                               const char *address, int dbindex)
{
	if(snprintf(plain, sizeof_plain, "List with ID %d (%s) was inaccessible during last gravity run",
	        dbindex, address) > sizeof_plain)
		log_warn("format_inaccessible_adlist_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_address = escape_html(address);

	if(snprintf(html, sizeof_html, "<a href=\"groups/lists?listid=%i\">List with ID <strong>%d</strong> (<code>%s</code>)</a> was inaccessible during last gravity run",
	            dbindex, dbindex, escaped_address) > sizeof_html)
		log_warn("format_inaccessible_adlist_message(): Buffer too small to hold HTML message, warning truncated");

	if(escaped_address != NULL)
		free(escaped_address);
}

static void format_certificate_domain_mismatch(char *plain, const int sizeof_plain, char *html, const int sizeof_html,
                                               const char *certfile, const char*domain)
{
	if(snprintf(plain, sizeof_plain, "SSL/TLS certificate %s does not match domain %s!", certfile, domain) > sizeof_plain)
		log_warn("format_certificate_domain_mismatch(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_certfile = escape_html(certfile);
	char *escaped_domain = escape_html(domain);

	if(snprintf(html, sizeof_html, "SSL/TLS certificate %s does not match domain <strong>%s</strong>!", escaped_certfile, escaped_domain) > sizeof_html)
		log_warn("format_certificate_domain_mismatch(): Buffer too small to hold HTML message, warning truncated");

	if(escaped_certfile != NULL)
		free(escaped_certfile);
	if(escaped_domain != NULL)
		free(escaped_domain);
}

int count_messages(const bool filter_dnsmasq_warnings)
{
	int count = 0;

	if(FTLDBerror())
		return count;

	sqlite3 *db;
	// Open database connection
	if((db = dbopen(false, false)) == NULL)
	{
		log_err("count_messages() - Failed to open DB");
		return count;
	}

	// Get message
	sqlite3_stmt* stmt = NULL;
	const char *querystr = filter_dnsmasq_warnings ?  "SELECT COUNT(*) FROM message WHERE type != 'DNSMASQ_WARN'" : "SELECT COUNT(*) FROM message";
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("count_messages() - SQL error prepare SELECT: %s",
		        sqlite3_errstr(rc));
		goto end_of_count_messages;
	}

	// Execute and finalize
	rc = sqlite3_step(stmt);
	if( rc != SQLITE_ROW ){
		log_err("count_messages() - SQL error step SELECT: %s",
		        sqlite3_errstr(rc));
		goto end_of_count_messages;
	}

	// Get count
	count = sqlite3_column_int(stmt, 0);

end_of_count_messages: // Close database connection
	sqlite3_finalize(stmt);
	dbclose(&db);

	return count;
}

bool format_messages(cJSON *array)
{
	if(FTLDBerror())
		return false;

	sqlite3 *db;
	// Open database connection
	if((db = dbopen(false, false)) == NULL)
	{
		log_err("format_messages() - Failed to open DB");
		return false;
	}

	// Get message
	sqlite3_stmt* stmt = NULL;
	const char *querystr = "SELECT id,timestamp,type,message,blob1,blob2,blob3,blob4,blob5 FROM message";
	int rc = sqlite3_prepare_v2(db, querystr, -1, &stmt, NULL);
	if( rc != SQLITE_OK ){
		log_err("format_messages() - SQL error prepare SELECT: %s",
		        sqlite3_errstr(rc));
		goto end_of_format_message;
	}

	// Execute and finalize
	while((rc = sqlite3_step(stmt)) == SQLITE_ROW)
	{
		// Create JSON object
		cJSON *item = cJSON_CreateObject();
		if(item == NULL)
			break;

		// Add ID
		cJSON_AddNumberToObject(item, "id", sqlite3_column_int(stmt, 0));

		// Add timestamp
		cJSON_AddNumberToObject(item, "timestamp", sqlite3_column_double(stmt, 1));

		// Get message type
		const char *mtypestr = (const char*)sqlite3_column_text(stmt, 2);

		// Add message type
		cJSON_AddStringToObject(item, "type", mtypestr);

		// Generate messages
		char plain[1024] = { 0 }, html[2048] = { 0 };
		const int mtype = get_message_type_from_string(mtypestr);
		switch(mtype)
		{
			case REGEX_MESSAGE:
			{
				const char *warning = (const char*)sqlite3_column_text(stmt, 3);
				const char *type = (const char*)sqlite3_column_text(stmt, 4);
				const char *regex = (const char*)sqlite3_column_text(stmt, 5);
				const int dbindex = sqlite3_column_int(stmt, 6);

				format_regex_message(plain, sizeof(plain), html, sizeof(html),
				                     type, regex, warning, dbindex);

				break;
			}

			case SUBNET_MESSAGE:
			{
				const char *ip = (const char*)sqlite3_column_text(stmt, 3);
				const int matching_count = sqlite3_column_int(stmt, 4);
				const char *names = (const char*)sqlite3_column_text(stmt, 5);
				const char *matching_ids = (const char*)sqlite3_column_text(stmt, 6);
				const char *chosen_match_text = (const char*)sqlite3_column_text(stmt, 7);
				const int chosen_match_id = sqlite3_column_int(stmt, 8);

				format_subnet_message(plain, sizeof(plain), html, sizeof(html),
				                      ip, matching_count, names, matching_ids, chosen_match_text, chosen_match_id);

				break;
			}

			case HOSTNAME_MESSAGE:
			{
				const char *ip = (const char*)sqlite3_column_text(stmt, 3);
				const char *name = (const char*)sqlite3_column_text(stmt, 4);
				const int pos = sqlite3_column_int(stmt, 6);

				format_hostname_message(plain, sizeof(plain), html, sizeof(html),
				                        ip, name, pos);

				break;
			}

			case DNSMASQ_CONFIG_MESSAGE:
			{
				const char *message = (const char*)sqlite3_column_text(stmt, 3);

				format_dnsmasq_config_message(plain, sizeof(plain), html, sizeof(html),
				                              message);

				break;
			}

			case RATE_LIMIT_MESSAGE:
			{
				const char *clientIP = (const char*)sqlite3_column_text(stmt, 3);
				const unsigned int count = sqlite3_column_int(stmt, 4);
				const unsigned int interval = sqlite3_column_int(stmt, 5);
				const time_t turnaround = sqlite3_column_int(stmt, 6);

				format_rate_limit_message(plain, sizeof(plain), html, sizeof(html),
				                          clientIP, count, interval, turnaround);

				break;
			}

			case DNSMASQ_WARN_MESSAGE:
			{
				const char *message = (const char*)sqlite3_column_text(stmt, 3);

				format_dnsmasq_warn_message(plain, sizeof(plain), html, sizeof(html),
				                            message);

				break;
			}

			case LOAD_MESSAGE:
			{
				const double load = sqlite3_column_double(stmt, 4);
				const int nprocs = sqlite3_column_int(stmt, 5);

				format_load_message(plain, sizeof(plain), html, sizeof(html),
				                    load, nprocs);

				break;
			}

			case SHMEM_MESSAGE:
			{
				const char *path = (const char*)sqlite3_column_text(stmt, 3);
				const int shmem = sqlite3_column_int(stmt, 4);
				const char *msg = (const char*)sqlite3_column_text(stmt, 5);

				format_shmem_message(plain, sizeof(plain), html, sizeof(html),
				                     path, shmem, msg);

				break;

			}

			case DISK_MESSAGE:
			{
				const char *path = (const char*)sqlite3_column_text(stmt, 3);
				const int disk = sqlite3_column_int(stmt, 4);
				const char *msg = (const char*)sqlite3_column_text(stmt, 5);

				format_disk_message(plain, sizeof(plain), html, sizeof(html),
				                    path, disk, msg);

				break;
			}

			case DISK_MESSAGE_EXTENDED:
			{
				const int disk = sqlite3_column_int(stmt, 4);
				const char *msg = (const char*)sqlite3_column_text(stmt, 5);
				const char *mnt_type = (const char*)sqlite3_column_text(stmt, 6);
				const char *mnt_dir = (const char*)sqlite3_column_text(stmt, 7);

				format_disk_message_extended(plain, sizeof(plain), html, sizeof(html),
				                             disk, msg, mnt_type, mnt_dir);

				break;
			}

			case INACCESSIBLE_ADLIST_MESSAGE:
			{
				const char *address = (const char*)sqlite3_column_text(stmt, 3);
				const int dbindex = sqlite3_column_int(stmt, 4);

				format_inaccessible_adlist_message(plain, sizeof(plain), html, sizeof(html),
				                                   address, dbindex);

				break;
			}

			case CERTIFICATE_DOMAIN_MISMATCH_MESSAGE:
			{
				const char *certfile = (const char*)sqlite3_column_text(stmt, 3);
				const char *domain = (const char*)sqlite3_column_text(stmt, 4);

				format_certificate_domain_mismatch(plain, sizeof(plain), html, sizeof(html),
				                                   certfile, domain);

				break;
			}
		}

		// Add the plain message
		cJSON *pstring = cJSON_CreateString(plain);
		if(pstring == NULL)
			return item;
		cJSON_AddItemToObject(item, "plain", pstring);

		// Add the HTML message
		cJSON *hstring = cJSON_CreateString(html);
		if(hstring == NULL)
			return item;
		cJSON_AddItemToObject(item, "html", hstring);

		// Add the message to the array
		cJSON_AddItemToArray(array, item);
	}

	if(rc != SQLITE_DONE)
	{
		log_err("format_messages() - SQL error step SELECT: %s",
			sqlite3_errstr(rc));
		goto end_of_format_message;
	}

end_of_format_message: // Close database connection
	sqlite3_finalize(stmt);
	dbclose(&db);

	return true;
}

void logg_regex_warning(const char *type, const char *warning, const int dbindex, const char *regex)
{
	if(warning == NULL)
		warning = "No further info available";

	// Only log regex errors/warnings in the main process to prevent errors
	// being added multiple times to the database when a TCP worker
	// (re)compiles a faulty regex
	if(getpid() != main_pid())
		return;

	// Create message
	char buf[2048];
	format_regex_message(buf, sizeof(buf), NULL, 0, type, regex, warning, dbindex);

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database only if not in CLI mode
	if(cli_mode)
		return;

	// Add to database
	const int rowid = add_message(REGEX_MESSAGE, warning, 3, type, regex, dbindex);
	if(rowid == -1)
		log_err("logg_regex_warning(): Failed to add message to database");
}

void logg_subnet_warning(const char *ip, const int matching_count, const char *matching_ids,
                         const int matching_bits, const char *chosen_match_text,
                         const int chosen_match_id)
{
	char *names = get_client_names_from_ids(matching_ids);

	// Create message
	char buf[2048];
	format_subnet_message(buf, sizeof(buf), NULL, 0, ip, matching_count, names, matching_ids,
	                      chosen_match_text, chosen_match_id);

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	const int rowid = add_message(SUBNET_MESSAGE, ip, 5, matching_count, names, matching_ids, chosen_match_text, chosen_match_id);

	if(rowid == -1)
		log_err("logg_subnet_warning(): Failed to add message to database");

	free(names);
}

void logg_hostname_warning(const char *ip, const char *name, const unsigned int pos)
{
	// Create message
	char buf[2048] = { 0 };
	format_hostname_message(buf, sizeof(buf), NULL, 0, ip, name, pos);

	// Return early if we did not generate a message
	if(buf[0] == '\0')
		return;

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	const int rowid = add_message(HOSTNAME_MESSAGE, ip, 2, name, (const int)pos);

	if(rowid == -1)
		log_err("logg_hostname_warning(): Failed to add message to database");
}

void logg_fatal_dnsmasq_message(const char *message)
{
	// Create message
	char buf[2048];
	format_dnsmasq_config_message(buf, sizeof(buf), NULL, 0, message);

	// Log to FTL.log
	log_crit("%s", buf);

	// Log to database
	const int rowid = add_message(DNSMASQ_CONFIG_MESSAGE, message, 0);

	if(rowid == -1)
		log_err("logg_fatal_dnsmasq_message(): Failed to add message to database");
}

void logg_rate_limit_message(const char *clientIP, const unsigned int rate_limit_count)
{
	const time_t turnaround = get_rate_limit_turnaround(rate_limit_count);

	// Create message
	char buf[2048];
	format_rate_limit_message(buf, sizeof(buf), NULL, 0, clientIP, config.dns.rateLimit.count.v.ui, config.dns.rateLimit.interval.v.ui, turnaround);

	// Log to FTL.log
	log_info("%s", buf);

	// Log to database
	const int rowid = add_message(RATE_LIMIT_MESSAGE, clientIP, 3, config.dns.rateLimit.count.v.ui, config.dns.rateLimit.interval.v.ui, turnaround);

	if(rowid == -1)
		log_err("logg_rate_limit_message(): Failed to add message to database");
}

void logg_warn_dnsmasq_message(char *message)
{
	// Create message
	char buf[2048];
	format_dnsmasq_warn_message(buf, sizeof(buf), NULL, 0, message);

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	const int rowid = add_message(DNSMASQ_WARN_MESSAGE, message, 0);

	if(rowid == -1)
		log_err("logg_warn_dnsmasq_message(): Failed to add message to database");
}

void log_resource_shortage(const double load, const int nprocs, const int shmem, const int disk, const char *path, const char *msg)
{
	// Create message
	char buf[2048];

	if(load > 0.0)
	{
		format_load_message(buf, sizeof(buf), NULL, 0, load, nprocs);

		// Log to FTL.log
		log_warn("%s", buf);

		// Log to database
		const int rowid = add_message(LOAD_MESSAGE, "excessive load", 2, load, nprocs);

		if(rowid == -1)
			log_err("log_resource_shortage(): Failed to add message to database");
	}
	else if(shmem > -1)
	{
		format_shmem_message(buf, sizeof(buf), NULL, 0, path, shmem, msg);

		// Log to FTL.log
		log_warn("%s", buf);

		// Log to database
		const int rowid = add_message(SHMEM_MESSAGE, path, 2, shmem, msg);

		if(rowid == -1)
			log_err("log_resource_shortage(): Failed to add message to database");
	}
	else if(disk > -1)
	{
		// Get filesystem details for this path
		struct mntent *fsdetails = get_filesystem_details(path);

		// Create plain message
		if(fsdetails != NULL)
			format_disk_message_extended(buf, sizeof(buf), NULL, 0, disk, msg, fsdetails->mnt_type, fsdetails->mnt_dir);
		else
			format_disk_message(buf, sizeof(buf), NULL, 0, path, disk, msg);

		// Log to FTL.log
		log_warn("%s", buf);

		// Log to database
		const int rowid = fsdetails != NULL ?
			add_message(DISK_MESSAGE_EXTENDED, path, 4, disk, fsdetails->mnt_type, fsdetails->mnt_dir) :
			add_message(DISK_MESSAGE, path, 2, disk, msg);

		if(rowid == -1)
			log_err("log_resource_shortage(): Failed to add message to database");
	}
}

void logg_inaccessible_adlist(const int dbindex, const char *address)
{
	// Create message
	char buf[2048];
	format_inaccessible_adlist_message(buf, sizeof(buf), NULL, 0, address, dbindex);

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	const int rowid = add_message(INACCESSIBLE_ADLIST_MESSAGE, address, 1, dbindex);

	if(rowid == -1)
		log_err("logg_inaccessible_adlist(): Failed to add message to database");
}

void log_certificate_domain_mismatch(const char *certfile, const char *domain)
{
	// Create message
	char buf[2048];
	format_certificate_domain_mismatch(buf, sizeof(buf), NULL, 0, certfile, domain);

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	const int rowid = add_message(CERTIFICATE_DOMAIN_MISMATCH_MESSAGE, certfile, 1, domain);

	if(rowid == -1)
		log_err("log_certificate_domain_mismatch(): Failed to add message to database");
}
