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
// GIT_HASH, FTL_ARCH
#include "version.h"

// Number of arguments in a variadic macro
// Credit: https://stackoverflow.com/a/35693080/2087442
#define PP_NARG(...) \
         PP_NARG_(__VA_ARGS__,PP_RSEQ_N())
#define PP_NARG_(...) \
         PP_128TH_ARG(__VA_ARGS__)
#define PP_128TH_ARG( \
          _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
         _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
         _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
         _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
         _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
         _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
         _61,_62,_63,_64,_65,_66,_67,_68,_69,_70, \
         _71,_72,_73,_74,_75,_76,_77,_78,_79,_80, \
         _81,_82,_83,_84,_85,_86,_87,_88,_89,_90, \
         _91,_92,_93,_94,_95,_96,_97,_98,_99,_100, \
         _101,_102,_103,_104,_105,_106,_107,_108,_109,_110, \
         _111,_112,_113,_114,_115,_116,_117,_118,_119,_120, \
         _121,_122,_123,_124,_125,_126,_127,N,...) N
#define PP_RSEQ_N() \
         127,126,125,124,123,122,121,120, \
         119,118,117,116,115,114,113,112,111,110, \
         109,108,107,106,105,104,103,102,101,100, \
         99,98,97,96,95,94,93,92,91,90, \
         89,88,87,86,85,84,83,82,81,80, \
         79,78,77,76,75,74,73,72,71,70, \
         69,68,67,66,65,64,63,62,61,60, \
         59,58,57,56,55,54,53,52,51,50, \
         49,48,47,46,45,44,43,42,41,40, \
         39,38,37,36,35,34,33,32,31,30, \
         29,28,27,26,25,24,23,22,21,20, \
         19,18,17,16,15,14,13,12,11,10, \
         9,8,7,6,5,4,3,2,1,0

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
		case CONNECTION_ERROR_MESSAGE:
			return "CONNECTION_ERROR";
		case NTP_MESSAGE:
			return "NTP";
		case VERIFY_MESSAGE:
			return "VERIFY";
		case GRAVITY_RESTORED_MESSAGE:
			return "GRAVITY_RESTORED";
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
	else if (strcmp(typestr, "CONNECTION_ERROR") == 0)
		return CONNECTION_ERROR_MESSAGE;
	else if (strcmp(typestr, "NTP") == 0)
		return NTP_MESSAGE;
	else if (strcmp(typestr, "VERIFY") == 0)
		return VERIFY_MESSAGE;
	else if (strcmp(typestr, "GRAVITY_RESTORED") == 0)
		return GRAVITY_RESTORED_MESSAGE;
	else
		return MAX_MESSAGE;
}

static unsigned char message_blob_types[MAX_MESSAGE][5] =
	{
		{	// REGEX_MESSAGE: The message column contains the regex text (the erroring regex filter itself)
			SQLITE_TEXT, // regex type ("deny", "allow")
			SQLITE_TEXT, // regex warning text
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
		},
		{
			// CONNECTION_ERROR_MESSAGE: The message column contains the server address
			SQLITE_TEXT, // reason
			SQLITE_TEXT, // error message
			SQLITE_NULL, // not used
			SQLITE_NULL, // not used
			SQLITE_NULL // not used
		},
		{
			// NTP: The message column contains the warning/error
			SQLITE_TEXT, // level (warning/error)
			SQLITE_TEXT, // component (server/client)
			SQLITE_NULL, // not used
			SQLITE_NULL, // not used
			SQLITE_NULL // not used
		},
		{
			// VERIFY_MESSAGE: The message column contains the error
			SQLITE_TEXT, // expected checksum
			SQLITE_TEXT, // actual checksum
			SQLITE_TEXT, // FTL commit hash
			SQLITE_TEXT, // FTL architecture
			SQLITE_NULL // not used
		},
		{
			// GRAVITY_RESTORED_MESSAGE: The message column contains the status
			SQLITE_NULL, // not used
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

static int _add_message(const enum message_type type,
                        const char *message, const size_t count, ...);
#define add_message(type, message, ...) _add_message(type, message, PP_NARG(__VA_ARGS__), __VA_ARGS__)
#define add_message_no_args(type, message) _add_message(type, message, 0)

static int _add_message(const enum message_type type,
                        const char *message, const size_t count,...)
{
	// Log to database only if not in CLI mode
	if(cli_mode)
		return -1;

	int rowid = -1;
	// Return early if database is known to be broken
	if(FTLDBerror())
		return -1;

	// Check if message type is known
	if(type >= MAX_MESSAGE)
	{
		log_err("add_message(type=%u, message=%s) - Invalid message type with %zu arguments",
		        type, message, count);
		return -1;
	}

	// Check if number of arguments is valid
	// Total number of arguments
	if(count > 5)
	{
		log_err("add_message(type=%u, message=%s) - Too many arguments (%zu), expected at most 5",
		        type, message, count);
		return -1;
	}
	// No arguments check
	if(count == 0 && message_blob_types[type][0] != SQLITE_NULL)
	{
		log_err("add_message(type=%u, message=%s) - Invalid number of arguments: No arguments passed for message type requiring arguments",
		        type, message);
		return -1;
	}
	// Non-zero arguments check
	else if(count > 1 && message_blob_types[type][count - 2] == SQLITE_NULL)
	{
		log_err("add_message(type=%u, message=%s) - Invalid number of arguments: Too many (%zu) arguments passed for this message type",
		        type, message, count);
		return -1;
	}

	sqlite3 *db = dbopen(false, false);
	// Open database connection
	if(db == NULL)
		// Reason for failure is logged in dbopen()
		return -1;

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
		goto end_of_add_message;
	}

	// Bind message to prepared statement
	if((rc = sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("add_message(type=%u, message=%s) - Failed to bind message DELETE: %s",
			type, message, sqlite3_errstr(rc));
		goto end_of_add_message;
	}

	// Execute and finalize (we accept both SQLITE_OK = removed and
	// SQLITE_DONE = nothing to remove)
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
		goto end_of_add_message;
	}

	// Bind message to prepared statement
	if((rc = sqlite3_bind_text(stmt, 2, message, -1, SQLITE_STATIC)) != SQLITE_OK)
	{
		log_err("add_message(type=%u, message=%s) - Failed to bind message: %s",
		        type, message, sqlite3_errstr(rc));
		goto end_of_add_message;
	}

	va_list ap;
	va_start(ap, count);
	for (size_t j = 0; j < count; j++)
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
			log_err("add_message(type=%u, message=%s) - Failed to bind argument %zu (type %u): %s",
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

end_of_add_message: // Close database connection

	// Final database handling
	if(stmt != NULL)
	{
		sqlite3_clear_bindings(stmt);
		sqlite3_reset(stmt);
		sqlite3_finalize(stmt);

		// Get row ID of the newly added message
		rowid = sqlite3_last_insert_rowid(db);
	}

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

	// Return early if memory allocation failed
	if(escaped_regex == NULL || escaped_warning == NULL)
	{
		if(escaped_regex != NULL)
			free(escaped_regex);
		if(escaped_warning != NULL)
			free(escaped_warning);
		return;
	}

	if(snprintf(html, sizeof_html, "Encountered an error when processing <a href=\"groups-domains.lp?domainid=%d\">regex %s filter with ID %d</a>: <pre>%s</pre>Error message: <pre>%s</pre>",
	            dbindex, type, dbindex, escaped_regex, escaped_warning) > sizeof_html)
		log_warn("format_regex_message(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_regex);
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

	// Return early if memory allocation failed
	if(escaped_ip == NULL || escaped_ids == NULL || escaped_names == NULL)
	{
		if(escaped_ip != NULL)
			free(escaped_ip);
		if(escaped_ids != NULL)
			free(escaped_ids);
		if(escaped_names != NULL)
			free(escaped_names);
		return;
	}

	if(snprintf(html, sizeof_html, "Client <code>%s</code> is managed by %i groups (IDs [%s]), all describing the same subnet:<pre>%s</pre>"
	            "FTL chose the most recent entry (ID %i) to obtain the group configuration for this client.",
	            escaped_ip, matching_count, escaped_ids, escaped_names, chosen_match_id) > sizeof_html)
		log_warn("format_subnet_message(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_ip);
	free(escaped_ids);
	free(escaped_names);
}

static void format_hostname_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *ip, const char *name, const int pos)
{
	// Format the plain text message (the JSON string is already escaped and
	// contains "" around the string)
	if(snprintf(plain, sizeof_plain, "Host name of client \"%s\" => %s contains (at least) one invalid character at position %i",
			ip, name, pos) > sizeof_plain)
		log_warn("format_hostname_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_ip = escape_html(ip);
	char *escaped_name = escape_html(name);

	// Return early if memory allocation failed
	if(escaped_ip == NULL || escaped_name == NULL)
	{
		if(escaped_ip != NULL)
			free(escaped_ip);
		if(escaped_name != NULL)
			free(escaped_name);
		return;
	}

	if(snprintf(html, sizeof_html, "Host name of client <code>%s</code> => <code>%s</code> contains (at least) one invalid character (hex %02x) at position %i",
			escaped_ip, escaped_name, (unsigned char)name[pos], pos) > sizeof_html)
		log_warn("format_hostname_message(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_ip);
	free(escaped_name);
}

static void format_dnsmasq_config_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *message)
{
	if(snprintf(plain, sizeof_plain, "Error in dnsmasq configuration: %s", message) > sizeof_plain)
		log_warn("format_dnsmasq_config_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_message = escape_html(message);

	// Return early if memory allocation failed
	if(escaped_message == NULL)
		return;

	if(snprintf(html, sizeof_html, "FTL failed to start due to %s.", escaped_message) > sizeof_html)
		log_warn("format_dnsmasq_config_message(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_message);
}

static void format_rate_limit_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *clientIP, const int count, const int interval, const int turnaround)
{
	if(snprintf(plain, sizeof_plain, "Rate-limiting %s for at least %d second%s",
	            clientIP, turnaround, turnaround == 1 ? "" : "s") > sizeof_plain)
		log_warn("format_rate_limit_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_clientIP = escape_html(clientIP);

	// Return early if memory allocation failed
	if(escaped_clientIP == NULL)
		return;

	if(snprintf(html, sizeof_html, "Client <code>%s</code> has been rate-limited for at least %d second%s (current limit: %d queries per %d seconds)",
	            escaped_clientIP, turnaround, turnaround == 1 ? "" : "s", count, interval) > sizeof_html)
		log_warn("format_rate_limit_message(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_clientIP);
}

static void format_dnsmasq_warn_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html, const char *message)
{
	if(snprintf(plain, sizeof_plain, "dnsmasq: %s", message) > sizeof_plain)
		log_warn("format_dnsmasq_warn_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	if(snprintf(html, sizeof_html, "<code>dnsmasq</code> warning:<pre>%s</pre>Check out <a href=\"https://docs.pi-hole.net/ftldns/dnsmasq_warn/\" target=\"_blank\">our documentation</a> for further information.", message) > sizeof_html)
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

	// Return early if memory allocation failed
	if(escaped_path == NULL || escaped_msg == NULL)
	{
		if(escaped_path != NULL)
			free(escaped_path);
		if(escaped_msg != NULL)
			free(escaped_msg);
		return;
	}

	if(snprintf(html, sizeof_html, "Shared memory shortage (<code>%s</code>) ahead: <strong>%d%%</strong> is used<br>%s",
	            escaped_path, shmem, escaped_msg) > sizeof_html)
		log_warn("log_resource_shortage(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_path);
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

	// Return early if memory allocation failed
	if(escaped_path == NULL || escaped_msg == NULL)
	{
		if(escaped_path != NULL)
			free(escaped_path);
		if(escaped_msg != NULL)
			free(escaped_msg);
		return;
	}

	if(snprintf(html, sizeof_html, "Disk shortage ahead: <strong>%d%%</strong> is used (%s) on partition containing the file <code>%s</code>",
	            disk, escaped_msg, escaped_path) > sizeof_html)
		log_warn("format_disk_message(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_path);
	free(escaped_msg);
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

	// Return early if memory allocation failed
	if(escaped_mnt_type == NULL || escaped_mnt_dir == NULL || escaped_msg == NULL)
	{
		if(escaped_mnt_type != NULL)
			free(escaped_mnt_type);
		if(escaped_mnt_dir != NULL)
			free(escaped_mnt_dir);
		if(escaped_msg != NULL)
			free(escaped_msg);
		return;
	}

	if(snprintf(html, sizeof_html, "Disk shortage ahead: <strong>%d%%</strong> is used (%s) on %s filesystem mounted at <code>%s</code>",
	            disk, escaped_msg, escaped_mnt_type, escaped_mnt_dir) > sizeof_html)
		log_warn("format_disk_message_extended(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_mnt_type);
	free(escaped_mnt_dir);
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

	// Return early if memory allocation failed
	if(escaped_address == NULL)
		return;

	if(snprintf(html, sizeof_html, "<a href=\"groups/lists?listid=%i\">List with ID <strong>%d</strong> (<code>%s</code>)</a> was inaccessible during last gravity run",
	            dbindex, dbindex, escaped_address) > sizeof_html)
		log_warn("format_inaccessible_adlist_message(): Buffer too small to hold HTML message, warning truncated");

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

	// Return early if memory allocation failed
	if(escaped_certfile == NULL || escaped_domain == NULL)
	{
		if(escaped_certfile != NULL)
			free(escaped_certfile);
		if(escaped_domain != NULL)
			free(escaped_domain);
		return;
	}

	if(snprintf(html, sizeof_html, "SSL/TLS certificate %s does not match domain <strong>%s</strong>!", escaped_certfile, escaped_domain) > sizeof_html)
		log_warn("format_certificate_domain_mismatch(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_certfile);
	free(escaped_domain);
}

static void format_connection_error(char *plain, const int sizeof_plain, char *html, const int sizeof_html,
                                    const char *server, const char *reason, const char *error)
{
	if(snprintf(plain, sizeof_plain, "Connection error (%s): %s (%s)", server, reason, error) > sizeof_plain)
		log_warn("format_connection_error(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_reason = escape_html(reason);
	char *escaped_error = escape_html(error);
	char *escaped_server = escape_html(server);

	// Return early if memory allocation failed
	if(escaped_reason == NULL || escaped_error == NULL || escaped_server == NULL)
	{
		if(escaped_reason != NULL)
			free(escaped_reason);
		if(escaped_error != NULL)
			free(escaped_error);
		if(escaped_server != NULL)
			free(escaped_server);
		return;
	}

	if(snprintf(html, sizeof_html, "Connection error (<strong>%s</strong>): %s (<strong>%s</strong>)", server, reason, error) > sizeof_html)
		log_warn("format_connection_error(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_reason);
	free(escaped_error);
	free(escaped_server);
}

static void format_ntp_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html,
                               const char *message, const char *level, const char *who)
{
	if(snprintf(plain, sizeof_plain, "%s NTP %s: %s", level, who, message) > sizeof_plain)
		log_warn("format_ntp_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	if(snprintf(html, sizeof_html, "%s in NTP %s:<pre>%s</pre>", level, who, message) > sizeof_html)
		log_warn("format_ntp_message(): Buffer too small to hold HTML message, warning truncated");
}

static void format_verify_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html,
                                  const char *message, const char *expected, const char *actual,
                                  const char *commit, const char *arch)
{
	if(snprintf(plain, sizeof_plain, "%s - expected \"%s\", but got \"%s\" - FTL commit is %s on %s",
	            message, expected, actual, commit, arch) > sizeof_plain)
		log_warn("format_verify_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	char *escaped_message = escape_html(message);
	char *escaped_expected = escape_html(expected);
	char *escaped_actual = escape_html(actual);
	char *escaped_commit = escape_html(commit);
	char *escaped_arch = escape_html(arch);

	// Return early if memory allocation failed
	if(escaped_message == NULL || escaped_expected == NULL || escaped_actual == NULL || escaped_commit == NULL || escaped_arch == NULL)
		return;

	if(snprintf(html, sizeof_html, "%s<br>Expected: <pre>%s</pre><br>Actual: <pre>%s</pre><br>FTL commit is <code>%s</code> on <code>%s</code>",
	            escaped_message, escaped_expected, escaped_actual, escaped_commit, escaped_arch) > sizeof_html)
		log_warn("format_verify_message(): Buffer too small to hold HTML message, warning truncated");

	free(escaped_message);
	free(escaped_expected);
	free(escaped_actual);
	free(escaped_commit);
	free(escaped_arch);
}

static void format_gravity_restored_message(char *plain, const int sizeof_plain, char *html, const int sizeof_html,
                                            const char *status)
{
	const bool failed = strcmp(status, "failed") == 0;

	if(snprintf(plain, sizeof_plain, "Gravity database restore %s", failed ? "failed" : "successful") > sizeof_plain)
		log_warn("format_gravity_restored_message(): Buffer too small to hold plain message, warning truncated");

	// Return early if HTML text is not required
	if(sizeof_html < 1 || html == NULL)
		return;

	if(failed)
	{
		if(snprintf(html, sizeof_html, "Gravity database damaged, restore attempt <strong class=\"log-red\">failed</strong><br><br>Please check your filesystem for corruption, and your disk space for availability.") > sizeof_html)
			log_warn("format_gravity_restored_message(): Buffer too small to hold HTML message, warning truncated");
	}
	else
	{
		char *escaped_status = escape_html(status);

		// Return early if memory allocation failed
		if(escaped_status == NULL)
			return;

		if(snprintf(html, sizeof_html, "Gravity database damaged, restore attempt <strong class=\"log-green\">successful</strong><br>The gravity database was restored using the automatic backup created on %s<br><br>Please check your filesystem for corruption, and your disk space for availability.", escaped_status) > sizeof_html)

		free(escaped_status);
	}
}

int count_messages(void)
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
	const char *querystr = config.misc.hide_dnsmasq_warn.v.b ?
			"SELECT COUNT(*) FROM message WHERE type != 'DNSMASQ_WARN'" :
			"SELECT COUNT(*) FROM message";
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
	{
		log_err("format_messages() - Database not available");
		return false;
	}

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
		{
			log_err("format_messages() - Failed to create JSON object");
			break;
		}

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
		const enum message_type mtype = get_message_type_from_string(mtypestr);
		switch(mtype)
		{
			case REGEX_MESSAGE:
			{
				const char *regex = (const char*)sqlite3_column_text(stmt, 3);
				const char *type = (const char*)sqlite3_column_text(stmt, 4);
				const char *warning = (const char*)sqlite3_column_text(stmt, 5);
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
				const int pos = sqlite3_column_int(stmt, 5);

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
				const int count = sqlite3_column_int(stmt, 4);
				const int interval = sqlite3_column_int(stmt, 5);
				const int turnaround = sqlite3_column_int(stmt, 6);

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

			case CONNECTION_ERROR_MESSAGE:
			{
				const char *server = (const char*)sqlite3_column_text(stmt, 3);
				const char *reason = (const char*)sqlite3_column_text(stmt, 4);
				const char *error = (const char*)sqlite3_column_text(stmt, 5);

				format_connection_error(plain, sizeof(plain), html, sizeof(html),
				                        server, reason, error);

				break;
			}

			case NTP_MESSAGE:
			{
				const char *message = (const char*)sqlite3_column_text(stmt, 3);
				const char *level = (const char*)sqlite3_column_text(stmt, 4);
				const char *who = (const char*)sqlite3_column_text(stmt, 5);

				format_ntp_message(plain, sizeof(plain), html, sizeof(html),
				                   message, level, who);

				break;
			}

			case VERIFY_MESSAGE:
			{
				const char *message = (const char*)sqlite3_column_text(stmt, 3);
				const char *expected = (const char*)sqlite3_column_text(stmt, 4);
				const char *actual = (const char*)sqlite3_column_text(stmt, 5);
				const char *hash = (const char*)sqlite3_column_text(stmt, 6);
				const char *arch = (const char*)sqlite3_column_text(stmt, 7);

				format_verify_message(plain, sizeof(plain), html, sizeof(html),
				                      message, expected, actual, hash, arch);

				break;
			}

			case GRAVITY_RESTORED_MESSAGE:
			{
				const char *status = (const char*)sqlite3_column_text(stmt, 3);

				format_gravity_restored_message(plain, sizeof(plain), html, sizeof(html),
				                                status);

				break;
			}

			case MAX_MESSAGE: // Fall through
			default:
				log_warn("format_messages() - Unknown message type: %s", mtypestr);
				break;
		}

		// Add the plain message
		cJSON *pstring = cJSON_CreateString(plain);
		if(pstring == NULL)
		{
			log_err("format_messages() - Failed to create plain message string from %s", plain);
			cJSON_Delete(item);
			break;
		}
		cJSON_AddItemToObject(item, "plain", pstring);

		// Add the HTML message
		cJSON *hstring = cJSON_CreateString(html);
		if(hstring == NULL)
		{
			log_err("format_messages() - Failed to create HTML message string from %s", html);
			cJSON_Delete(item);
			break;
		}
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

	// Add to database
	add_message(REGEX_MESSAGE, regex, type, warning, dbindex);
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
	add_message(SUBNET_MESSAGE, ip, matching_count, names, matching_ids, chosen_match_text, chosen_match_id);


	free(names);
}

void log_hostname_warning(const char *ip, const char *name, const unsigned int pos)
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
	add_message(HOSTNAME_MESSAGE, ip, name, (const int)pos);

}

void logg_fatal_dnsmasq_message(const char *message)
{
	// Create message
	char buf[2048];
	format_dnsmasq_config_message(buf, sizeof(buf), NULL, 0, message);

	// Log to FTL.log
	log_crit("%s", buf);

	// Log to database
	add_message_no_args(DNSMASQ_CONFIG_MESSAGE, message);

}

void logg_rate_limit_message(const char *clientIP, const unsigned int rate_limit_count)
{
	const int turnaround = get_rate_limit_turnaround(rate_limit_count);

	// Create message
	char buf[2048];
	format_rate_limit_message(buf, sizeof(buf), NULL, 0, clientIP, config.dns.rateLimit.count.v.ui, config.dns.rateLimit.interval.v.ui, turnaround);

	// Log to FTL.log
	log_info("%s", buf);

	// Log to database
	add_message(RATE_LIMIT_MESSAGE, clientIP, config.dns.rateLimit.count.v.ui, config.dns.rateLimit.interval.v.ui, turnaround);

}

void logg_warn_dnsmasq_message(char *message)
{
	// Create message
	char buf[2048];
	format_dnsmasq_warn_message(buf, sizeof(buf), NULL, 0, message);

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	add_message_no_args(DNSMASQ_WARN_MESSAGE, message);

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
		add_message(LOAD_MESSAGE, "excessive load", load, nprocs);


	}
	else if(shmem > -1)
	{
		format_shmem_message(buf, sizeof(buf), NULL, 0, path, shmem, msg);

		// Log to FTL.log
		log_warn("%s", buf);

		// Log to database
		add_message(SHMEM_MESSAGE, path, shmem, msg);


	}
	else if(disk > -1)
	{
		// Get filesystem details for this path
		struct mntent *fsdetails = get_filesystem_details(path);

		// Log filesystem details if in debug mode
		if(config.debug.gc.v.b)
		{
			if(fsdetails != NULL)
			{
				log_debug(DEBUG_GC, "Disk details for path \"%s\":", path);
				log_debug(DEBUG_GC, "  Device or server for filesystem: %s", fsdetails->mnt_fsname);
				log_debug(DEBUG_GC, "  Directory mounted on: %s", fsdetails->mnt_dir);
				log_debug(DEBUG_GC, "  Type of filesystem: %s", fsdetails->mnt_type);
				log_debug(DEBUG_GC, "  Comma-separated options for fs: %s", fsdetails->mnt_opts);
				log_debug(DEBUG_GC, "  Dump frequency (in days): %d", fsdetails->mnt_freq);
				log_debug(DEBUG_GC, "  Pass number for `fsck': %d", fsdetails->mnt_passno);
			}
			else
				log_debug(DEBUG_GC, "Failed to get filesystem details for path \"%s\"", path);
		}

		// Create plain message
		if(fsdetails != NULL)
			format_disk_message_extended(buf, sizeof(buf), NULL, 0, disk, msg, fsdetails->mnt_type, fsdetails->mnt_dir);
		else
			format_disk_message(buf, sizeof(buf), NULL, 0, path, disk, msg);

		// Log to FTL.log
		log_warn("%s", buf);

		// Log to database
		fsdetails != NULL ?
			add_message(DISK_MESSAGE_EXTENDED, path, disk, msg, fsdetails->mnt_type, fsdetails->mnt_dir) :
			add_message(DISK_MESSAGE, path, disk, msg);


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
	add_message(INACCESSIBLE_ADLIST_MESSAGE, address, dbindex);

}

void log_certificate_domain_mismatch(const char *certfile, const char *domain)
{
	// Create message
	char buf[2048];
	format_certificate_domain_mismatch(buf, sizeof(buf), NULL, 0, certfile, domain);

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	add_message(CERTIFICATE_DOMAIN_MISMATCH_MESSAGE, certfile, domain);

}

void log_connection_error(const char *server, const char *reason, const char *error)
{
	// Create message
	char buf[2048];
	format_connection_error(buf, sizeof(buf), NULL, 0, server, reason, error);

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	add_message(CONNECTION_ERROR_MESSAGE, server, reason, error);

}

void log_ntp_message(const bool error, const bool server, const char *message)
{
	const char *who = server ? "server" : "client";
	const char *level = error ? "Error" : "Warning";

	// Create message
	char buf[2048];
	format_ntp_message(buf, sizeof(buf), NULL, 0, message, level, who);

	// Log to FTL.log
	if(error)
		log_err("%s", buf);
	else
		log_warn("%s", buf);

	// Log to database
	add_message(NTP_MESSAGE, message, level, who);

}

void log_verify_message(const char *expected, const char *actual)
{
	// Create message
	char buf[2048];
	snprintf(buf, sizeof(buf), "Corrupt binary detected - this may lead to unexpected behaviour!");

	// Log to FTL.log
	log_crit("%s", buf);

	// Log to database
	add_message(VERIFY_MESSAGE, buf, expected, actual, git_hash(), ftl_arch());

}

void log_gravity_restored(const char *status)
{
	// Create message
	char buf[2048];
	format_gravity_restored_message(buf, sizeof(buf), NULL, 0, status);

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	add_message_no_args(GRAVITY_RESTORED_MESSAGE, status);

}
