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

static cJSON *messages = NULL;

// Return a copy of the message table JSON object
cJSON * __attribute__((pure)) get_messages(void)
{
	if(messages)
		return cJSON_Duplicate(messages, true);
	else
		return cJSON_CreateArray();
}

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
			return "ADLIST";
		case MAX_MESSAGE:
		default:
			return "UNKNOWN";
	}
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
			SQLITE_NULL, // Not used
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
	};
// Create message table in the database
bool create_message_table(sqlite3 *db)
{
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

	return true;
}

// Flush message table
bool flush_message_table(void)
{
	// Free memory allocated for messages
	if(messages != NULL)
	{
		cJSON_Delete(messages);
		messages = NULL;
	}
	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	sqlite3 *db;
	// Open database connection
	if((db = dbopen(false)) == NULL)
	{
		log_err("flush_message_table() - Failed to open DB");
		return false;
	}

	// Flush message table
	SQL_bool(db, "DELETE FROM message;");

	// Close database connection
	dbclose(&db);

	return true;
}

static int add_message(const enum message_type type,
                       const char *message, const int count,...)
{
	// Allocate memory for messages if not already done
	if(messages == NULL)
	{
		messages = cJSON_CreateArray();
		if(messages == NULL)
		{
			log_err("add_message() - Failed to create JSON array");
			return -1;
		}
	}

	int rowid = -1;
	// Return early if database is known to be broken
	if(FTLDBerror())
		return rowid;

	sqlite3 *db;
	// Open database connection
	if((db = dbopen(false)) == NULL)
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

bool delete_message(const long id)
{
	// Find message with this ID in our JSON messages array
	for(int i = 0; i < cJSON_GetArraySize(messages); i++)
	{
		// Get message
		cJSON *message = cJSON_GetArrayItem(messages, i);
		if(message == NULL)
			continue;

		// Get ID
		cJSON *jid = cJSON_GetObjectItem(message, "id");
		if(jid == NULL)
			continue;

		// Check if this is the message we want to delete
		log_debug(DEBUG_API, "Checking message with ID %i", jid->valueint);
		if(jid->valueint == id)
		{
			// Delete message from array
			log_debug(DEBUG_API, "Deleting message with ID %li from array", id);
			cJSON_DeleteItemFromArray(messages, i);
			break;
		}
	}

	// Return early if database is known to be broken
	if(FTLDBerror())
		return false;

	sqlite3 *db;
	// Open database connection
	if((db = dbopen(false)) == NULL)
	{
		log_err("delete_message(%li) - Failed to open DB", id);
		return false;
	}

	sqlite3_stmt *res = NULL;
	if(sqlite3_prepare_v2(db, "DELETE FROM message WHERE id = ?;", -1, &res, 0) != SQLITE_OK)
	{
		log_err("SQL error (%i): %s", sqlite3_errcode(db), sqlite3_errmsg(db));
		return false;
	}
	sqlite3_bind_int(res, 1, id);
	if(sqlite3_step(res) != SQLITE_DONE)
	{
		log_err("SQL error (%i): %s", sqlite3_errcode(db), sqlite3_errmsg(db));
		return false;
	}
	sqlite3_finalize(res);

	// Close database connection
	dbclose(&db);

	return true;
}

static cJSON *add_plain_message(const char *message, const int rowid, const enum message_type type)
{
	// Create JSON object
	cJSON *item = cJSON_CreateObject();
	if(item == NULL)
		return item;

	// Add ID
	cJSON_AddNumberToObject(item, "id", rowid);

	// Add timestamp
	cJSON_AddNumberToObject(item, "timestamp", double_time());

	// Add message type
	cJSON *typestr = cJSON_CreateStringReference(get_message_type_str(type));
	if(typestr == NULL)
		return item;
	cJSON_AddItemToObject(item, "type", typestr);

	// Add the plain message
	cJSON *string = cJSON_CreateString(message);
	if(string == NULL)
		return item;
	cJSON_AddItemToObject(item, "plain", string);

	// Add item to messages array
	cJSON_AddItemToArray(messages, item);

	return item;
}

static bool add_html_message(cJSON *item, const char *message)
{
	// Add the HTML message
	cJSON *string = cJSON_CreateString(message);
	if(string == NULL)
		return false;
	return cJSON_AddItemToObject(item, "html", string);
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
	size_t ret;
	char buf[2048];
	ret = snprintf(buf, sizeof(buf), "Invalid regex %s filter \"%s\": %s",
	               type, regex, warning);
	if(ret > sizeof(buf))
		log_warn("logg_regex_warning(): Buffer too small to hold plain message, warning truncated");

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database only if not in CLI mode
	if(!cli_mode)
	{
		// Add to database
		const int rowid = add_message(REGEX_MESSAGE, warning, 3, type, regex, dbindex);

		// Add to plain_messages
		cJSON *item = add_plain_message(buf, rowid, REGEX_MESSAGE);

		// Create HTML message
		ret = snprintf(buf, sizeof(buf), "Encountered an error when processing <a href=\"groups-domains.php?domainid=%d\">regex %s filter with ID %d</a>: <pre>%s</pre>Error message: <pre>%s</pre>",
		               dbindex, type, dbindex, regex, warning);
		if(ret > sizeof(buf))
			log_warn("logg_regex_warning(): Buffer too small to hold HTML message, warning truncated");
		add_html_message(item, buf);
	}
}

void logg_subnet_warning(const char *ip, const int matching_count, const char *matching_ids,
                         const int matching_bits, const char *chosen_match_text,
                         const int chosen_match_id)
{
	// Create message
	size_t ret;
	char buf[2048];
	ret = snprintf(buf, sizeof(buf), "Client %s is managed by %i groups (IDs %s), all describing /%i subnets. "
	               "FTL chose the most recent entry %s (ID %i) for this client.",
	               ip, matching_count, matching_ids, matching_bits,
	               chosen_match_text, chosen_match_id);
	if(ret > sizeof(buf))
		log_warn("logg_regex_warning(): Buffer too small to hold plain message, warning truncated");

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	char *names = get_client_names_from_ids(matching_ids);
	const int rowid = add_message(SUBNET_MESSAGE, ip, 5, matching_count, names, matching_ids, chosen_match_text, chosen_match_id);

	// Add to plain_messages
	cJSON *item = add_plain_message(buf, rowid, SUBNET_MESSAGE);

	// Create HTML message
	ret = snprintf(buf, sizeof(buf), "Client <code>%s</code> is managed by %i groups (IDs [%s]), all describing /%i subnets:<pre>%s</pre>FTL chose the most recent entry (ID %i) to obtain the group configuration for this client.",
	               ip, matching_count, matching_ids, matching_bits, names, chosen_match_id);
	if(ret > sizeof(buf))
		log_warn("logg_regex_warning(): Buffer too small to hold HTML message, warning truncated");
	add_html_message(item, buf);
	free(names);
}

void logg_hostname_warning(const char *ip, const char *name, const unsigned int pos)
{
	// Create message
	size_t ret;
	char buf[2048];
	ret = snprintf(buf, sizeof(buf), "Host name of client \"%s\" => \"%s\" contains (at least) one invalid character at position %u",
	               ip, name, pos);
	if(ret > sizeof(buf))
		log_warn("logg_hostname_warning(): Buffer too small to hold plain message, warning truncated");

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	const int rowid = add_message(HOSTNAME_MESSAGE, ip, 2, name, (const int)pos);

	// Add to plain and HTML_messages
	cJSON *item = add_plain_message(buf, rowid, HOSTNAME_MESSAGE);
	add_html_message(item, buf);
}

void logg_fatal_dnsmasq_message(const char *message)
{
	// Create message
	size_t ret;
	char buf[2048];
	ret = snprintf(buf, sizeof(buf), "Error in dnsmasq core: %s", message);
	if(ret > sizeof(buf))
		log_warn("logg_fatal_dnsmasq_message(): Buffer too small to hold plain message, warning truncated");

	// Log to FTL.log
	log_crit("%s", buf);

	// Log to database
	const int rowid = add_message(DNSMASQ_CONFIG_MESSAGE, message, 0);

	// Add to plain message
	cJSON *item = add_plain_message(buf, rowid, DNSMASQ_CONFIG_MESSAGE);

	// Create HTML message
	ret = snprintf(buf, sizeof(buf), "FTL failed to start due to %s.", message);
	if(ret > sizeof(buf))
		log_warn("logg_fatal_dnsmasq_message(): Buffer too small to hold HTML message, warning truncated");
	add_html_message(item, buf);

	// FTL will die after this point, so we should make sure to clean up behind
	// ourselves
	cleanup(EXIT_FAILURE);
}

void logg_rate_limit_message(const char *clientIP, const unsigned int rate_limit_count)
{
	const time_t turnaround = get_rate_limit_turnaround(rate_limit_count);

	// Create message
	size_t ret;
	char buf[2048];
	ret = snprintf(buf, sizeof(buf), "Rate-limiting %s for at least %ld second%s",
	               clientIP, turnaround, turnaround == 1 ? "" : "s");
	if(ret > sizeof(buf))
		log_warn("logg_rate_limit_message(): Buffer too small to hold plain message, warning truncated");

	// Log to FTL.log
	log_info("%s", buf);

	// Log to database
	const int rowid = add_message(RATE_LIMIT_MESSAGE, clientIP, 2, config.dns.rateLimit.count.v.ui, config.dns.rateLimit.interval.v.ui);

	// Add to plain message
	cJSON *item = add_plain_message(buf, rowid, RATE_LIMIT_MESSAGE);

	// Create HTML message
	ret = snprintf(buf, sizeof(buf), "Client <code>%s</code> has been rate-limited for at least %ld second%s (current limit: %u queries per %u seconds)",
	               clientIP, turnaround, turnaround == 1 ? "" : "s", config.dns.rateLimit.count.v.ui, config.dns.rateLimit.interval.v.ui);
	if(ret > sizeof(buf))
		log_warn("logg_rate_limit_message(): Buffer too small to hold HTML message, warning truncated");
	add_html_message(item, buf);
}

void logg_warn_dnsmasq_message(char *message)
{
	// Create message
	size_t ret;
	char buf[2048];
	ret = snprintf(buf, sizeof(buf), "WARNING in dnsmasq core: %s", message);
	if(ret > sizeof(buf))
		log_warn("logg_warn_dnsmasq_message(): Buffer too small to hold plain message, warning truncated");

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	const int rowid = add_message(DNSMASQ_WARN_MESSAGE, message, 0);

	// Add to plain message
	cJSON *item = add_plain_message(buf, rowid, DNSMASQ_WARN_MESSAGE);

	// Create HTML message
	ret = snprintf(buf, sizeof(buf), "Warning in <code>dnsmasq</code> core:<pre>%s</pre>Check out <a href=\"https://docs.pi-hole.net/ftldns/dnsmasq_warn/\" target=\"_blank\">our documentation</a> for further information.", message);
	if(ret > (int)sizeof(buf))
		log_warn("logg_warn_dnsmasq_message(): Buffer too small to hold HTML message, warning truncated");
	add_html_message(item, buf);
}

void log_resource_shortage(const double load, const int nprocs, const int shmem, const int disk, const char *path, const char *msg)
{
	// Create message
	size_t ret;
	char buf[2048];

	if(load > 0.0)
	{
		ret = snprintf(buf, sizeof(buf), "Long-term load (15min avg) larger than number of processors: %.1f > %d", load, nprocs);
		if(ret > sizeof(buf))
			log_warn("log_resource_shortage(): Buffer too small to hold plain message, warning truncated");

		// Log to FTL.log
		log_warn("%s", buf);

		// Log to database
		const int rowid = add_message(LOAD_MESSAGE, "excessive load", 2, load, nprocs);

		// Add to plain message
		cJSON *item = add_plain_message(buf, rowid, LOAD_MESSAGE);

		// Create HTML message
		ret = snprintf(buf, sizeof(buf), "Long-term load (15min avg) larger than number of processors: <strong>%.1f &gt; %d</strong><br>This may slow down DNS resolution and can cause bottlenecks.", load, nprocs);
		if(ret > (int)sizeof(buf))
			log_warn("log_resource_shortage(): Buffer too small to hold HTML message, warning truncated");
		add_html_message(item, buf);
	}
	else if(shmem > -1)
	{
		ret = snprintf(buf, sizeof(buf), "RAM shortage (%s) ahead: %d%% is used (%s)", path, shmem, msg);
		if(ret > sizeof(buf))
			log_warn("log_resource_shortage(): Buffer too small to hold plain message, warning truncated");

		// Log to FTL.log
		log_warn("%s", buf);

		// Log to database
		const int rowid = add_message(SHMEM_MESSAGE, path, 2, shmem, msg);

		// Add to plain message
		cJSON *item = add_plain_message(buf, rowid, SHMEM_MESSAGE);

		// Create HTML message
		ret = snprintf(buf, sizeof(buf), "RAM shortage (<code>%s</code>) ahead: <strong>%d%%</strong> is used<br>%s", path, shmem, msg);
		if(ret > (int)sizeof(buf))
			log_warn("log_resource_shortage(): Buffer too small to hold HTML message, warning truncated");
		add_html_message(item, buf);
	}
	else if(disk > -1)
	{
		// Get filesystem details for this path
		struct mntent *fsdetails = get_filesystem_details(path);

		// Create plain message
		if(fsdetails != NULL)
			ret = snprintf(buf, sizeof(buf), "Disk shortage ahead: %d%% is used (%s) on %s filesystem mounted at %s",
			               disk, msg, fsdetails->mnt_type, fsdetails->mnt_dir);
		else
			ret = snprintf(buf, sizeof(buf), "Disk shortage ahead: %d%% is used (%s) on partition containing the file %s",
			               disk, msg, path);

		if(ret > sizeof(buf))
			log_warn("log_resource_shortage(): Buffer too small to hold plain message, warning truncated");

		// Log to FTL.log
		log_warn("%s", buf);

		// Log to database
		const int rowid = add_message(DISK_MESSAGE, path, 2, disk, msg);

		// Add to plain message
		cJSON *item = add_plain_message(buf, rowid, DISK_MESSAGE);

		// Create HTML message
		if(fsdetails != NULL)
			ret = snprintf(buf, sizeof(buf), "Disk shortage ahead: <strong>%d%%</strong> is used (%s) on %s filesystem mounted at <code>%s</code>",
			               disk, msg, fsdetails->mnt_type, fsdetails->mnt_dir);
		else
			ret = snprintf(buf, sizeof(buf), "Disk shortage ahead: <strong>%d%%</strong> is used (%s) on partition containing the file <code>%s</code>",
			               disk, msg, path);
		if(ret > (int)sizeof(buf))
			log_warn("log_resource_shortage(): Buffer too small to hold HTML message, warning truncated");

		add_html_message(item, buf);
	}
}

void logg_inaccessible_adlist(const int dbindex, const char *address)
{
	// Create message
	size_t ret;
	char buf[2048];
	ret = snprintf(buf, sizeof(buf), "Adlist with ID %d (%s) was inaccessible during last gravity run", dbindex, address);
	if(ret > sizeof(buf))
		log_warn("logg_inaccessible_adlist(): Buffer too small to hold plain message, warning truncated");

	// Log to FTL.log
	log_warn("%s", buf);

	// Log to database
	const int rowid = add_message(INACCESSIBLE_ADLIST_MESSAGE, address, 1, dbindex);

	// Add to plain message
	cJSON *item = add_plain_message(buf, rowid, INACCESSIBLE_ADLIST_MESSAGE);

	// Create HTML message
	ret = snprintf(buf, sizeof(buf), "<a href=\"groups-adlists.php?adlist=%i\">Adlist with ID <strong>%d</strong> (<code>%s</code>)</a> was inaccessible during last gravity run", dbindex, dbindex, address);
	if(ret > (int)sizeof(buf))
		log_warn("logg_inaccessible_adlist(): Buffer too small to hold HTML message, warning truncated");
	add_html_message(item, buf);
}
