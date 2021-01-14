/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/ftl
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../webserver/http-common.h"
#include "../webserver/json_macros.h"
#include "routes.h"
// struct fifologData
#include "../fifo.h"
// get_FTL_db_filesize()
#include "files.h"
// get_sqlite3_version()
#include "database/common.h"
// get_number_of_queries_in_DB()
#include "database/query-table.h"
// getgrgid()
#include <grp.h>
// sysinfo()
#include <sys/sysinfo.h>

int api_ftl_client(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();
	const struct mg_request_info *request = mg_get_request_info(conn);

	// Add client's IP address
	JSON_OBJ_REF_STR(json, "remote_addr", request->remote_addr);

	// Add HTTP version
	JSON_OBJ_REF_STR(json, "http_version", request->http_version);

	// Add request method
	JSON_OBJ_REF_STR(json, "method", request->request_method);

	// Add HTTP headers
	cJSON *headers = JSON_NEW_ARRAY();
	for(int i = 0; i < request->num_headers; i++)
	{
		// Add headers
		cJSON *header = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(header, "name", request->http_headers[i].name);
		JSON_OBJ_REF_STR(header, "value", request->http_headers[i].value);
		JSON_ARRAY_ADD_ITEM(headers, header);
	}
	JSON_OBJ_ADD_ITEM(json, "headers", headers);

	JSON_SEND_OBJECT(json);
}

// fifologData is allocated in shared memory for cross-fork compatibility
fifologData *fifo_log = NULL;
int api_ftl_dnsmasq_log(struct mg_connection *conn)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(conn) < 0)
	{
		return send_json_unauthorized(conn);
	}

	unsigned int start = 0u;
	const struct mg_request_info *request = mg_get_request_info(conn);
	if(request->query_string != NULL)
	{
		// Does the user request an ID to sent from?
		unsigned int nextID;
		if(get_uint_var(request->query_string, "nextID", &nextID))
		{
			if(nextID >= fifo_log->next_id)
			{
				// Do not return any data
				start = LOG_SIZE;
			}
			else if((fifo_log->next_id > LOG_SIZE) && nextID < (fifo_log->next_id) - LOG_SIZE)
			{
				// Requested an ID smaller than the lowest one we have
				// We return the entire buffer
				start = 0u;
			}
			else if(fifo_log->next_id >= LOG_SIZE)
			{
				// Reply with partial buffer, measure from the end
				// (the log is full)
				start = LOG_SIZE - (fifo_log->next_id - nextID);
			}
			else
			{
				// Reply with partial buffer, measure from the start
				// (the log is not yet full)
				start = nextID;
			}
		}
	}

	// Process data
	cJSON *json = JSON_NEW_OBJ();
	cJSON *log = JSON_NEW_ARRAY();
	for(unsigned int i = start; i < LOG_SIZE; i++)
	{
		if(fifo_log->timestamp[i] == 0)
		{
			// Uninitialized buffer entry
			break;
		}

		cJSON *entry = JSON_NEW_OBJ();
		JSON_OBJ_ADD_NUMBER(entry, "timestamp", fifo_log->timestamp[i]);
		JSON_OBJ_REF_STR(entry, "message", fifo_log->message[i]);
		JSON_ARRAY_ADD_ITEM(log, entry);
	}
	JSON_OBJ_ADD_ITEM(json, "log", log);
	JSON_OBJ_ADD_NUMBER(json, "nextID", fifo_log->next_id);

	// Send data
	JSON_SEND_OBJECT(json);
}

int api_ftl_database(struct mg_connection *conn)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(conn) < 0)
	{
		send_json_unauthorized(conn);
	}

	cJSON *json = JSON_NEW_OBJ();

	// Add database stat details
	struct stat st;
	get_database_stat(&st);
	JSON_OBJ_ADD_NUMBER(json, "size", st.st_size); // Total size, in bytes

	// File type
	char octal[5] = { 0 };
	const char *human;
	cJSON *type = JSON_NEW_OBJ();
	snprintf(octal, sizeof(octal), "%04o", (st.st_mode & S_IFMT) >> 9);
	JSON_OBJ_COPY_STR(type, "octal", octal);
	if((st.st_mode & S_IFMT) == S_IFREG)
		human = "Regular file";
	else if((st.st_mode & S_IFMT) == S_IFLNK)
		human = "Symbolic link";
	else
		human = "Unknown";
	JSON_OBJ_REF_STR(type, "human", human);
	JSON_OBJ_ADD_ITEM(json, "type", type);

	// File mode
	cJSON *mode = JSON_NEW_OBJ();
	snprintf(octal, sizeof(octal), "%03o", st.st_mode & 0x1FF);
	JSON_OBJ_COPY_STR(mode, "octal", octal);
	char permissions[10] = { 0 };
	get_permission_string(permissions, &st);
	JSON_OBJ_REF_STR(mode, "human", permissions);
	JSON_OBJ_ADD_ITEM(json, "mode", mode);

	JSON_OBJ_ADD_NUMBER(json, "atime", st.st_atime); // Time of last access
	JSON_OBJ_ADD_NUMBER(json, "mtime", st.st_mtime); // Time of last modification
	JSON_OBJ_ADD_NUMBER(json, "ctime", st.st_ctime); // Time of last status change (owner or mode change, etc.)

	// Get owner details
	cJSON *user = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(user, "uid", st.st_uid); // UID
	const struct passwd *pw = getpwuid(st.st_uid);
	if(pw != NULL)
	{
		JSON_OBJ_COPY_STR(user, "name", pw->pw_name); // User name
		JSON_OBJ_COPY_STR(user, "info", pw->pw_gecos); // User information
	}
	cJSON *group = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(group, "gid", st.st_gid); // GID
	const struct group *gr = getgrgid(st.st_uid);
	if(gr != NULL)
	{
		JSON_OBJ_COPY_STR(group, "name", gr->gr_name); // Group name
	}
	cJSON *owner = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(owner, "user", user);
	JSON_OBJ_ADD_ITEM(owner, "group", group);
	JSON_OBJ_ADD_ITEM(json, "owner", owner);

	// Add number of queries in database
	const int queries_in_database = get_number_of_queries_in_DB();
	JSON_OBJ_ADD_NUMBER(json, "queries", queries_in_database);

	// Add SQLite library version
	JSON_OBJ_REF_STR(json, "sqlite_version", get_sqlite3_version());

	// Send reply to user
	JSON_SEND_OBJECT(json);
}

int api_ftl_system(struct mg_connection *conn)
{
	cJSON *json = JSON_NEW_OBJ();

	const int nprocs = get_nprocs();
	struct sysinfo info;
	if(sysinfo(&info) != 0)
		return send_json_error(conn, 500, "error", strerror(errno), NULL);

	// Seconds since boot
	JSON_OBJ_ADD_NUMBER(json, "uptime", info.uptime);

	cJSON *ram = JSON_NEW_OBJ();
	// Total usable main memory size
	JSON_OBJ_ADD_NUMBER(ram, "total", info.totalram * info.mem_unit);
	// Available memory size
	JSON_OBJ_ADD_NUMBER(ram, "free", info.freeram * info.mem_unit);
	// Amount of shared memory
	JSON_OBJ_ADD_NUMBER(ram, "shared", info.sharedram * info.mem_unit);
	// Memory used by buffers
	JSON_OBJ_ADD_NUMBER(ram, "buffer", info.bufferram * info.mem_unit);
	unsigned long used = info.totalram - info.freeram;
	// The following is a fall-back from procps code for lxc containers
	// messing around with memory information
	if(info.sharedram + info.bufferram < used)
		used -= info.sharedram + info.bufferram;
	JSON_OBJ_ADD_NUMBER(ram, "used", used * info.mem_unit);

	cJSON *swap = JSON_NEW_OBJ();
	// Total swap space size
	JSON_OBJ_ADD_NUMBER(swap, "total", info.totalswap * info.mem_unit);
	// Swap space still available
	JSON_OBJ_ADD_NUMBER(swap, "free", info.freeswap * info.mem_unit);

	cJSON *high = JSON_NEW_OBJ();
	// Total high memory size
	JSON_OBJ_ADD_NUMBER(high, "total", info.totalhigh * info.mem_unit);
	// High memory still available
	JSON_OBJ_ADD_NUMBER(high, "free", info.freehigh * info.mem_unit);

	cJSON *memory = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(memory, "ram", ram);
	JSON_OBJ_ADD_ITEM(memory, "swap", swap);
	JSON_OBJ_ADD_ITEM(memory, "high", high);
	JSON_OBJ_ADD_ITEM(json, "memory", memory);

	// Number of current processes
	JSON_OBJ_ADD_NUMBER(json, "procs", info.procs);

	cJSON *cpu = JSON_NEW_OBJ();
	// Number of available processors
	JSON_OBJ_ADD_NUMBER(cpu, "nprocs", nprocs);

	// 1, 5, and 15 minute load averages (we need to convert them)
	cJSON *load = JSON_NEW_ARRAY();
	cJSON *percent = JSON_NEW_ARRAY();
	float load_f[3] = { 0.f };
	const float longfloat = 1.f / (1 << SI_LOAD_SHIFT);
	for(unsigned int i = 0; i < 3; i++)
	{
		load_f[i] = longfloat * info.loads[i];
		JSON_ARRAY_ADD_NUMBER(load, load_f[i]);
		JSON_ARRAY_ADD_NUMBER(percent, (100.f*load_f[i]/nprocs));
	}

	// Averaged CPU usage in percent
	JSON_OBJ_ADD_ITEM(cpu, "load", load);
	JSON_OBJ_ADD_ITEM(cpu, "percent", percent);
	JSON_OBJ_ADD_ITEM(json, "cpu", cpu);

	// Source available temperatures
	cJSON *sensors = JSON_NEW_ARRAY();
	char buffer[256];
	for(int i = 0; i < nprocs; i++)
	{
		FILE *f_label = NULL, *f_value = NULL;
		// Try /sys/class/thermal/thermal_zoneX/{type,temp}
		sprintf(buffer, "/sys/class/thermal/thermal_zone%d/type", i);
		f_label = fopen(buffer, "r");
		sprintf(buffer, "/sys/class/thermal/thermal_zone%d/temp", i);
		f_value = fopen(buffer, "r");
		if(f_label != NULL && f_value != NULL)
		{
			int temp = 0;
			char label[1024];
			if(fread(label, sizeof(label)-1, 1, f_label) > 0 && fscanf(f_value, "%d", &temp) == 1)
			{
				cJSON *item = JSON_NEW_OBJ();
				JSON_OBJ_COPY_STR(item, "label", label);
				JSON_OBJ_ADD_NUMBER(item, "value", temp < 1000 ? temp : 1e-3f*temp);
				JSON_ARRAY_ADD_ITEM(sensors, item);
			}
		}
		if(f_label != NULL)
			fclose(f_label);
		if(f_value != NULL)
			fclose(f_value);

		// Try /sys/class/hwmon/hwmon0X/tempX_{label,input}
		sprintf(buffer, "/sys/class/hwmon/hwmon0/temp%d_label", i);
		f_label = fopen(buffer, "r");
		sprintf(buffer, "/sys/class/hwmon/hwmon0/temp%d_input", i);
		f_value = fopen(buffer, "r");
		if(f_label != NULL && f_value != NULL)
		{
			int temp = 0;
			char label[1024];
			if(fread(label, sizeof(label)-1, 1, f_label) > 0 && fscanf(f_value, "%d", &temp) == 1)
			{
				cJSON *item = JSON_NEW_OBJ();
				JSON_OBJ_COPY_STR(item, "label", label);
				JSON_OBJ_ADD_NUMBER(item, "value", temp < 1000 ? temp : 1e-3f*temp);
				JSON_ARRAY_ADD_ITEM(sensors, item);
			}
		}
		if(f_label != NULL)
			fclose(f_label);
		if(f_value != NULL)
			fclose(f_value);
	}
	JSON_OBJ_ADD_ITEM(json, "sensors", sensors);
	
	JSON_SEND_OBJECT(json);
}
