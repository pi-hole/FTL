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
#include "api.h"
// struct fifologData
#include "../fifo.h"
// sysinfo()
#include <sys/sysinfo.h>
// get_blockingstatus()
#include "../setupVars.h"
// counters
#include "../shmem.h"
// get_FTL_db_filesize()
#include "../files.h"
// get_sqlite3_version()
#include "../database/common.h"
// get_number_of_queries_in_DB()
#include "../database/query-table.h"
// getgrgid()
#include <grp.h>
// config struct
#include "../config/config.h"
// struct clientsData
#include "../datastructure.h"
// uname()
#include <sys/utsname.h>
// get_cpu_percentage()
#include "../daemon.h"
// getProcessMemory()
#include "procps.h"

int api_ftl_client(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();
	// Add client's IP address
	JSON_REF_STR_IN_OBJECT(json, "remote_addr", api->request->remote_addr);

	// Add HTTP version
	JSON_REF_STR_IN_OBJECT(json, "http_version", api->request->http_version);

	// Add request method
	JSON_REF_STR_IN_OBJECT(json, "method", api->request->request_method);

	// Add HTTP headers
	cJSON *headers = JSON_NEW_ARRAY();
	for(int i = 0; i < api->request->num_headers; i++)
	{
		// Add headers
		cJSON *header = JSON_NEW_OBJECT();
		JSON_REF_STR_IN_OBJECT(header, "name", api->request->http_headers[i].name);
		JSON_REF_STR_IN_OBJECT(header, "value", api->request->http_headers[i].value);
		JSON_ADD_ITEM_TO_ARRAY(headers, header);
	}
	JSON_ADD_ITEM_TO_OBJECT(json, "headers", headers);

	JSON_SEND_OBJECT(json);
}

// fifologData is allocated in shared memory for cross-fork compatibility
fifologData *fifo_log = NULL;
int api_ftl_logs_dns(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

	unsigned int start = 0u;
	if(api->request->query_string != NULL)
	{
		// Does the user request an ID to sent from?
		unsigned int nextID;
		if(get_uint_var(api->request->query_string, "nextID", &nextID))
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
	cJSON *json = JSON_NEW_OBJECT();
	cJSON *log = JSON_NEW_ARRAY();
	for(unsigned int i = start; i < LOG_SIZE; i++)
	{
		if(fifo_log->timestamp[i] < 1.0)
		{
			// Uninitialized buffer entry
			break;
		}

		cJSON *entry = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(entry, "timestamp", fifo_log->timestamp[i]);
		JSON_REF_STR_IN_OBJECT(entry, "message", fifo_log->message[i]);
		JSON_ADD_ITEM_TO_ARRAY(log, entry);
	}
	JSON_ADD_ITEM_TO_OBJECT(json, "log", log);
	JSON_ADD_NUMBER_TO_OBJECT(json, "nextID", fifo_log->next_id);

	// Send data
	JSON_SEND_OBJECT(json);
}

int api_ftl_dbinfo(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

	cJSON *json = JSON_NEW_OBJECT();

	// Add database stat details
	struct stat st;
	get_database_stat(&st);
	JSON_ADD_NUMBER_TO_OBJECT(json, "size", st.st_size); // Total size, in bytes

	// File type
	const char *filetype;
	if((st.st_mode & S_IFMT) == S_IFREG)
		filetype = "Regular file";
	else if((st.st_mode & S_IFMT) == S_IFLNK)
		filetype = "Symbolic link";
	else
		filetype = "Unknown";
	JSON_REF_STR_IN_OBJECT(json, "type", filetype);

	// File mode
	char permissions[10] = { 0 };
	get_permission_string(permissions, &st);
	JSON_REF_STR_IN_OBJECT(json, "mode", permissions);

	JSON_ADD_NUMBER_TO_OBJECT(json, "atime", st.st_atime); // Time of last access
	JSON_ADD_NUMBER_TO_OBJECT(json, "mtime", st.st_mtime); // Time of last modification
	JSON_ADD_NUMBER_TO_OBJECT(json, "ctime", st.st_ctime); // Time of last status change (owner or mode change, etc.)

	// Get owner details
	cJSON *user = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(user, "uid", st.st_uid); // UID
	const struct passwd *pw = getpwuid(st.st_uid);
	if(pw != NULL)
	{
		JSON_COPY_STR_TO_OBJECT(user, "name", pw->pw_name); // User name
		JSON_COPY_STR_TO_OBJECT(user, "info", pw->pw_gecos); // User information
	}
	else
	{
		JSON_ADD_NULL_TO_OBJECT(user, "name");
		JSON_ADD_NULL_TO_OBJECT(user, "info");
	}

	cJSON *group = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(group, "gid", st.st_gid); // GID
	const struct group *gr = getgrgid(st.st_uid);
	if(gr != NULL)
	{
		JSON_COPY_STR_TO_OBJECT(group, "name", gr->gr_name); // Group name
	}
	else
	{
		JSON_ADD_NULL_TO_OBJECT(group, "name");
	}
	cJSON *owner = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(owner, "user", user);
	JSON_ADD_ITEM_TO_OBJECT(owner, "group", group);
	JSON_ADD_ITEM_TO_OBJECT(json, "owner", owner);

	// Add number of queries in on-disk database
	const int queries_in_database = get_number_of_queries_in_DB(NULL, "query_storage", true);
	JSON_ADD_NUMBER_TO_OBJECT(json, "queries", queries_in_database);

	// Add SQLite library version
	JSON_REF_STR_IN_OBJECT(json, "sqlite_version", get_sqlite3_version());

	// Send reply to user
	JSON_SEND_OBJECT(json);
}

static int read_temp_sensor(struct ftl_conn *api,
                            const char *label_path,
                            const char *value_path,
                            const char *short_path,
                            cJSON *object)
{
	FILE *f_label = fopen(label_path, "r");
	FILE *f_value = fopen(value_path, "r");
	if(f_value != NULL)
	{
		int raw_temp = 0;
		char label[1024];
		if(fscanf(f_value, "%d", &raw_temp) == 1)
		{
			cJSON *item = JSON_NEW_OBJECT();
			if(f_label && fgets(label, sizeof(label)-1, f_label))
			{
				// Remove newline if present
				char *p = strchr(label, '\n');
				if (p != NULL) *p = '\0';
				JSON_COPY_STR_TO_OBJECT(item, "name", label);
			}
			else
			{
				JSON_ADD_NULL_TO_OBJECT(item, "name");
			}
			JSON_COPY_STR_TO_OBJECT(item, "path", short_path);

			// Compute actual temperature
			double temp = raw_temp < 1000 ? raw_temp : 1e-3*raw_temp;
			const char *unit = "C";
			if(config.misc.temp.unit.v.s[0] == 'F')
			{
				temp = 1.8*temp + 32; // Convert °Celsius to °Fahrenheit
				unit = "F";
			}
			else if(config.misc.temp.unit.v.s[0] == 'K')
			{
				temp += 273.15; // Convert °Celsius to Kelvin
				unit = "K";
			}
			JSON_ADD_NUMBER_TO_OBJECT(item, "value", temp);
			JSON_ADD_NUMBER_TO_OBJECT(item, "hot_limit", config.misc.temp.limit.v.d);
			JSON_REF_STR_IN_OBJECT(item, "unit", unit);
			JSON_ADD_ITEM_TO_ARRAY(object, item);
		}
	}
	if(f_label != NULL)
		fclose(f_label);
	if(f_value != NULL)
		fclose(f_value);

	return 0;
}

int get_system_obj(struct ftl_conn *api, cJSON *system)
{
	const int nprocs = get_nprocs();
	struct sysinfo info;
	if(sysinfo(&info) != 0)
		return send_json_error(api, 500, "error", strerror(errno), NULL);

	// Seconds since boot
	JSON_ADD_NUMBER_TO_OBJECT(system, "uptime", info.uptime);

	cJSON *memory = JSON_NEW_OBJECT();
	cJSON *ram = JSON_NEW_OBJECT();
	// We cannot use the memory information available through sysinfo() as
	// this is not what we want. It is worth noting that freeram in sysinfo
	// is not what most people would call "free RAM". freeram excludes
	// memory used by cached filesystem metadata ("buffers") and contents
	// ("cache"). Both of these can be a significant portion of RAM but are
	// freed by the OS when programs need that memory. sysinfo does contain
	// size used by buffers (sysinfo.bufferram), but not cache. The best
	// option is to use the MemAvailable (as opposed to MemFree) entry in
	// /proc/meminfo instead.
	struct proc_meminfo mem = { 0 };
	parse_proc_meminfo(&mem);
	// Total usable main memory size
	JSON_ADD_NUMBER_TO_OBJECT(ram, "total", mem.total);
	// Free memory size
	JSON_ADD_NUMBER_TO_OBJECT(ram, "free", mem.mfree);
	// Used memory size
	JSON_ADD_NUMBER_TO_OBJECT(ram, "used", mem.used);
	// Available memory size
	// See https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773
	// This Linux kernel commit message explains there are more nuances. It
	// says: "Many programs check /proc/meminfo to estimate how much free
	// memory is available. They generally do this by adding up "free" and
	// "cached", which was fine ten years ago, but is pretty much guaranteed
	// to be wrong today."
	JSON_ADD_NUMBER_TO_OBJECT(ram, "available", mem.avail);
	JSON_ADD_ITEM_TO_OBJECT(memory, "ram", ram);

	cJSON *swap = JSON_NEW_OBJECT();
	// Total swap space size
	JSON_ADD_NUMBER_TO_OBJECT(swap, "total", info.totalswap * info.mem_unit);
	// Swap space still available
	JSON_ADD_NUMBER_TO_OBJECT(swap, "free", info.freeswap * info.mem_unit);
	// Used swap space
	JSON_ADD_NUMBER_TO_OBJECT(swap, "used", (info.totalswap - info.freeswap) * info.mem_unit);
	JSON_ADD_ITEM_TO_OBJECT(memory, "swap", swap);
	JSON_ADD_ITEM_TO_OBJECT(system, "memory", memory);

	// Number of current processes
	JSON_ADD_NUMBER_TO_OBJECT(system, "procs", info.procs);

	cJSON *cpu = JSON_NEW_OBJECT();
	// Number of available processors
	JSON_ADD_NUMBER_TO_OBJECT(cpu, "nprocs", nprocs);

	// 1, 5, and 15 minute load averages (we need to convert them)
	cJSON *raw = JSON_NEW_ARRAY();
	cJSON *percent = JSON_NEW_ARRAY();
	float load_f[3] = { 0.f };
	const float longfloat = 1.f / (1 << SI_LOAD_SHIFT);
	for(unsigned int i = 0; i < 3; i++)
	{
		load_f[i] = longfloat * info.loads[i];
		JSON_ADD_NUMBER_TO_ARRAY(raw, load_f[i]);
		JSON_ADD_NUMBER_TO_ARRAY(percent, (100.f*load_f[i]/nprocs));
	}

	// Averaged CPU usage in percent
	cJSON *load = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(load, "raw", raw);
	JSON_ADD_ITEM_TO_OBJECT(load, "percent", percent);
	JSON_ADD_ITEM_TO_OBJECT(cpu, "load", load);
	JSON_ADD_ITEM_TO_OBJECT(system, "cpu", cpu);

	// Source available temperatures, we try to read as many
	// temperature sensors as there are cores on this system
	cJSON *sensors = JSON_NEW_ARRAY();
	char label_path[256], value_path[256], fallback_label[64];
	int ret;
	for(int i = 0; i < nprocs; i++)
	{
		// Try /sys/class/thermal/thermal_zoneX/{type,temp}
		sprintf(label_path, "/sys/class/thermal/thermal_zone%d/type", i);
		sprintf(value_path, "/sys/class/thermal/thermal_zone%d/temp", i);
		sprintf(fallback_label, "thermal_zone%d/temp", i);
		ret = read_temp_sensor(api, label_path, value_path, fallback_label, sensors);
		// Error handling
		if(ret != 0)
			return ret;

		// Try /sys/class/hwmon/hwmon0X/tempX_{label,input}
		sprintf(label_path, "/sys/class/hwmon/hwmon0/temp%d_label", i);
		sprintf(value_path, "/sys/class/hwmon/hwmon0/temp%d_input", i);
		sprintf(fallback_label, "hwmon0/temp%d", i);
		ret = read_temp_sensor(api, label_path, value_path, fallback_label, sensors);
		// Error handling
		if(ret != 0)
			return ret;
	}
	JSON_ADD_ITEM_TO_OBJECT(system, "sensors", sensors);

	// Try to obtain device model
	FILE *f_model = fopen("/sys/firmware/devicetree/base/model", "r");
	char model[1024] = { 0 };
	if(f_model && fgets(model, sizeof(model)-1, f_model))
	{
		// Remove newline if present
		char *p = strchr(model, '\n');
		if (p != NULL) *p = '\0';
		JSON_COPY_STR_TO_OBJECT(system, "model", model);
	}
	else
	{
		JSON_ADD_NULL_TO_OBJECT(system, "model");
	}
	if(f_model)
		fclose(f_model);

	// Add hostname to system object
	char hostname[256] = { 0 };
	if(gethostname(hostname, sizeof(hostname)) != 0)
	{
		log_warn("gethostname() failed: %s", strerror(errno));
		JSON_ADD_NULL_TO_OBJECT(system, "hostname");
	}
	else
		JSON_COPY_STR_TO_OBJECT(system, "hostname", hostname);

	cJSON *dns = JSON_NEW_OBJECT();
	const bool blocking = get_blockingstatus();
	JSON_ADD_BOOL_TO_OBJECT(dns, "blocking", blocking); // same reply type as in /api/dns/status
	JSON_ADD_ITEM_TO_OBJECT(system, "dns", dns);

	cJSON *uname_ = JSON_NEW_OBJECT();
	struct utsname un = { 0 };
	uname(&un);
	JSON_COPY_STR_TO_OBJECT(uname_, "domainname", un.domainname);
	JSON_COPY_STR_TO_OBJECT(uname_, "machine", un.machine);
	JSON_COPY_STR_TO_OBJECT(uname_, "nodename", un.nodename);
	JSON_COPY_STR_TO_OBJECT(uname_, "release", un.release);
	JSON_COPY_STR_TO_OBJECT(uname_, "sysname", un.sysname);
	JSON_COPY_STR_TO_OBJECT(uname_, "version", un.version);
	JSON_ADD_ITEM_TO_OBJECT(system, "uname", uname_);

	return 0;
}

int get_ftl_obj(struct ftl_conn *api, cJSON *ftl, const bool is_locked)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

	cJSON *database = JSON_NEW_OBJECT();

	// Source from shared objects within lock
	if(!is_locked)
		lock_shm();
	const int db_gravity = counters->database.gravity;
	const int db_groups = counters->database.groups;
	const int db_lists = counters->database.lists;
	const int db_clients = counters->database.clients;
	const int db_allowed = counters->database.domains.allowed;
	const int db_denied = counters->database.domains.denied;
	const int clients_total = counters->clients;
	const int privacylevel = config.misc.privacylevel.v.privacy_level;

	// unique_clients: count only clients that have been active within the most recent 24 hours
	int activeclients = 0;
	for(int clientID=0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);
		if(client == NULL)
			continue;

		if(client->count > 0)
			activeclients++;
	}
	if(!is_locked)
		unlock_shm();

	JSON_ADD_NUMBER_TO_OBJECT(database, "gravity", db_gravity);
	JSON_ADD_NUMBER_TO_OBJECT(database, "groups", db_groups);
	JSON_ADD_NUMBER_TO_OBJECT(database, "lists", db_lists);
	JSON_ADD_NUMBER_TO_OBJECT(database, "clients", db_clients);

	cJSON *domains = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(domains, "allowed", db_allowed);
	JSON_ADD_NUMBER_TO_OBJECT(domains, "denied", db_denied);
	JSON_ADD_ITEM_TO_OBJECT(database, "domains", domains);
	JSON_ADD_ITEM_TO_OBJECT(ftl, "database", database);

	JSON_ADD_NUMBER_TO_OBJECT(ftl, "privacy_level", privacylevel);

	cJSON *clients = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(clients, "total",clients_total);
	JSON_ADD_NUMBER_TO_OBJECT(clients, "active", activeclients);
	JSON_ADD_ITEM_TO_OBJECT(ftl, "clients", clients);

	JSON_ADD_NUMBER_TO_OBJECT(ftl, "pid", getpid());

	struct proc_mem pmem = { 0 };
	struct proc_meminfo mem = { 0 };
	parse_proc_meminfo(&mem);
	getProcessMemory(&pmem, mem.total);
	JSON_ADD_NUMBER_TO_OBJECT(ftl, "%mem", pmem.VmRSS_percent);
	JSON_ADD_NUMBER_TO_OBJECT(ftl, "%cpu", get_cpu_percentage());

	return 0;
}

int api_ftl_sysinfo(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
		return send_json_unauthorized(api);

	cJSON *json = JSON_NEW_OBJECT();

	// Get system object
	cJSON *system = JSON_NEW_OBJECT();
	int ret = get_system_obj(api, system);
	if (ret != 0)
		return ret;

	JSON_ADD_ITEM_TO_OBJECT(json, "system", system);

	// Get FTL object
	cJSON *ftl = JSON_NEW_OBJECT();
	ret = get_ftl_obj(api, ftl, false);
	if(ret != 0)
		return ret;

	JSON_ADD_ITEM_TO_OBJECT(json, "ftl", ftl);
	JSON_SEND_OBJECT(json);
}
