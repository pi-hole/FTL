/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/ftl
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"
// sysinfo()
#include <sys/sysinfo.h>
// get_blockingstatus()
#include "setupVars.h"
// counters
#include "shmem.h"
// get_FTL_db_filesize()
#include "files.h"
// get_sqlite3_version()
#include "database/common.h"
// get_number_of_queries_in_DB()
#include "database/query-table.h"
// getgrgid()
#include <grp.h>
// config struct
#include "config/config.h"
// struct clientsData
#include "datastructure.h"
// uname()
#include <sys/utsname.h>
// get_cpu_percentage()
#include "daemon.h"
// getProcessMemory()
#include "procps.h"

// get_FTL_version()
#include "log.h"
#include "version.h"
// prase_line()
#include "files.h"

// get_messages()
#include "database/message-table.h"
// LONG_MIN, LONG_MAX
#include <limits.h>

// getCacheInformation()
#include "cache_info.h"

// glob_t
#include <glob.h>

#define VERSIONS_FILE "/etc/pihole/versions"

int api_info_client(struct ftl_conn *api)
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

int api_info_database(struct ftl_conn *api)
{
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

static int get_system_obj(struct ftl_conn *api, cJSON *system)
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
	JSON_ADD_NUMBER_TO_OBJECT(ram, "%used", 100.0*mem.used/mem.total);
	JSON_ADD_ITEM_TO_OBJECT(memory, "ram", ram);

	cJSON *swap = JSON_NEW_OBJECT();
	// Total swap space size
	const float total_swap = info.totalswap * info.mem_unit / 1024;
	JSON_ADD_NUMBER_TO_OBJECT(swap, "total", total_swap);
	// Swap space still available
	JSON_ADD_NUMBER_TO_OBJECT(swap, "free", info.freeswap * info.mem_unit / 1024);
	// Used swap space
	const float used_swap = (info.totalswap - info.freeswap) * info.mem_unit / 1024;
	JSON_ADD_NUMBER_TO_OBJECT(swap, "used", used_swap);
	JSON_ADD_NUMBER_TO_OBJECT(swap, "%used", 100.0*used_swap/total_swap);
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
	const float f_load = 1.f / (1 << SI_LOAD_SHIFT);
	for(unsigned int i = 0; i < 3; i++)
	{
		load_f[i] = f_load * info.loads[i];
		JSON_ADD_NUMBER_TO_ARRAY(raw, load_f[i]);
		JSON_ADD_NUMBER_TO_ARRAY(percent, (100.f*load_f[i]/nprocs));
	}

	// Averaged CPU usage in percent
	cJSON *load = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(load, "raw", raw);
	JSON_ADD_ITEM_TO_OBJECT(load, "percent", percent);
	JSON_ADD_ITEM_TO_OBJECT(cpu, "load", load);
	JSON_ADD_ITEM_TO_OBJECT(system, "cpu", cpu);

	// All okay
	return 0;
}

static int read_temp_sensor(struct ftl_conn *api,
                            const char *label_path,
                            const char *value_path,
                            const char *short_path,
                            cJSON *object)
{
	// Check if sensor is available
	if(file_exists(value_path) == false)
		return 0;

	// Open files
	FILE *f_value = fopen(value_path, "r");
	if(f_value != NULL)
	{
		int raw_temp = 0;
		char label[1024];
		if(fscanf(f_value, "%d", &raw_temp) == 1)
		{
			FILE *f_label = NULL;
			if(file_exists(label_path))
				f_label = fopen(label_path, "r");

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

			if(f_label != NULL)
				fclose(f_label);

			// Compute actual temperature, many sensors give their values in milli °Celsius
			// see, e.g., https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-thermal
			double temp = raw_temp < 1000 ? raw_temp : 1e-3*raw_temp;
			if(config.webserver.api.temp.unit.v.s[0] == 'F')
				temp = 1.8*temp + 32; // Convert °Celsius to °Fahrenheit
			else if(config.webserver.api.temp.unit.v.s[0] == 'K')
				temp += 273.15; // Convert °Celsius to Kelvin
			JSON_ADD_NUMBER_TO_OBJECT(item, "value", temp);
			JSON_ADD_ITEM_TO_ARRAY(object, item);
		}
	}
	if(f_value != NULL)
		fclose(f_value);

	// All okay
	return 0;
}

// Get the temperature from sensor files using a glob pattern
static int sensor_temp_from_glob(struct ftl_conn *api, cJSON *sensors, const char *globstr, const char *item_string, const char *label_string)
{
	glob_t globbuf = { 0 };
	int ret = glob(globstr, 0, NULL, &globbuf);
	if(ret != 0)
		return 0;

	// Iterate over all files matching the glob
	for(size_t i = 0; i < globbuf.gl_pathc; i++)
	{
		char *value_path = globbuf.gl_pathv[i];
		char *label_path = NULL;

		// Replace <item> with <label> if we have a label (label_string != NULL)
		if(label_string != NULL)
		{
			label_path = strdup(value_path);
			if(label_path == NULL)
				return -1;
			char *p = strstr(label_path, item_string);
			if(p == NULL)
			{
				free(label_path);
				continue;
			}
			strcpy(p, label_string);
		}

		// Read the sensor
		ret = read_temp_sensor(api, label_path, value_path, value_path, sensors);
		if(label_path != NULL)
			free(label_path);
		if(ret != 0)
			return ret;
	}

	// Free the glob buffer
	globfree(&globbuf);

	// All okay
	return 0;
}

static int get_sensors_arr(struct ftl_conn *api, cJSON *sensors)
{
	int ret;
	// Source available temperatures, we try to read temperature sensors from
	// different locations. We try to read the sensor label from the label file
	// and the sensor value from the value file. If the label file does not
	// exist, we use the value file as label.

	// Thermal zone sensors
	// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-thermal
	ret = sensor_temp_from_glob(api, sensors, "/sys/class/thermal/thermal_zone*/temp", "type", "temp");
	if(ret != 0)
		return ret;

	// Hwmon sensors
	// https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-hwmon
	ret = sensor_temp_from_glob(api, sensors, "/sys/class/hwmon/hwmon*/temp*_input", "input", "label");
	if(ret != 0)
		return ret;

	// Intel core temperature sensors
	// see https://github.com/pi-hole/AdminLTE/issues/2520
	// documentation: https://www.kernel.org/doc/html/latest/hwmon/coretemp.html
	// but see also here: https://github.com/torvalds/linux/blob/fae30e3/drivers/hwmon/coretemp.c#L505-L510
	ret = sensor_temp_from_glob(api, sensors, "/sys/devices/platform/coretemp.*/hwmon/hwmon*/temp*_input", "input", "label");
	if(ret != 0)
		return ret;

	// All okay
	return 0;
}

static cJSON *read_sys_property(const char *path)
{
	if(!file_exists(path))
		return cJSON_CreateNull();

	FILE *fp = fopen(path, "r");
	if(fp == NULL)
		return cJSON_CreateNull();

	char buf[256];
	if(fgets(buf, sizeof(buf), fp) == NULL)
	{
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	// Remove newline if present
	char *p = strchr(buf, '\n');
	if (p != NULL) *p = '\0';
	return cJSON_CreateString(buf);
}

static int get_host_obj(struct ftl_conn *api, cJSON *host)
{
	cJSON *uname_ = JSON_NEW_OBJECT();
	struct utsname un = { 0 };
	uname(&un);
	JSON_COPY_STR_TO_OBJECT(uname_, "domainname", un.domainname);
	JSON_COPY_STR_TO_OBJECT(uname_, "machine", un.machine);
	JSON_COPY_STR_TO_OBJECT(uname_, "nodename", un.nodename);
	JSON_COPY_STR_TO_OBJECT(uname_, "release", un.release);
	JSON_COPY_STR_TO_OBJECT(uname_, "sysname", un.sysname);
	JSON_COPY_STR_TO_OBJECT(uname_, "version", un.version);
	JSON_ADD_ITEM_TO_OBJECT(host, "uname", uname_);

	JSON_ADD_ITEM_TO_OBJECT(host, "model", read_sys_property("/sys/firmware/devicetree/base/model"));

	cJSON *dmi = JSON_NEW_OBJECT();
	cJSON *bios = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(bios, "vendor", read_sys_property("/sys/devices/virtual/dmi/id/bios_vendor"));

	cJSON *board = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(board, "name", read_sys_property("/sys/devices/virtual/dmi/id/board_name"));
	JSON_ADD_ITEM_TO_OBJECT(board, "vendor", read_sys_property("/sys/devices/virtual/dmi/id/board_vendor"));
	JSON_ADD_ITEM_TO_OBJECT(board, "version", read_sys_property("/sys/devices/virtual/dmi/id/board_version"));

	cJSON *product = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(product, "name", read_sys_property("/sys/devices/virtual/dmi/id/product_name"));
	JSON_ADD_ITEM_TO_OBJECT(product, "family", read_sys_property("/sys/devices/virtual/dmi/id/product_family"));
	JSON_ADD_ITEM_TO_OBJECT(product, "version", read_sys_property("/sys/devices/virtual/dmi/id/product_version"));

	cJSON *sys = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(sys, "vendor", read_sys_property("/sys/devices/virtual/dmi/id/sys_vendor"));

	JSON_ADD_ITEM_TO_OBJECT(dmi, "bios", bios);
	JSON_ADD_ITEM_TO_OBJECT(dmi, "board", board);
	JSON_ADD_ITEM_TO_OBJECT(dmi, "product", product);
	JSON_ADD_ITEM_TO_OBJECT(dmi, "sys", sys);
	JSON_ADD_ITEM_TO_OBJECT(host, "dmi", dmi);

	// All okay
	return 0;
}

static int get_ftl_obj(struct ftl_conn *api, cJSON *ftl)
{
	cJSON *database = JSON_NEW_OBJECT();

	// Source from shared objects within lock
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

	// All okay
	return 0;
}

int api_info_system(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();

	// Get system object
	cJSON *system = JSON_NEW_OBJECT();
	int ret = get_system_obj(api, system);
	if (ret != 0)
		return ret;

	JSON_ADD_ITEM_TO_OBJECT(json, "system", system);
	JSON_SEND_OBJECT(json);
}

int api_info_ftl(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();

	// Get ftl object
	cJSON *ftl = JSON_NEW_OBJECT();
	int ret = get_ftl_obj(api, ftl);
	if (ret != 0)
		return ret;

	JSON_ADD_ITEM_TO_OBJECT(json, "ftl", ftl);
	JSON_SEND_OBJECT(json);
}

int api_info_host(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();

	// Get host object
	cJSON *host = JSON_NEW_OBJECT();
	int ret = get_host_obj(api, host);
	if (ret != 0)
		return ret;

	JSON_ADD_ITEM_TO_OBJECT(json, "host", host);
	JSON_SEND_OBJECT(json);
}

int api_info_sensors(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJECT();

	// Get sensors array
	cJSON *sensors = JSON_NEW_ARRAY();
	int ret = get_sensors_arr(api, sensors);
	if (ret != 0)
		return ret;
	JSON_ADD_ITEM_TO_OBJECT(json, "sensors", sensors);

	// Add hot limit
	JSON_ADD_NUMBER_TO_OBJECT(json, "hot_limit", config.webserver.api.temp.limit.v.d);

	// Add unit
	const char *unit = "C";
	if(config.webserver.api.temp.unit.v.s[0] == 'F')
		unit = "F";
	else if(config.webserver.api.temp.unit.v.s[0] == 'K')
		unit = "K";
	JSON_REF_STR_IN_OBJECT(json, "unit", unit);

	JSON_SEND_OBJECT(json);
}

int api_info_version(struct ftl_conn *api)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	char *key, *value;
	cJSON *core_local = JSON_NEW_OBJECT();
	cJSON *web_local = JSON_NEW_OBJECT();
	cJSON *ftl_local = JSON_NEW_OBJECT();
	cJSON *core_remote = JSON_NEW_OBJECT();
	cJSON *web_remote = JSON_NEW_OBJECT();
	cJSON *ftl_remote = JSON_NEW_OBJECT();
	cJSON *docker = JSON_NEW_OBJECT();

	FILE *fp = fopen(VERSIONS_FILE, "r");
	if(!fp)
		return send_json_error(api, 500,
		                       "internal_error",
		                       "Failed to read " VERSIONS_FILE,
		                       NULL);

	// Loop over KEY=VALUE parts in the versions file
	while((read = getline(&line, &len, fp)) != -1)
	{
		if (parse_line(line, &key, &value))
			continue;

		if(strcmp(key, "CORE_BRANCH") == 0)
			JSON_COPY_STR_TO_OBJECT(core_local, "branch", value);
		else if(strcmp(key, "WEB_BRANCH") == 0)
			JSON_COPY_STR_TO_OBJECT(web_local, "branch", value);
		// Added below from the running FTL binary itself
		//else if(strcmp(key, "FTL_BRANCH") == 0)
		//	JSON_COPY_STR_TO_OBJECT(ftl_local, "branch", value);
		else if(strcmp(key, "CORE_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(core_local, "version", value);
		else if(strcmp(key, "WEB_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(web_local, "version", value);
		// Added below from the running FTL binary itself
		//else if(strcmp(key, "FTL_VERSION") == 0)
		//	JSON_COPY_STR_TO_OBJECT(ftl_local, "version", value);
		else if(strcmp(key, "GITHUB_CORE_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(core_remote, "version", value);
		else if(strcmp(key, "GITHUB_WEB_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(web_remote, "version", value);
		else if(strcmp(key, "GITHUB_FTL_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(ftl_remote, "version", value);
		else if(strcmp(key, "CORE_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(core_local, "hash", value);
		else if(strcmp(key, "WEB_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(web_local, "hash", value);
		else if(strcmp(key, "FTL_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(ftl_local, "hash", value);
		else if(strcmp(key, "GITHUB_CORE_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(core_remote, "hash", value);
		else if(strcmp(key, "GITHUB_WEB_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(web_remote, "hash", value);
		else if(strcmp(key, "GITHUB_FTL_HASH") == 0)
			JSON_COPY_STR_TO_OBJECT(ftl_remote, "hash", value);
		else if(strcmp(key, "DOCKER_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(docker, "local", value);
		else if(strcmp(key, "GITHUB_DOCKER_VERSION") == 0)
			JSON_COPY_STR_TO_OBJECT(docker, "remote", value);
	}

	// Free allocated memory and release file pointer
	free(line);
	fclose(fp);

	// Add remaining properties to ftl object
	JSON_REF_STR_IN_OBJECT(ftl_local, "branch", GIT_BRANCH);
	JSON_REF_STR_IN_OBJECT(ftl_local, "version", get_FTL_version());
	JSON_REF_STR_IN_OBJECT(ftl_local, "date", GIT_DATE);

	cJSON *version = JSON_NEW_OBJECT();

	cJSON *core = JSON_NEW_OBJECT();
	JSON_ADD_NULL_IF_NOT_EXISTS(core_local, "branch");
	JSON_ADD_NULL_IF_NOT_EXISTS(core_local, "version");
	JSON_ADD_NULL_IF_NOT_EXISTS(core_local, "hash");
	JSON_ADD_ITEM_TO_OBJECT(core, "local", core_local);
	JSON_ADD_NULL_IF_NOT_EXISTS(core_remote, "version");
	JSON_ADD_NULL_IF_NOT_EXISTS(core_remote, "hash");
	JSON_ADD_ITEM_TO_OBJECT(core, "remote", core_remote);
	JSON_ADD_ITEM_TO_OBJECT(version, "core", core);

	cJSON *web = JSON_NEW_OBJECT();
	JSON_ADD_NULL_IF_NOT_EXISTS(web_local, "branch");
	JSON_ADD_NULL_IF_NOT_EXISTS(web_local, "version");
	JSON_ADD_NULL_IF_NOT_EXISTS(web_local, "hash");
	JSON_ADD_ITEM_TO_OBJECT(web, "local", web_local);
	JSON_ADD_NULL_IF_NOT_EXISTS(web_remote, "version");
	JSON_ADD_NULL_IF_NOT_EXISTS(web_remote, "hash");
	JSON_ADD_ITEM_TO_OBJECT(web, "remote", web_remote);
	JSON_ADD_ITEM_TO_OBJECT(version, "web", web);

	cJSON *ftl = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(ftl, "local", ftl_local);
	JSON_ADD_NULL_IF_NOT_EXISTS(ftl_local, "branch");
	JSON_ADD_NULL_IF_NOT_EXISTS(ftl_local, "version");
	JSON_ADD_NULL_IF_NOT_EXISTS(ftl_local, "hash");
	JSON_ADD_ITEM_TO_OBJECT(ftl, "remote", ftl_remote);
	JSON_ADD_NULL_IF_NOT_EXISTS(ftl_remote, "version");
	JSON_ADD_NULL_IF_NOT_EXISTS(ftl_remote, "hash");
	JSON_ADD_ITEM_TO_OBJECT(version, "ftl", ftl);

	// Add nulls to docker if we didn't find any version
	JSON_ADD_NULL_IF_NOT_EXISTS(docker, "local");
	JSON_ADD_NULL_IF_NOT_EXISTS(docker, "remote");
	JSON_ADD_ITEM_TO_OBJECT(version, "docker", docker);

	// Send reply
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "version", version);
	JSON_SEND_OBJECT(json);
}

static int api_info_messages_GET(struct ftl_conn *api)
{
	// Get a private copy of the messages array
	cJSON *messages = get_messages();

	// Filtering based on GET parameters?
	bool filter_dnsmasq_warnings = false;
	if(api->request->query_string != NULL)
	{
		get_bool_var(api->request->query_string, "filter_dnsmasq_warnings", &filter_dnsmasq_warnings);
	}

	// Filter messages if requested
	if(filter_dnsmasq_warnings)
	{
		// Create new array
		cJSON *filtered = cJSON_CreateArray();

		// Loop over all messages
		for(int i = 0; i < cJSON_GetArraySize(messages); i++)
		{
			// Get message
			cJSON *message = cJSON_GetArrayItem(messages, i);
			if(message == NULL)
				continue;

			// Get type
			cJSON *type = cJSON_GetObjectItem(message, "type");
			if(type == NULL)
				continue;

			// Skip if it is a DNSMASQ_WARN message
			if(strcmp(type->valuestring, "DNSMASQ_WARN") == 0)
				continue;

			// else: Add a copy to the filtered array
			cJSON_AddItemToArray(filtered, cJSON_Duplicate(message, true));
		}

		// Free old array and replace with filtered one
		cJSON_Delete(messages);
		messages = filtered;
	}

	// Create object, add the array and send them
	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "messages", messages);
	JSON_SEND_OBJECT(json);
}

static int api_info_messages_DELETE(struct ftl_conn *api)
{
	// Check if we have an ID
	errno = 0;
	if(api->item == NULL)
	{
		// Send error reply
		return send_json_error(api, 400, // 400 Bad Request
		                       "uri_error",
		                       "Specify ID of message to delete in path",
		                       api->action_path);
	}

	// Parse ID
	errno = 0;
	const long id = strtol(api->item, NULL, 10);;
	if(errno != 0 ||id == LONG_MIN || id == LONG_MAX || id < 0)
	{
		// Send error reply
		return send_json_error(api, 400, // 400 Bad Request
		                       "bad_request",
		                       "Invalid ID in path",
		                       api->action_path);
	}

	// Delete message with this ID from the database
	delete_message(id);

	// Send empty reply with code 204 No Content
	cJSON *json = JSON_NEW_OBJECT();
	JSON_SEND_OBJECT_CODE(json, 204);
}

int api_info_messages(struct ftl_conn *api)
{
	if(api->method == HTTP_GET)
		return api_info_messages_GET(api);
	else if(api->method == HTTP_DELETE)
		return api_info_messages_DELETE(api);
	else
		return send_json_error(api, 405, "method_not_allowed", "Method not allowed", NULL);
}

int api_info_cache(struct ftl_conn *api)
{
	struct cache_info ci = { 0 };
	get_dnsmasq_cache_info(&ci);
	cJSON *cache = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(cache, "size", ci.cache_size);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "inserted", ci.cache_inserted);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "evicted", ci.cache_live_freed);
	cJSON *valid = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(valid, "a", ci.valid.a);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "aaaa", ci.valid.aaaa);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "cname", ci.valid.cname);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "srv", ci.valid.srv);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "ds", ci.valid.ds);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "dnskey", ci.valid.dnskey);
	JSON_ADD_NUMBER_TO_OBJECT(valid, "other", ci.valid.other);
	JSON_ADD_ITEM_TO_OBJECT(cache, "valid", valid);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "expired", ci.expired);
	JSON_ADD_NUMBER_TO_OBJECT(cache, "immortal", ci.immortal);

	cJSON *json = JSON_NEW_OBJECT();
	JSON_ADD_ITEM_TO_OBJECT(json, "cache", cache);
	JSON_SEND_OBJECT(json);
}
