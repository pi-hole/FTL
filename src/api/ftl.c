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
// Routing information and flags
#include <net/route.h>
// Interate through directories
#include <dirent.h>

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
	{
		return send_json_unauthorized(api);
	}

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
	{
		return send_json_unauthorized(api);
	}

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
		int temp = 0;
		char label[1024];
		if(fscanf(f_value, "%d", &temp) == 1)
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
			JSON_ADD_NUMBER_TO_OBJECT(item, "value", temp < 1000 ? temp : 1e-3*temp);
			JSON_ADD_ITEM_TO_ARRAY(object, item);
		}
	}
	if(f_label != NULL)
		fclose(f_label);
	if(f_value != NULL)
		fclose(f_value);

	return 0;
}

// Get RAM information in units of kB
// This is implemented similar to how free (procps) does it
static bool GetRamInKB(long *mem_total, long *mem_used, long *mem_free, long *mem_avail)
{
	long page_cached = -1, buffers = -1, slab_reclaimable = -1;
	FILE *meminfo = fopen("/proc/meminfo", "r");
	if(meminfo == NULL)
		return false;

	char line[256];
	while(fgets(line, sizeof(line), meminfo))
	{
		sscanf(line, "MemTotal: %ld kB", mem_total);
		sscanf(line, "MemFree: %ld kB", mem_free);
		sscanf(line, "MemAvailable: %ld kB", mem_avail);
		sscanf(line, "Cached: %ld kB", &page_cached);
		sscanf(line, "Buffers: %ld kB", &buffers);
		sscanf(line, "SReclaimable: %ld kB", &slab_reclaimable);

		// Exit if we have them all
		if(*mem_total > -1 && *mem_avail > -1 && *mem_free > -1 &&
		   buffers > -1 && slab_reclaimable > -1)
			break;
	}
	fclose(meminfo);

	// Compute actual memory numbers
	const long mem_cached = page_cached + slab_reclaimable;
	// if mem_avail is greater than mem_total or our calculation of used
	// overflows, that's symptomatic of running within a lxc container where
	// such values will be dramatically distorted over those of the host.
	if (*mem_avail > *mem_total)
		*mem_avail = *mem_free;
	*mem_used = *mem_total - *mem_free - mem_cached - buffers;
	if (*mem_used < 0)
		*mem_used = *mem_total - *mem_free;

	// Return success
	return true;
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
	long mem_total = -1, mem_used = -1, mem_free = -1, mem_avail = -1;
	GetRamInKB(&mem_total, &mem_used, &mem_free, &mem_avail);
	// Total usable main memory size
	JSON_ADD_NUMBER_TO_OBJECT(ram, "total", mem_total);
	// Free memory size
	JSON_ADD_NUMBER_TO_OBJECT(ram, "free", mem_free);
	// Used memory size
	JSON_ADD_NUMBER_TO_OBJECT(ram, "used", mem_used);
	// Available memory size
	// See https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773
	// This Linux kernel commit message explains there are more nuances. It
	// says: "Many programs check /proc/meminfo to estimate how much free
	// memory is available. They generally do this by adding up "free" and
	// "cached", which was fine ten years ago, but is pretty much guaranteed
	// to be wrong today."
	JSON_ADD_NUMBER_TO_OBJECT(ram, "available", mem_avail);
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

	cJSON *dns = JSON_NEW_OBJECT();
	const bool blocking = get_blockingstatus();
	JSON_ADD_BOOL_TO_OBJECT(dns, "blocking", blocking); // same reply type as in /api/dns/status
	JSON_ADD_ITEM_TO_OBJECT(system, "dns", dns);

	return 0;
}

int get_ftl_obj(struct ftl_conn *api, cJSON *ftl, const bool is_locked)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

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
	const int privacylevel = config.misc.privacylevel;

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

	return 0;
}

int api_ftl_sysinfo(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

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

static bool getDefaultInterface(char iface[IF_NAMESIZE], in_addr_t *gw)
{
	// Get IPv4 default route gateway and associated interface
	long dest_r = 0, gw_r = 0;
	int flags = 0, metric = 0, minmetric = __INT_MAX__;
	char iface_r[IF_NAMESIZE] = { 0 };
	char buf[1024] = { 0 };

	FILE *file;
	if((file = fopen("/proc/net/route", "r")))
	{
		// Parse /proc/net/route - the kernel's IPv4 routing table
		while(fgets(buf, sizeof(buf), file))
		{
			if(sscanf(buf, "%s %lx %lx %x %*i %*i %i", iface_r, &dest_r, &gw_r, &flags, &metric) != 5)
				continue;

			// Only anaylze routes which are UP and whose
			// destinations are a gateway
			if(!(flags & RTF_UP) || !(flags & RTF_GATEWAY))
				continue;

			// Only analyze "catch all" routes (destination 0.0.0.0)
			if(dest_r != 0)
				continue;

			// Store default gateway, overwrite if we find a route with
			// a lower metric
			if(metric < minmetric)
			{
				minmetric = metric;
				*gw = gw_r;
				strcpy(iface, iface_r);

				log_debug(DEBUG_API, "Reading interfaces: flags: %i, addr: %s, iface: %s, metric: %i, minmetric: %i",
				          flags, inet_ntoa(*(struct in_addr *) gw), iface, metric, minmetric);
			}
		}
		fclose(file);
	}
	else
		log_err("Cannot read /proc/net/route: %s", strerror(errno));

	// Return success based on having found the default gateway's address
	return gw != 0;
}

int api_ftl_gateway(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	in_addr_t gw = 0;
	char iface[IF_NAMESIZE] = { 0 };

	// Get default interface
	getDefaultInterface(iface, &gw);

	// Generate JSON response
	cJSON *json = JSON_NEW_OBJECT();
	const char *gwaddr = inet_ntoa(*(struct in_addr *) &gw);
	JSON_COPY_STR_TO_OBJECT(json, "address", gwaddr);
	JSON_REF_STR_IN_OBJECT(json, "interface", iface);
	JSON_SEND_OBJECT(json);
}

int api_ftl_interfaces(struct ftl_conn *api)
{
	// Verify requesting client is allowed to see this ressource
	if(check_client_auth(api) == API_AUTH_UNAUTHORIZED)
	{
		return send_json_unauthorized(api);
	}

	cJSON *json = JSON_NEW_OBJECT();

	// Get interface with default route
	in_addr_t gw = 0;
	char default_iface[IF_NAMESIZE] = { 0 };
	getDefaultInterface(default_iface, &gw);

	// Enumerate and list interfaces
	// Loop over interfaces and extract information
	DIR *dfd;
	FILE *f;
	struct dirent *dp;
	size_t tx_sum = 0, rx_sum = 0;
	char fname[64 + IF_NAMESIZE] = { 0 };
	char readbuffer[1024] = { 0 };

	// Open /sys/class/net directory
	if ((dfd = opendir("/sys/class/net")) == NULL)
	{
		log_err("API: Cannot access /sys/class/net");
		return 500;
	}

	// Get IP addresses of all interfaces on this machine
	struct ifaddrs *ifap = NULL;
	if(getifaddrs(&ifap) == -1)
		log_err("API: Cannot get interface addresses: %s", strerror(errno));

	cJSON *interfaces = JSON_NEW_ARRAY();
	// Walk /sys/class/net directory
	while ((dp = readdir(dfd)) != NULL)
	{
		// Skip "." and ".."
		if(!dp->d_name || strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;

		// Create new interface record
		cJSON *iface = JSON_NEW_OBJECT();

		// Extract interface name
		const char *iface_name = dp->d_name;
		JSON_COPY_STR_TO_OBJECT(iface, "name", iface_name);

		// Is this the default interface?
		const bool is_default_iface = strcmp(iface_name, default_iface) == 0;
		JSON_ADD_BOOL_TO_OBJECT(iface, "default", is_default_iface);

		// Extract carrier status
		bool carrier = false;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/carrier", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fgets(readbuffer, sizeof(readbuffer)-1, f) != NULL)
				carrier = readbuffer[0] == '1';
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));
		JSON_ADD_BOOL_TO_OBJECT(iface, "carrier", carrier);

		// Extract link speed (may not be possible, e.g., for WiFi devices with dynamic link speeds)
		int speed = -1;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/speed", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%i", &(speed)) != 1)
				speed = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));
		JSON_ADD_NUMBER_TO_OBJECT(iface, "speed", speed);

		// Get total transmitted bytes
		ssize_t tx_bytes = -1;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/tx_bytes", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(tx_bytes)) != 1)
				tx_bytes = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Format transmitted bytes
		double tx = 0.0;
		char tx_unit[3] = { 0 };
		format_memory_size(tx_unit, tx_bytes, &tx);
		if(tx_unit[0] != '\0')
			tx_unit[1] = 'B';

		// Add transmitted bytes to interface record
		cJSON *tx_json = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(tx_json, "num", tx);
		JSON_COPY_STR_TO_OBJECT(tx_json, "unit", tx_unit);
		JSON_ADD_ITEM_TO_OBJECT(iface, "tx", tx_json);

		// Get total received bytes
		ssize_t rx_bytes = -1;
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/rx_bytes", iface_name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(rx_bytes)) != 1)
				rx_bytes = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Format received bytes
		double rx = 0.0;
		char rx_unit[3] = { 0 };
		format_memory_size(rx_unit, rx_bytes, &rx);
		if(rx_unit[0] != '\0')
			rx_unit[1] = 'B';

		// Add received bytes to JSON object
		cJSON *rx_json = JSON_NEW_OBJECT();
		JSON_ADD_NUMBER_TO_OBJECT(rx_json, "num", rx);
		JSON_COPY_STR_TO_OBJECT(rx_json, "unit", rx_unit);
		JSON_ADD_ITEM_TO_OBJECT(iface, "rx", rx_json);

		// Get IP address(es) of this interface
		if(ifap)
		{
			// Walk through linked list of interface addresses
			cJSON *ipv4 = JSON_NEW_ARRAY();
			cJSON *ipv6 = JSON_NEW_ARRAY();
			for(struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
			{
				// Skip interfaces without an address and those
				// not matching the current interface
				if(ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, iface_name) != 0)
					continue;

				// If we reach this point, we found the correct interface
				const sa_family_t family = ifa->ifa_addr->sa_family;
				char host[NI_MAXHOST] = { 0 };
				if(family == AF_INET || family == AF_INET6)
				{
					// Get IP address
					const int s = getnameinfo(ifa->ifa_addr,
					                          (family == AF_INET) ?
					                               sizeof(struct sockaddr_in) :
					                               sizeof(struct sockaddr_in6),
					                          host, NI_MAXHOST,
					                          NULL, 0, NI_NUMERICHOST);
					if (s != 0)
					{
						log_warn("API: getnameinfo() failed: %s\n", gai_strerror(s));
						continue;
					}

					if(family == AF_INET)
					{
						JSON_COPY_STR_TO_ARRAY(ipv4, host);
					}
					else if(family == AF_INET6)
					{
						JSON_COPY_STR_TO_ARRAY(ipv6, host);
					}
				}
			}
			JSON_ADD_ITEM_TO_OBJECT(iface, "ipv4", ipv4);
			JSON_ADD_ITEM_TO_OBJECT(iface, "ipv6", ipv6);
		}

		// Sum up transmitted and received bytes
		tx_sum += tx_bytes;
		rx_sum += rx_bytes;

		// Add interface to array
		JSON_ADD_ITEM_TO_ARRAY(interfaces, iface);
	}

	freeifaddrs(ifap);

	cJSON *sum = JSON_NEW_OBJECT();
	JSON_COPY_STR_TO_OBJECT(sum, "name", "sum");
	JSON_ADD_BOOL_TO_OBJECT(sum, "carrier", true);
	JSON_ADD_NUMBER_TO_OBJECT(sum, "speed", 0);

	// Format transmitted bytes
	double tx = 0.0;
	char tx_unit[3] = { 0 };
	format_memory_size(tx_unit, tx_sum, &tx);
	if(tx_unit[0] != '\0')
		tx_unit[1] = 'B';

	// Add transmitted bytes to interface record
	cJSON *tx_json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(tx_json, "num", tx);
	JSON_COPY_STR_TO_OBJECT(tx_json, "unit", tx_unit);
	JSON_ADD_ITEM_TO_OBJECT(sum, "tx", tx_json);

	// Format received bytes
	double rx = 0.0;
	char rx_unit[3] = { 0 };
	format_memory_size(rx_unit, rx_sum, &rx);
	if(rx_unit[0] != '\0')
		rx_unit[1] = 'B';

	// Add received bytes to JSON object
	cJSON *rx_json = JSON_NEW_OBJECT();
	JSON_ADD_NUMBER_TO_OBJECT(rx_json, "num", rx);
	JSON_COPY_STR_TO_OBJECT(rx_json, "unit", rx_unit);
	JSON_ADD_ITEM_TO_OBJECT(sum, "rx", rx_json);

	cJSON *ipv4 = JSON_NEW_ARRAY();
	cJSON *ipv6 = JSON_NEW_ARRAY();
	JSON_ADD_ITEM_TO_OBJECT(sum, "ipv4", ipv4);
	JSON_ADD_ITEM_TO_OBJECT(sum, "ipv6", ipv6);

	// Add interface to array
	JSON_ADD_ITEM_TO_ARRAY(interfaces, sum);
	JSON_ADD_ITEM_TO_OBJECT(json, "interfaces", interfaces);
	JSON_SEND_OBJECT(json);
}
