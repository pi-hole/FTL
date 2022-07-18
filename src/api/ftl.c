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
	cJSON *json = JSON_NEW_OBJ();
	// Add client's IP address
	JSON_OBJ_REF_STR(json, "remote_addr", api->request->remote_addr);

	// Add HTTP version
	JSON_OBJ_REF_STR(json, "http_version", api->request->http_version);

	// Add request method
	JSON_OBJ_REF_STR(json, "method", api->request->request_method);

	// Add HTTP headers
	cJSON *headers = JSON_NEW_ARRAY();
	for(int i = 0; i < api->request->num_headers; i++)
	{
		// Add headers
		cJSON *header = JSON_NEW_OBJ();
		JSON_OBJ_REF_STR(header, "name", api->request->http_headers[i].name);
		JSON_OBJ_REF_STR(header, "value", api->request->http_headers[i].value);
		JSON_ARRAY_ADD_ITEM(headers, header);
	}
	JSON_OBJ_ADD_ITEM(json, "headers", headers);

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
	cJSON *json = JSON_NEW_OBJ();
	cJSON *log = JSON_NEW_ARRAY();
	for(unsigned int i = start; i < LOG_SIZE; i++)
	{
		if(fifo_log->timestamp[i] < 1.0)
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

int api_ftl_dbinfo(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJ();

	// Add database stat details
	struct stat st;
	get_database_stat(&st);
	JSON_OBJ_ADD_NUMBER(json, "size", st.st_size); // Total size, in bytes

	// File type
	const char *filetype;
	if((st.st_mode & S_IFMT) == S_IFREG)
		filetype = "Regular file";
	else if((st.st_mode & S_IFMT) == S_IFLNK)
		filetype = "Symbolic link";
	else
		filetype = "Unknown";
	JSON_OBJ_REF_STR(json, "type", filetype);

	// File mode
	char permissions[10] = { 0 };
	get_permission_string(permissions, &st);
	JSON_OBJ_REF_STR(json, "mode", permissions);

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
	else
	{
		JSON_OBJ_ADD_NULL(user, "name");
		JSON_OBJ_ADD_NULL(user, "info");
	}

	cJSON *group = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(group, "gid", st.st_gid); // GID
	const struct group *gr = getgrgid(st.st_uid);
	if(gr != NULL)
	{
		JSON_OBJ_COPY_STR(group, "name", gr->gr_name); // Group name
	}
	else
	{
		JSON_OBJ_ADD_NULL(group, "name");
	}
	cJSON *owner = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(owner, "user", user);
	JSON_OBJ_ADD_ITEM(owner, "group", group);
	JSON_OBJ_ADD_ITEM(json, "owner", owner);

	// Add number of queries in on-disk database
	const int queries_in_database = get_number_of_queries_in_DB(NULL, "query_storage", true);
	JSON_OBJ_ADD_NUMBER(json, "queries", queries_in_database);

	// Add SQLite library version
	JSON_OBJ_REF_STR(json, "sqlite_version", get_sqlite3_version());

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
			cJSON *item = JSON_NEW_OBJ();
			if(f_label && fgets(label, sizeof(label)-1, f_label))
			{
				// Remove newline if present
				char *p = strchr(label, '\n');
				if (p != NULL) *p = '\0';
				JSON_OBJ_COPY_STR(item, "name", label);
			}
			else
			{
				JSON_OBJ_ADD_NULL(item, "name");
			}
			JSON_OBJ_COPY_STR(item, "path", short_path);
			JSON_OBJ_ADD_NUMBER(item, "value", temp < 1000 ? temp : 1e-3*temp);
			JSON_ARRAY_ADD_ITEM(object, item);
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
	JSON_OBJ_ADD_NUMBER(system, "uptime", info.uptime);

	cJSON *memory = JSON_NEW_OBJ();
	cJSON *ram = JSON_NEW_OBJ();
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
	JSON_OBJ_ADD_NUMBER(ram, "total", mem_total);
	// Free memory size
	JSON_OBJ_ADD_NUMBER(ram, "free", mem_free);
	// Used memory size
	JSON_OBJ_ADD_NUMBER(ram, "used", mem_used);
	// Available memory size
	// See https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773
	// This Linux kernel commit message explains there are more nuances. It
	// says: "Many programs check /proc/meminfo to estimate how much free
	// memory is available. They generally do this by adding up "free" and
	// "cached", which was fine ten years ago, but is pretty much guaranteed
	// to be wrong today."
	JSON_OBJ_ADD_NUMBER(ram, "available", mem_avail);
	JSON_OBJ_ADD_ITEM(memory, "ram", ram);

	cJSON *swap = JSON_NEW_OBJ();
	// Total swap space size
	JSON_OBJ_ADD_NUMBER(swap, "total", info.totalswap * info.mem_unit);
	// Swap space still available
	JSON_OBJ_ADD_NUMBER(swap, "free", info.freeswap * info.mem_unit);
	// Used swap space
	JSON_OBJ_ADD_NUMBER(swap, "used", (info.totalswap - info.freeswap) * info.mem_unit);
	JSON_OBJ_ADD_ITEM(memory, "swap", swap);
	JSON_OBJ_ADD_ITEM(system, "memory", memory);

	// Number of current processes
	JSON_OBJ_ADD_NUMBER(system, "procs", info.procs);

	cJSON *cpu = JSON_NEW_OBJ();
	// Number of available processors
	JSON_OBJ_ADD_NUMBER(cpu, "nprocs", nprocs);

	// 1, 5, and 15 minute load averages (we need to convert them)
	cJSON *raw = JSON_NEW_ARRAY();
	cJSON *percent = JSON_NEW_ARRAY();
	float load_f[3] = { 0.f };
	const float longfloat = 1.f / (1 << SI_LOAD_SHIFT);
	for(unsigned int i = 0; i < 3; i++)
	{
		load_f[i] = longfloat * info.loads[i];
		JSON_ARRAY_ADD_NUMBER(raw, load_f[i]);
		JSON_ARRAY_ADD_NUMBER(percent, (100.f*load_f[i]/nprocs));
	}

	// Averaged CPU usage in percent
	cJSON *load = JSON_NEW_OBJ();
	JSON_OBJ_ADD_ITEM(load, "raw", raw);
	JSON_OBJ_ADD_ITEM(load, "percent", percent);
	JSON_OBJ_ADD_ITEM(cpu, "load", load);
	JSON_OBJ_ADD_ITEM(system, "cpu", cpu);

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
	JSON_OBJ_ADD_ITEM(system, "sensors", sensors);

	// Try to obtain device model
	FILE *f_model = fopen("/sys/firmware/devicetree/base/model", "r");
	char model[1024] = { 0 };
	if(f_model && fgets(model, sizeof(model)-1, f_model))
	{
		// Remove newline if present
		char *p = strchr(model, '\n');
		if (p != NULL) *p = '\0';
		JSON_OBJ_COPY_STR(system, "model", model);
	}
	else
	{
		JSON_OBJ_ADD_NULL(system, "model");
	}
	if(f_model)
		fclose(f_model);

	cJSON *dns = JSON_NEW_OBJ();
	const bool blocking = get_blockingstatus();
	JSON_OBJ_ADD_BOOL(dns, "blocking", blocking); // same reply type as in /api/dns/status
	JSON_OBJ_ADD_ITEM(system, "dns", dns);

	return 0;
}

int get_ftl_obj(struct ftl_conn *api, cJSON *ftl, const bool is_locked)
{
	cJSON *database = JSON_NEW_OBJ();

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
	const int privacylevel = config.privacylevel;

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

	JSON_OBJ_ADD_NUMBER(database, "gravity", db_gravity);
	JSON_OBJ_ADD_NUMBER(database, "groups", db_groups);
	JSON_OBJ_ADD_NUMBER(database, "lists", db_lists);
	JSON_OBJ_ADD_NUMBER(database, "clients", db_clients);

	cJSON *domains = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(domains, "allowed", db_allowed);
	JSON_OBJ_ADD_NUMBER(domains, "denied", db_denied);
	JSON_OBJ_ADD_ITEM(database, "domains", domains);
	JSON_OBJ_ADD_ITEM(ftl, "database", database);

	JSON_OBJ_ADD_NUMBER(ftl, "privacy_level", privacylevel);

	cJSON *clients = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(clients, "total",clients_total);
	JSON_OBJ_ADD_NUMBER(clients, "active", activeclients);
	JSON_OBJ_ADD_ITEM(ftl, "clients", clients);

	return 0;
}

int api_ftl_sysinfo(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJ();

	// Get system object
	cJSON *system = JSON_NEW_OBJ();
	int ret = get_system_obj(api, system);
	if (ret != 0)
		return ret;

	JSON_OBJ_ADD_ITEM(json, "system", system);

	// Get FTL object
	cJSON *ftl = JSON_NEW_OBJ();
	ret = get_ftl_obj(api, ftl, false);
	if(ret != 0)
		return ret;

	JSON_OBJ_ADD_ITEM(json, "ftl", ftl);
	JSON_SEND_OBJECT(json);
}

int api_ftl_maxhistory(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(json, "maxHistory", config.maxHistory);
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
	in_addr_t gw = 0;
	char iface[IF_NAMESIZE] = { 0 };

	// Get default interface
	getDefaultInterface(iface, &gw);

	// Generate JSON response
	cJSON *json = JSON_NEW_OBJ();
	const char *gwaddr = inet_ntoa(*(struct in_addr *) &gw);
	JSON_OBJ_COPY_STR(json, "address", gwaddr);
	JSON_OBJ_REF_STR(json, "interface", iface);
	JSON_SEND_OBJECT(json);
}


struct if_info {
	bool carrier;
	bool default_iface;
	char *name;
	struct {
		char *v4;
		char *v6;
	} ip;
	int speed;
	ssize_t rx_bytes;
	ssize_t tx_bytes;
	sa_family_t family;
	struct if_info *next;
};

static bool listInterfaces(struct if_info **head, char default_iface[IF_NAMESIZE])
{
	// Loop over interfaces and extract information
	DIR *dfd;
	FILE *f;
	struct dirent *dp;
	struct if_info *tail = NULL;
	size_t tx_sum = 0, rx_sum = 0;
	char fname[64 + IF_NAMESIZE] = { 0 };
	char readbuffer[1024] = { 0 };

	// Open /sys/class/net directory
	if ((dfd = opendir("/sys/class/net")) == NULL)
	{
		log_err("API: Cannot access /sys/class/net");
		return false;
	}

	// Get IP addresses of all interfaces on this machine
	struct ifaddrs *ifap = NULL;
	if(getifaddrs(&ifap) == -1)
		log_err("API: Cannot get interface addresses: %s", strerror(errno));

	// Walk /sys/class/net directory
	while ((dp = readdir(dfd)) != NULL)
	{
		// Skip "." and ".."
		if(!dp->d_name || strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;

		// Create new interface record
		struct if_info *new = calloc(1, sizeof(struct if_info));
		new->name = strdup(dp->d_name);

		new->default_iface = strcmp(new->name, default_iface) == 0;

		// Extract carrier status
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/carrier", new->name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fgets(readbuffer, sizeof(readbuffer)-1, f) != NULL)
				new->carrier = readbuffer[0] == '1';
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Extract link speed (may not be possible, e.g., for WiFi devices with dynamic link speeds)
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/speed", new->name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%i", &(new->speed)) != 1)
				new->speed = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Get total transmitted bytes
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/tx_bytes", new->name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(new->tx_bytes)) != 1)
				new->tx_bytes = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Get total transmitted bytes
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/rx_bytes", new->name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(new->rx_bytes)) != 1)
				new->rx_bytes = -1;
			fclose(f);
		}
		else
			log_err("Cannot read %s: %s", fname, strerror(errno));

		// Get IP address(es) of this interface
		if(ifap)
		{
			// Walk through linked list of interface addresses

			for(struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
			{
				// Skip interfaces without an address and those
				// not matching the current interface
				if(ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, new->name) != 0)
					continue;

				// If we reach this point, we found the correct interface
				new->family = ifa->ifa_addr->sa_family;
				char host[NI_MAXHOST] = { 0 };
				if(new->family == AF_INET || new->family == AF_INET6)
				{
					// Get IP address
					const int s = getnameinfo(ifa->ifa_addr,
					                          (new->family == AF_INET) ?
					                               sizeof(struct sockaddr_in) :
					                               sizeof(struct sockaddr_in6),
					                          host, NI_MAXHOST,
					                          NULL, 0, NI_NUMERICHOST);
					if (s != 0)
					{
						log_warn("API: getnameinfo() failed: %s\n", gai_strerror(s));
						continue;
					}

					if(new->family == AF_INET)
					{
						// IPv4 address
						if(!new->ip.v4)
						{
							// First or only IPv4 address of this interface
							new->ip.v4 = strdup(host);
						}
						else
						{
							// Create comma-separated list
							char *new_v4 = calloc(strlen(new->ip.v4) + strlen(host) + 2, sizeof(char));
							sprintf(new_v4, "%s,%s", new->ip.v4, host);
							free(new->ip.v4);
							new->ip.v4 = new_v4;
						}
					}
					else if(new->family == AF_INET6)
					{
						// IPv6 address
						if(!new->ip.v6)
						{
							// First or only IPv6 address of this interface
							new->ip.v6 = strdup(host);
						}
						else
						{
							// Create comma-separated list
							char *new_v6 = calloc(strlen(new->ip.v6) + strlen(host) + 2, sizeof(char));
							sprintf(new_v6, "%s,%s", new->ip.v6, host);
							free(new->ip.v6);
							new->ip.v6 = new_v6;
						}
					}
				}
			}
		}

		// Add to end of the linked list
		if(!*head)
			*head = new;
		if(tail)
			tail->next = new;
		tail = new;

		tx_sum += new->tx_bytes;
		rx_sum += new->rx_bytes;
	}

	freeifaddrs(ifap);

	// Create sum entry only if there is more than one interface
	if(head == NULL)
		return true;

	struct if_info *new = calloc(1, sizeof(struct if_info));
	new->name = strdup("sum");
	new->carrier = true;
	new->speed = 0;
	new->tx_bytes = tx_sum;
	new->rx_bytes = rx_sum;
	if(tail)
		tail->next = new;
	tail = new;

	return true;
}

static int json_iface(struct ftl_conn *api, struct if_info *iface, cJSON *json)
{
	double tx = 0.0, rx = 0.0;
	char tx_unit[3] = { 0 }, rx_unit[3] = { 0 };
	format_memory_size(tx_unit, iface->tx_bytes, &tx);
	format_memory_size(rx_unit, iface->rx_bytes, &rx);
	if(tx_unit[0] != '\0')
		tx_unit[1] = 'B';
	if(rx_unit[0] != '\0')
		rx_unit[1] = 'B';

	JSON_OBJ_COPY_STR(json, "name", iface->name);
	JSON_OBJ_ADD_BOOL(json, "carrier", iface->carrier);
	JSON_OBJ_ADD_NUMBER(json, "speed", iface->speed);

	cJSON *tx_json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(tx_json, "num", tx);
	JSON_OBJ_COPY_STR(tx_json, "unit", rx_unit);
	JSON_OBJ_ADD_ITEM(json, "tx", tx_json);

	cJSON *rx_json = JSON_NEW_OBJ();
	JSON_OBJ_ADD_NUMBER(rx_json, "num", rx);
	JSON_OBJ_COPY_STR(rx_json, "unit", rx_unit);
	JSON_OBJ_ADD_ITEM(json, "rx", rx_json);

	if( iface->carrier && iface->ip.v4)
	{
		JSON_OBJ_COPY_STR(json, "ipv4", iface->ip.v4);
	}
	else
	{
		JSON_OBJ_REF_STR(json, "ipv4", "-");
	}

	if( iface->carrier && iface->ip.v6)
	{
		JSON_OBJ_COPY_STR(json, "ipv6", iface->ip.v6);
	}
	else
	{
		JSON_OBJ_REF_STR(json, "ipv6", "-");
	}

	return 200;
}

int api_ftl_interfaces(struct ftl_conn *api)
{
	cJSON *json = JSON_NEW_OBJ();
	cJSON *gateway = JSON_NEW_OBJ();
	cJSON *interfaces = JSON_NEW_ARRAY();

	// Get interface with default route
	in_addr_t gw = 0;
	char default_iface[IF_NAMESIZE] = { 0 };
	getDefaultInterface(default_iface, &gw);

	const char *gwaddr = inet_ntoa(*(struct in_addr *) &gw);
	JSON_OBJ_COPY_STR(gateway, "address", gwaddr);
	JSON_OBJ_REF_STR(gateway, "interface", default_iface);
	JSON_OBJ_ADD_ITEM(json, "gateway", gateway);

	// Enumerate and list interfaces
	struct if_info *ifinfo = NULL;
	if(!listInterfaces(&ifinfo, default_iface))
		JSON_SEND_OBJECT(json);

	// Loop over collected interface information
	struct if_info *iface = ifinfo;
	// Show only the default interface as first interface
	while(iface)
	{
		if(iface->default_iface)
		{
			cJSON *ijson = JSON_NEW_OBJ();
			int rc = json_iface(api, iface, ijson);
			if(rc != 200)
				return rc;
			JSON_ARRAY_ADD_ITEM(interfaces, ijson);
			break;
		}
		iface = iface->next;
	}
	iface = ifinfo;
	// Show all but the default interface
	while(iface)
	{
		if(!iface->default_iface)
		{
			cJSON *ijson = JSON_NEW_OBJ();
			int rc = json_iface(api, iface, ijson);
			if(rc != 200)
				return rc;
			JSON_ARRAY_ADD_ITEM(interfaces, ijson);
		}

		// Free associated memory
		struct if_info *next = iface->next;
		if(iface->name)
			free(iface->name);
		if(iface->ip.v4)
			free(iface->ip.v4);
		if(iface->ip.v6)
			free(iface->ip.v6);
		free(iface);
		iface = next;
	}
	JSON_OBJ_ADD_ITEM(json, "interfaces", interfaces);
	JSON_SEND_OBJECT(json);
}