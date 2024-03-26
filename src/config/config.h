/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  FTL config file prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef CONFIG_H
#define CONFIG_H

// enum privacy_level
#include "../enums.h"
#include <stdbool.h>
// typedef int16_t
#include <sys/types.h>
// typedef uni32_t
#include <stdint.h>
// struct in_addr, in6_addr
#include <netinet/in.h>
// type bool
#include <stdbool.h>
// type FILE
#include <stdio.h>
// type cJSON
#include "webserver/cJSON/cJSON.h"
// enum web_theme
#include "api/theme.h"

#define GLOBALTOMLPATH "/etc/pihole/pihole.toml"

// This static string represents an unchanged password
#define PASSWORD_VALUE "********"

// Size of the buffer used to report possible errors during config validation
#define VALIDATOR_ERRBUF_LEN 256

// Location of the legacy (pre-v6.0) config file
#define GLOBALCONFFILE_LEGACY "/etc/pihole/pihole-FTL.conf"

union conf_value {
	bool b;                                     // boolean value
	int i;                                      // integer value
	unsigned int ui;                            // unsigned int value
	uint16_t u16;                               // 16 bit unsigned int value
	long l;                                     // long value
	unsigned long ul;                           // unsigned long value
	double d;                                   // double value
	char *s;                                    // char * value
	enum ptr_type ptr_type;                     // enum ptr_type value
	enum busy_reply busy_reply;                 // enum busy_reply value
	enum blocking_mode blocking_mode;           // enum blocking_mode value
	enum refresh_hostnames refresh_hostnames;   // enum refresh_hostnames value
	enum privacy_level privacy_level;           // enum privacy_level value
	enum debug_flag debug_flag;                 // enum debug_flag value
	enum listening_mode listeningMode;          // enum listening_mode value
	enum web_theme web_theme;                   // enum web_theme value
	enum temp_unit temp_unit;                   // enum temp_unit value
	struct in_addr in_addr;                     // struct in_addr value
	struct in6_addr in6_addr;                   // struct in6_addr value
	cJSON *json;                                // cJSON * value
};

enum conf_type {
	CONF_BOOL = 1,
	CONF_INT,
	CONF_UINT,
	CONF_UINT16,
	CONF_LONG,
	CONF_ULONG,
	CONF_DOUBLE,
	CONF_STRING,
	CONF_PASSWORD,
	CONF_STRING_ALLOCATED,
	CONF_ENUM_PTR_TYPE,
	CONF_ENUM_BUSY_TYPE,
	CONF_ENUM_BLOCKING_MODE,
	CONF_ENUM_REFRESH_HOSTNAMES,
	CONF_ENUM_PRIVACY_LEVEL,
	CONF_ENUM_LISTENING_MODE,
	CONF_ENUM_WEB_THEME,
	CONF_ENUM_TEMP_UNIT,
	CONF_STRUCT_IN_ADDR,
	CONF_STRUCT_IN6_ADDR,
	CONF_JSON_STRING_ARRAY,
	CONF_ALL_DEBUG_BOOL
} __attribute__ ((packed));

#define MAX_CONFIG_PATH_DEPTH 6

#define FLAG_RESTART_FTL           (1 << 0)
#define FLAG_ADVANCED_SETTING      (1 << 1)
#define FLAG_PSEUDO_ITEM           (1 << 2)
#define FLAG_INVALIDATE_SESSIONS   (1 << 3)
#define FLAG_WRITE_ONLY            (1 << 4)
#define FLAG_ENV_VAR               (1 << 5)
#define FLAG_CONF_IMPORTED         (1 << 6)

struct conf_item {
	const char *k;        // item Key
	char **p;             // item Path
	char *e;              // item Environment variable
	const char *h;        // Help text / description
	cJSON *a;             // JSON array or object of Allowed values (where applicable)
	enum conf_type t;     // variable Type
	uint8_t f;            // additional Flags
	union conf_value v;   // current Value
	union conf_value d;   // Default value
	bool (*c)(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]); // Function pointer to validate the value
};

struct enum_options {
	const char *item;
	const char *description;
};

// When new config items are added, the following places need to be updated:
// - src/config/config.c: New default item
// - test/pihole.toml: Add the new item to the test config file
// - api/docs/content/specs/config.yml: Add the new item to the API documentation
struct config {
	struct {
		struct conf_item upstreams;
		struct conf_item CNAMEdeepInspect;
		struct conf_item blockESNI;
		struct conf_item EDNS0ECS;
		struct conf_item ignoreLocalhost;
		struct conf_item showDNSSEC;
		struct conf_item analyzeOnlyAandAAAA;
		struct conf_item piholePTR;
		struct conf_item replyWhenBusy;
		struct conf_item blockTTL;
		struct conf_item hosts;
		struct conf_item domainNeeded;
		struct conf_item expandHosts;
		struct conf_item domain;
		struct conf_item bogusPriv;
		struct conf_item dnssec;
		struct conf_item interface;
		struct conf_item hostRecord;
		struct conf_item listeningMode;
		struct conf_item queryLogging;
		struct conf_item cnameRecords;
		struct conf_item port;
		struct conf_item revServers;
		struct {
			struct conf_item size;
			struct conf_item optimizer;
		} cache;
		struct {
			struct conf_item active;
			struct conf_item mode;
		} blocking;
		struct {
			struct conf_item mozillaCanary;
			struct conf_item iCloudPrivateRelay;
		} specialDomains;
		struct {
			struct {
				struct conf_item force4;
				struct conf_item v4;
				struct conf_item force6;
				struct conf_item v6;
			} host;
			struct {
				struct conf_item force4;
				struct conf_item v4;
				struct conf_item force6;
				struct conf_item v6;
			} blocking;
		} reply;
		struct {
			struct conf_item count;
			struct conf_item interval;
		} rateLimit;
	} dns;

	struct {
		struct conf_item active;
		struct conf_item start;
		struct conf_item end;
		struct conf_item router;
		struct conf_item netmask;
		struct conf_item leaseTime;
		struct conf_item ipv6;
		struct conf_item rapidCommit;
		struct conf_item multiDNS;
		struct conf_item logging;
		struct conf_item hosts;
	} dhcp;

	struct {
		struct conf_item resolveIPv4;
		struct conf_item resolveIPv6;
		struct conf_item networkNames;
		struct conf_item refreshNames;
	} resolver;

	struct {
		struct conf_item DBimport;
		struct conf_item maxDBdays;
		struct conf_item DBinterval;
		struct conf_item useWAL;
		struct {
			struct conf_item parseARPcache;
			struct conf_item expire;
		} network;
	} database;

	struct {
		struct conf_item domain;
		struct conf_item acl;
		struct conf_item port;
		struct {
			struct conf_item timeout;
			struct conf_item restore;
		} session;
		struct {
			struct conf_item rev_proxy;
			struct conf_item cert;
		} tls;
		struct {
			struct conf_item webroot;
			struct conf_item webhome;
		} paths;
		struct {
			struct conf_item boxed;
			struct conf_item theme;
		} interface;
		struct {
			struct conf_item localAPIauth;
			struct conf_item searchAPIauth;
			struct conf_item max_sessions;
			struct conf_item prettyJSON;
			struct conf_item pwhash;
			struct conf_item password; // This is a pseudo-item
			struct conf_item totp_secret; // This is a write-only item
			struct conf_item app_pwhash;
			struct conf_item excludeClients;
			struct conf_item excludeDomains;
			struct conf_item maxHistory;
			struct conf_item maxClients;
			struct conf_item client_history_global_max;
			struct conf_item allow_destructive;
			struct {
				struct conf_item limit;
				struct conf_item unit;
			} temp;
		} api;
	} webserver;

	struct {
		struct conf_item pid;
		struct conf_item database;
		struct conf_item gravity;
		struct conf_item gravity_tmp;
		struct conf_item macvendor;
		struct conf_item setupVars;
		struct conf_item pcap;
		struct {
			struct conf_item ftl;
			struct conf_item dnsmasq;
			struct conf_item webserver;
		} log;
	} files;

	struct {
		struct conf_item privacylevel;
		struct conf_item delay_startup;
		struct conf_item nice;
		struct conf_item addr2line;
		struct conf_item etc_dnsmasq_d;
		struct conf_item dnsmasq_lines;
		struct conf_item extraLogging;
		struct {
			struct conf_item load;
			struct conf_item shmem;
			struct conf_item disk;
		} check;
	} misc;

	struct {
		// The order of items in this struct has to match the order in
		// enum debug_flags due to a few simplifications made elsewhere
		// in the code
		struct conf_item database;
		struct conf_item networking;
		struct conf_item locks;
		struct conf_item queries;
		struct conf_item flags;
		struct conf_item shmem;
		struct conf_item gc;
		struct conf_item arp;
		struct conf_item regex;
		struct conf_item api;
		struct conf_item tls;
		struct conf_item overtime;
		struct conf_item status;
		struct conf_item caps;
		struct conf_item dnssec;
		struct conf_item vectors;
		struct conf_item resolver;
		struct conf_item edns0;
		struct conf_item clients;
		struct conf_item aliasclients;
		struct conf_item events;
		struct conf_item helper;
		struct conf_item config;
		struct conf_item inotify;
		struct conf_item webserver;
		struct conf_item extra;
		struct conf_item reserved;
		// all must be the last item in this struct
		struct conf_item all;
	} debug;
};

extern struct config config;

#define CONFIG_ELEMENTS (sizeof(config)/sizeof(struct conf_item))
#define DEBUG_ELEMENTS (sizeof(config.debug)/sizeof(struct conf_item))

// Defined in config.c
void set_debug_flags(struct config *conf);
void set_all_debug(struct config *conf, const bool status);
void initConfig(struct config *conf);
void reset_config(struct conf_item *conf_item);
bool readFTLconf(struct config *conf, const bool rewrite);
bool getLogFilePath(void);
struct conf_item *get_conf_item(struct config *conf, const unsigned int n);
struct conf_item *get_debug_item(struct config *conf, const enum debug_flag debug);
unsigned int config_path_depth(char **paths) __attribute__ ((pure));
void duplicate_config(struct config *dst, struct config *src);
void free_config(struct config *conf);
bool compare_config_item(const enum conf_type t, const union conf_value *val1, const union conf_value *val2);
char **gen_config_path(const char *pathin, const char delim);
void free_config_path(char **paths);
bool check_paths_equal(char **paths1, char **paths2, unsigned int max_level) __attribute__ ((pure));
const char *get_conf_type_str(const enum conf_type type) __attribute__ ((const));
void replace_config(struct config *newconf);
void reread_config(void);

// Defined in toml_reader.c
bool readDebugSettings(void);
void init_config_mutex(void);
enum blocking_status get_blockingstatus(void) __attribute__((pure));
void set_blockingstatus(bool enabled);

// Add enum items with descriptions
#define CONFIG_ADD_ENUM_OPTIONS(json, opts)({ \
	json = cJSON_CreateArray(); \
	for(unsigned int i = 0; i < ArraySize(opts); i++) \
	{ \
		cJSON *jopt = cJSON_CreateObject(); \
		if(opts[i].item[0] >= '0' && opts[i].item[0] <= '9') \
			cJSON_AddItemToObject(jopt, "item", cJSON_CreateNumber(opts[i].item[0] - '0')); \
		else \
			cJSON_AddItemToObject(jopt, "item", cJSON_CreateStringReference(opts[i].item)); \
		cJSON_AddItemToObject(jopt, "description", cJSON_CreateStringReference(opts[i].description)); \
		cJSON_AddItemToArray(json, jopt); \
	} \
})

// Get a string representation of the allowed value, this is always allocated
// and needs to be freed after use
#define CONFIG_ITEM_ARRAY(json, output)({ \
	if(cJSON_IsArray(json)) \
	{ \
		cJSON *array = cJSON_CreateArray(); \
		for(int icnt = 0; icnt < cJSON_GetArraySize(json); icnt++) \
		{ \
			cJSON *jopt = cJSON_GetArrayItem(json, icnt); \
			cJSON *item = cJSON_GetObjectItem(jopt, "item"); \
			if(cJSON_IsString(item)) \
				cJSON_AddItemToArray(array, cJSON_Duplicate(item, true)); \
		} \
		output = cJSON_PrintUnformatted(array); \
		cJSON_Delete(array); \
	} \
	else if(cJSON_IsString(json)) \
	{ \
		output = strdup(json->valuestring); \
	} \
})

#endif //CONFIG_H
