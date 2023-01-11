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
#include "cJSON/cJSON.h"

#define GLOBALTOMLPATH "/etc/pihole/pihole-FTL.toml"

// Defined in config.c
void set_all_debug(const bool status);
void initConfig(void);
void readFTLconf(const bool rewrite);
bool getLogFilePath(void);
struct conf_item *get_conf_item(unsigned int n);
struct conf_item *get_debug_item(const enum debug_flag debug);
unsigned int config_path_depth(struct conf_item *conf_item) __attribute__ ((pure));

// Defined in toml_reader.c
bool getPrivacyLevel(void);
bool getBlockingMode(void);
bool readDebugSettings(void);
void init_config_mutex(void);
bool get_blockingstatus(void) __attribute__((pure));
void set_blockingstatus(bool enabled);

union conf_value {
	bool b;                                     // boolean value
	int i;                                      // integer value
	unsigned int ui;                            // unsigned int value
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
	enum listening_mode listening_mode;         // enum listening_mode value
	struct in_addr in_addr;                     // struct in_addr value
	struct in6_addr in6_addr;                   // struct in6_addr value
	cJSON *json;                                // cJSON * value
};

enum conf_type {
	CONF_BOOL,
	CONF_INT,
	CONF_UINT,
	CONF_LONG,
	CONF_ULONG,
	CONF_DOUBLE,
	CONF_STRING,
	CONF_STRING_ALLOCATED,
	CONF_ENUM_PTR_TYPE,
	CONF_ENUM_BUSY_TYPE,
	CONF_ENUM_BLOCKING_MODE,
	CONF_ENUM_REFRESH_HOSTNAMES,
	CONF_ENUM_PRIVACY_LEVEL,
	CONF_ENUM_LISTENING_MODE,
	CONF_STRUCT_IN_ADDR,
	CONF_STRUCT_IN6_ADDR,
	// We could theoretically use a more generic type, however, we want this
	// here for strict input checking
	CONF_JSON_STRING_ARRAY
} __attribute__ ((packed));

#define MAX_CONFIG_PATH_DEPTH 4

struct conf_item {
	const char *k;        // item Key
	char **p;             // item Path
	const char *h;        // Help text / description
	const char *a;        // string of Allowed values (where applicable)
	enum conf_type t;     // variable Type
	bool restart_dnsmasq; // De we need to restart the dnsmasq core when this changes?
	union conf_value v;   // current Value
	union conf_value d;   // Default value
};

struct config {
	struct {
		struct conf_item CNAMEdeepInspect;
		struct conf_item blockESNI;
		struct conf_item EDNS0ECS;
		struct conf_item ignoreLocalhost;
		struct conf_item showDNSSEC;
		struct conf_item analyzeAAAA;
		struct conf_item analyzeOnlyAandAAAA;
		struct conf_item piholePTR;
		struct conf_item replyWhenBusy;
		struct conf_item blockTTL;
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
				struct conf_item overwrite_v4;
				struct conf_item overwrite_v6;
				struct conf_item v4;
				struct conf_item v6;
			} host;
			struct {
				struct conf_item overwrite_v4;
				struct conf_item overwrite_v6;
				struct conf_item v4;
				struct conf_item v6;
			} blocking;
		} reply;
		struct {
			struct conf_item count;
			struct conf_item interval;
		} rateLimit;
	} dns;

	struct {
		struct conf_item upstreams;
		struct conf_item domain;
		struct conf_item domain_needed;
		struct conf_item expand_hosts;
		struct conf_item bogus_priv;
		struct conf_item dnssec;
		struct conf_item interface;
		struct conf_item host_record;
		struct conf_item listening_mode;
		struct conf_item cache_size;
		struct {
			struct conf_item active;
			struct conf_item cidr;
			struct conf_item target;
			struct conf_item domain;
		} rev_server;
		struct {
			struct conf_item active;
			struct conf_item start;
			struct conf_item end;
			struct conf_item router;
			struct conf_item leasetime;
			struct conf_item ipv6;
			struct conf_item rapid_commit;
		} dhcp;
	} dnsmasq;

	struct {
		struct conf_item resolveIPv4;
		struct conf_item resolveIPv6;
		struct conf_item networkNames;
		struct conf_item refreshNames;
	} resolver;

	struct {
		struct conf_item DBimport;
		struct conf_item DBexport;
		struct conf_item maxHistory;
		struct conf_item maxDBdays;
		struct conf_item DBinterval;
		struct {
			struct conf_item parseARPcache;
			struct conf_item expire;
		} network;
	} database;

	struct {
		struct conf_item localAPIauth;
		struct conf_item prettyJSON;
		struct conf_item sessionTimeout;
		struct conf_item pwhash;
		struct conf_item exclude_clients;
		struct conf_item exclude_domains;
	} api;

	struct {
		struct conf_item domain;
		struct conf_item acl;
		struct conf_item port;
		struct {
			struct conf_item webroot;
			struct conf_item webhome;
		} paths;
		struct {
			struct conf_item boxed;
			struct conf_item theme;
		} interface;
	} http;

	struct {
		struct conf_item pid;
		struct conf_item database;
		struct conf_item gravity;
		struct conf_item macvendor;
		struct conf_item setupVars;
		struct conf_item http_info;
		struct conf_item ph7_error;
		struct {
			struct conf_item ftl;
			struct conf_item dnsmasq;
		} log;
	} files;

	struct {
		struct conf_item nice;
		struct conf_item delay_startup;
		struct conf_item addr2line;
		struct conf_item privacylevel;
		struct conf_item temp_limit;
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
		struct conf_item extra;
		struct conf_item reserved;
	} debug;
};

extern struct config config;
extern int dns_port;

#define CONFIG_ELEMENTS (sizeof(config)/sizeof(struct conf_item))
#define DEBUG_ELEMENTS (sizeof(config.debug)/sizeof(struct conf_item))

#endif //CONFIG_H
