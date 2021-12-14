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
// assert_sizeof
#include "../static_assert.h"
// struct in_addr, in6_addr
#include <netinet/in.h>

#define GLOBALTOMLPATH "/etc/pihole/pihole-FTL.toml"

void setDefaults(void);
void readFTLconf(void);
bool getLogFilePath(void);

// Defined in toml_reader.c
bool getPrivacyLevel(void);
bool getBlockingMode(void);
bool readDebugSettings(void);
void init_config_mutex(void);

// We do not use bitfields in here as this struct exists only once in memory.
// Accessing bitfields may produce slightly more inefficient code on some
// architectures (such as ARM) and savng a few bit of RAM but bloating up the
// rest of the application each time these fields are accessed is bad.
typedef struct {
	bool socket_listenlocal;
	bool analyze_AAAA;
	bool resolveIPv6;
	bool resolveIPv4;
	bool ignore_localhost;
	bool analyze_only_A_AAAA;
	bool DBimport;
	bool DBexport;
	bool parse_arp_cache;
	bool cname_deep_inspection;
	bool blockESNI;
	bool networkNames;
	bool edns0_ecs;
	bool show_dnssec;
	bool addr2line;
	struct {
		bool mozilla_canary;
		bool icloud_private_relay;
	} special_domains;
	struct {
		bool load;
		unsigned char shmem;
		unsigned char disk;
	} check;
	enum privacy_level privacylevel;
	enum blocking_mode blockingmode;
	enum refresh_hostnames refresh_hostnames;
	enum debug_flag debug;
	int nice;
	enum busy_reply reply_when_busy;
	enum ptr_type pihole_ptr;
	int maxDBdays;
	unsigned int maxHistory;
	unsigned int delay_startup;
	unsigned int DBinterval;
	unsigned int dns_port; // set in fork_and_bind.c
	unsigned int network_expire;
	unsigned int block_ttl;
	struct {
		unsigned int count;
		unsigned int interval;
	} rate_limit;
	struct {
		bool overwrite_v4 :1;
		bool overwrite_v6 :1;
		struct in_addr v4;
		struct in6_addr v6;
	} reply_addr;
	struct {
		bool localAPIauth;
		bool prettyJSON;
		unsigned int sessionTimeout;
		char *domain;
		char *acl;
		char *port;
		struct {
			char *webroot;
			char *webhome;
		} paths;
	} http;
	struct {
		char *log;
		char *pid;
		char *database;
		char *gravity;
		char *macvendor;
		char *setupVars;
		char *http_info;
		char *ph7_error;
	} files;
} ConfigStruct;
//ASSERT_SIZEOF(ConfigStruct, 200, 144, 144);

typedef struct {
	const char* conf;
	const char* snapConf;
	char* log;
	char* pid;
	char* port;
	char* socketfile;
	char* FTL_db;
	char* gravity_db;
	char* macvendor_db;
	char* setupVars;
	char* auditlist;
} FTLFileNamesStruct;

extern ConfigStruct config;
extern ConfigStruct defaults;

#endif //CONFIG_H
