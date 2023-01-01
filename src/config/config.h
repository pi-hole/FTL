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
	struct {
		bool CNAMEdeepInspect;
		bool blockESNI;
		bool EDNS0ECS;
		bool ignoreLocalhost;
		bool showDNSSEC;
		bool analyzeAAAA;
		bool analyzeOnlyAandAAAA;
		enum ptr_type piholePTR;
		enum busy_reply replyWhenBusy;
		unsigned int blockTTL;
		unsigned int port; // set in fork_and_bind.c
		enum blocking_mode blockingmode;
		struct {
			bool mozillaCanary;
			bool iCloudPrivateRelay;
		} specialDomains;
		struct {
			struct {
				bool overwrite_v4 :1;
				bool overwrite_v6 :1;
				struct in_addr v4;
				struct in6_addr v6;
			} host;
			struct {
				bool overwrite_v4 :1;
				bool overwrite_v6 :1;
				struct in_addr v4;
				struct in6_addr v6;
			} blocking;
		} reply;
		struct {
			unsigned int count;
			unsigned int interval;
		} rateLimit;
	} dns;

	struct {
		bool resolveIPv4;
		bool resolveIPv6;
		bool networkNames;
		enum refresh_hostnames refreshNames;
	} resolver;

	struct {
		bool DBimport;
		bool DBexport;
		unsigned int maxHistory;
		int maxDBdays;
		unsigned int DBinterval;
		struct {
			bool parseARPcache;
			unsigned int expire;
		} network;
	} database;

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

	struct {
		int nice;
		unsigned int delay_startup;
		bool addr2line;
		enum privacy_level privacylevel;
		struct {
			bool load;
			unsigned char shmem;
			unsigned char disk;
		} check;
	} misc;

	enum debug_flag debug;
} ConfigStruct;

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
