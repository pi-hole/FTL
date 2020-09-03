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
#include "enums.h"

// typedef int16_t
#include <sys/types.h>
// typedef uni32_t
#include <idn-int.h>

void getLogFilePath(void);
void read_FTLconf(void);
void get_privacy_level(FILE *fp);
void get_blocking_mode(FILE *fp);
void read_debuging_settings(FILE *fp);

typedef struct {
	int maxDBdays;
	int port;
	int maxlogage;
	int dns_port;
	unsigned int delay_startup;
	enum debug_flags debug;
	unsigned int network_expire;
	enum privacy_level privacylevel;
	enum blocking_mode blockingmode;
	bool socket_listenlocal;
	bool analyze_AAAA;
	bool resolveIPv6;
	bool resolveIPv4;
	bool ignore_localhost;
	bool analyze_only_A_AAAA;
	bool DBimport;
	bool parse_arp_cache;
	bool cname_inspection;
	bool block_esni;
	bool names_from_netdb;
	bool edns0_ecs;
	time_t DBinterval;
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
extern FTLFileNamesStruct FTLfiles;

#endif //CONFIG_H
