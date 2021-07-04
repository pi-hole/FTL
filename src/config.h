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
#include <stdint.h>
// assert_sizeof
#include "static_assert.h"
// struct in_addr, in6_addr
#include <netinet/in.h>

void getLogFilePath(void);
void read_FTLconf(void);
void get_privacy_level(FILE *fp);
void get_blocking_mode(FILE *fp);
void read_debuging_settings(FILE *fp);

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
	bool cname_inspection;
	bool block_esni;
	bool names_from_netdb;
	bool edns0_ecs;
	bool show_dnssec;
	struct {
		bool mozilla_canary :1;
	} special_domains;
	enum privacy_level privacylevel;
	enum blocking_mode blockingmode;
	enum refresh_hostnames refresh_hostnames;
	int maxDBdays;
	int port;
	int maxlogage;
	int dns_port;
	unsigned int delay_startup;
	unsigned int network_expire;
	struct {
		unsigned int count;
		unsigned int interval;
	} rate_limit;
	enum debug_flags debug;
	time_t DBinterval;
	struct {
		bool overwrite_v4 :1;
		bool overwrite_v6 :1;
		struct in_addr v4;
		struct in6_addr v6;
	} reply_addr;
} ConfigStruct;
ASSERT_SIZEOF(ConfigStruct, 88, 84, 84);

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
