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
// struct in_addr, in6_addr
#include <netinet/in.h>
// type bool
#include <stdbool.h>
// type FILE
#include <stdio.h>

void init_config_mutex(void);
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
	bool socket_listenlocal :1;
	bool analyze_AAAA :1;
	bool resolveIPv6 :1;
	bool resolveIPv4 :1;
	bool ignore_localhost :1;
	bool analyze_only_A_AAAA :1;
	bool DBimport :1;
	bool DBexport :1;
	bool parse_arp_cache :1;
	bool cname_inspection :1;
	bool block_esni :1;
	bool names_from_netdb :1;
	bool edns0_ecs :1;
	bool show_dnssec :1;
	bool addr2line :1;
	struct {
		bool mozilla_canary :1;
		bool icloud_private_relay :1;
	} special_domains;
	struct {
		bool load :1;
		unsigned char shmem;
		unsigned char disk;
	} check;
	enum privacy_level privacylevel;
	enum blocking_mode blockingmode;
	enum refresh_hostnames refresh_hostnames;
	enum busy_reply reply_when_busy;
	enum ptr_type pihole_ptr;
	int maxDBdays;
	int port;
	int maxlogage;
	int dns_port;
	unsigned int delay_startup;
	unsigned int network_expire;
	unsigned int block_ttl;
	struct {
		unsigned int count;
		unsigned int interval;
	} rate_limit;
	enum debug_flags debug;
	time_t DBinterval;
	struct {
		struct {
			bool overwrite_v4 :1;
			bool overwrite_v6 :1;
			struct in_addr v4;
			struct in6_addr v6;
		} own_host;
		struct {
			bool overwrite_v4 :1;
			bool overwrite_v6 :1;
			struct in_addr v4;
			struct in6_addr v6;
		} ip_blocking;
	} reply_addr;
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
