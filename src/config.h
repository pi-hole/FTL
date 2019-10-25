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

// typedef int16_t
#include <sys/types.h>

void getLogFilePath(void);
void read_FTLconf(void);
void get_privacy_level(FILE *fp);
void get_blocking_mode(FILE *fp);
void read_debuging_settings(FILE *fp);

typedef struct {
	int maxDBdays;
	int DBinterval;
	int port;
	int maxlogage;
	int dns_port;
	unsigned int delay_startup;
	int16_t debug;
	unsigned char privacylevel;
	unsigned char blockingmode;
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
} ConfigStruct;

typedef struct {
	const char* conf;
	const char* snapConf;
	char* log;
	char* pid;
	char* port;
	char* FTL_db;
	char* gravity_db;
	char* macvendor_db;
	char* setupVars;
	char* auditlist;
} FTLFileNamesStruct;

typedef struct httpsettings {
	char *webroot;
	char port[20]; // enough space for 2*(maximum length of number in a uint16_t = 5 characters) + ",[::]:" + NULL
} httpsettingsStruct;

extern ConfigStruct config;
extern FTLFileNamesStruct FTLfiles;
extern httpsettingsStruct httpsettings;

enum {
  DEBUG_DATABASE      = (1 << 0),  /* 00000000 00000001 */
  DEBUG_NETWORKING    = (1 << 1),  /* 00000000 00000010 */
  DEBUG_LOCKS         = (1 << 2),  /* 00000000 00000100 */
  DEBUG_QUERIES       = (1 << 3),  /* 00000000 00001000 */
  DEBUG_FLAGS         = (1 << 4),  /* 00000000 00010000 */
  DEBUG_SHMEM         = (1 << 5),  /* 00000000 00100000 */
  DEBUG_GC            = (1 << 6),  /* 00000000 01000000 */
  DEBUG_ARP           = (1 << 7),  /* 00000000 10000000 */
  DEBUG_REGEX         = (1 << 8),  /* 00000001 00000000 */
  DEBUG_API           = (1 << 9),  /* 00000010 00000000 */
  DEBUG_OVERTIME      = (1 << 10), /* 00000100 00000000 */
  DEBUG_EXTBLOCKED    = (1 << 11), /* 00001000 00000000 */
  DEBUG_CAPS          = (1 << 12), /* 00010000 00000000 */
  DEBUG_DNSMASQ_LINES = (1 << 13), /* 00100000 00000000 */
  DEBUG_VECTORS       = (1 << 14), /* 01000000 00000000 */
  DEBUG_RESOLVER      = (1 << 15), /* 10000000 00000000 */
};

#endif //CONFIG_H
