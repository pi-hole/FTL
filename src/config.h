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
} ConfigStruct;

extern ConfigStruct config;

#endif //CONFIG_H
