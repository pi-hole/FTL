/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq config writer prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DNSMASQ_CONFIG_H
#define DNSMASQ_CONFIG_H

#include "config/config.h"

#define ERRBUF_SIZE 1024

bool write_dnsmasq_config(struct config *conf, bool test_config, char errbuf[ERRBUF_SIZE]);
int get_lineno_from_string(const char *string);
char *get_dnsmasq_line(const unsigned int lineno);
bool read_legacy_dhcp_static_config(void);
bool read_legacy_cnames_config(void);
bool read_legacy_custom_hosts_config(void);
bool write_custom_list(void);

#define DNSMASQ_PH_CONFIG "/etc/pihole/dnsmasq.conf"
#define DNSMASQ_TEMP_CONF "/etc/pihole/dnsmasq.conf.temp"
#define DNSMASQ_STATIC_LEASES "/etc/pihole/04-pihole-static-dhcp.conf"
#define DNSMASQ_CNAMES "/etc/pihole/05-pihole-custom-cname.conf"
#define DNSMASQ_HOSTSDIR "/etc/pihole/hosts"
#define DNSMASQ_CUSTOM_LIST DNSMASQ_HOSTSDIR"/custom.list"
#define DNSMASQ_CUSTOM_LIST_LEGACY "/etc/pihole/custom.list"
#define DHCPLEASESFILE "/etc/pihole/dhcp.leases"

#endif //DNSMASQ_CONFIG_H
