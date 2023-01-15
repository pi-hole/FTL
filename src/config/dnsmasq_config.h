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

bool write_dnsmasq_config(bool test_config);
bool read_legacy_dhcp_static_config(void);

#endif //DNSMASQ_CONFIG_H
