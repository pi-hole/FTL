/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  ARP scanning prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef ARP_SCAN_H
#define ARP_SCAN_H

int run_arp_scan(const bool scan_all, const bool extreme_mode);

#endif // ARP_SCAN_H
