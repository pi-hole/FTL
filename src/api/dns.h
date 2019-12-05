/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API DNS prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef API_DNS_H
#define API_DNS_H

typedef struct cacheinforecord {
        int cache_size;
        int cache_live_freed;
        int cache_inserted;
} cacheinforecord;

// defined in src/dnsmasq_interface.c
extern void getCacheInformation(cacheinforecord *cacheinfo);

#endif // API_DNS_H