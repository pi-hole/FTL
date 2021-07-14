/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTL_PRIVATE
#include "cache_info.h"

// int cache_inserted, cache_live_freed are defined in dnsmasq/cache.c
void getCacheInformation(cacheinforecord *cacheinfo)
{
	// cache-size - interpretation is obvious
	cacheinfo->cache_size = daemon->cachesize;
	// cache-live-freed - interpretation see below
	cacheinfo->cache_live_freed = daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED];
	// cache-inserted - interpretation see below
	cacheinfo->cache_inserted = daemon->metrics[METRIC_DNS_CACHE_INSERTED];
	// cache-live-freed and cache-inserted:
	// It means the resolver handled <cache-inserted> names lookups that
	// needed to be sent to upstream servers and that <cache-live-freed>
	// was thrown out of the cache before reaching the end of its
	// time-to-live, to make room for a newer name.
	// For <cache-live-freed>, smaller is better. New queries are always
	// cached. If the cache is full with entries which haven't reached
	// the end of their time-to-live, then the entry which hasn't been
	// looked up for the longest time is evicted.
}