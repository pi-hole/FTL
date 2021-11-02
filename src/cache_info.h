/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  FTL cache_info prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef CACHE_INFO_H
#define CACHE_INFO_H

struct cache_info {
  // <cache-size> is obvious
  int cache_size;
  // It means the resolver handled <cache-inserted> names lookups that
  // needed to be sent to upstream servers and that <cache-live-freed>
  // was thrown out of the cache before reaching the end of its
  // time-to-live, to make room for a newer name.
  // For <cache-live-freed>, smaller is better. New queries are always
  // cached. If the cache is full with entries which haven't reached
  // the end of their time-to-live, then the entry which hasn't been
  // looked up for the longest time is evicted.
  int cache_live_freed;
  int cache_inserted;
  // <valid> are cache entries with positive remaining TTL
  struct valid {
    int ipv4;
    int ipv6;
    int cname;
    int srv;
    int ds;
    int dnskey;
    int other;
  } valid;
  // <expired> cache entries (to be removed when space is needed)
  int expired;
  // <immortal> cache records never expire (e.g. from /etc/hosts)
  int immortal;
};

void get_dnsmasq_cache_info(struct cache_info *ci);

#endif // CACHE_INFO_H
