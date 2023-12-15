/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Domain name resolution prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef RESOLVE_H
#define RESOLVE_H

void *DNSclient_thread(void *val);
char *resolveHostname(const char *addr, const bool force) __attribute__((malloc));
bool resolve_names(void) __attribute__((pure));
bool resolve_this_name(const char *ipaddr) __attribute__((pure));

// musl does not define MAXHOSTNAMELEN
// If it is not defined, we set the value
// found on a x86_64 glibc instance
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#endif //RESOLVE_H
