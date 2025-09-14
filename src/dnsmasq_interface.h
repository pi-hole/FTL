/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DNSMASQ_INTERFACE_H
#define DNSMASQ_INTERFACE_H

// Including stdbool.h here as it is required for defining the boolean prototype of FTL_new_query
#include <stdbool.h>

#include "edns0.h"
#include "metrics.h"

enum protocol { TCP, UDP, INTERNAL };

void FTL_hook(unsigned int flags, const char *name, const union all_addr *addr, char *arg, int id, unsigned short type, const char *file, const int line);

#define FTL_iface(iface, addr, addrfamily) _FTL_iface(iface, addr, addrfamily, __FILE__, __LINE__)
void _FTL_iface(struct irec *recviface, const union all_addr *addr, const sa_family_t addrfamily, const char *file, const int line);

#define FTL_new_query(flags, name, addr, arg, qtype, id, proto) _FTL_new_query(flags, name, addr, arg, qtype, id, proto, __FILE__, __LINE__)
bool _FTL_new_query(const unsigned int flags, const char *name, union mysockaddr *addr, char *arg, const unsigned short qtype, int id, enum protocol proto, const char *file, const int line);

#define FTL_header_analysis(header, server, id) _FTL_header_analysis(header, server, id, __FILE__, __LINE__)
void _FTL_header_analysis(const struct dns_header *header, const struct server *server, const int id, const char *file, const int line);

#define FTL_check_reply(rcode, flags, addr, id) _FTL_check_reply(rcode, flags, addr, id, __FILE__, __LINE__)
int _FTL_check_reply(const unsigned int rcode, const unsigned short flags, const union all_addr *addr, const int id, const char *file, const int line);

void FTL_forwarding_retried(struct frec *forward, const int newID, const bool dnssec);

#define MAX_EDE_DATA 128
#define FTL_make_answer(header, limit, len, ede_data, ede_len) _FTL_make_answer(header, limit, len, ede_data, ede_len, __FILE__, __LINE__)
size_t _FTL_make_answer(struct dns_header *header, char *limit, const size_t len, unsigned char ede_data[MAX_EDE_DATA], size_t *ede_len, const char *file, const int line);

bool FTL_CNAME(const char *dst, const char *src, const int id);

void FTL_query_in_progress(const int id);
void FTL_multiple_replies(const int id, int *firstID);

void FTL_dnsmasq_reload(void);
void FTL_TCP_worker_created(const int confd);
void FTL_TCP_worker_terminating(bool finished);

bool FTL_unlink_DHCP_lease(const char *ipaddr, const char **hint);

void FTL_connection_error(const char *reason, const union mysockaddr *addr, const char where);

bool get_dnsmasq_debug(void) __attribute__ ((pure));

// defined in src/dnsmasq/cache.c
extern char *querystr(char *desc, unsigned short type);

extern void FTL_dnsmasq_log(const char *payload, const int length);

#endif // DNSMASQ_INTERFACE_H
