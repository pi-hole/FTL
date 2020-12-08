/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
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

extern int socketfd, telnetfd4, telnetfd6;
extern unsigned char* pihole_privacylevel;
enum protocol { TCP, UDP };

void FTL_next_iface(const char *newiface, const int ifidx, const struct listener *listeners);

#define FTL_new_query(flags, name, blockingreason, addr, types, qtype, id, edns, proto) _FTL_new_query(flags, name, blockingreason, addr, types, qtype, id, edns, proto, __FILE__, __LINE__)
bool _FTL_new_query(const unsigned int flags, const char *name, const char** blockingreason, const union all_addr *addr, const char *types, const unsigned short qtype, const int id, const ednsData *edns, enum protocol proto, const char* file, const int line);

#define FTL_forwarded(flags, name, serv, id) _FTL_forwarded(flags, name, serv, id, __FILE__, __LINE__)
void _FTL_forwarded(const unsigned int flags, const char *name, const struct server *serv, const int id, const char* file, const int line);

#define FTL_reply(flags, name, addr, id) _FTL_reply(flags, name, addr, id, __FILE__, __LINE__)
void _FTL_reply(const unsigned int flags, const char *name, const union all_addr *addr, const int id, const char* file, const int line);

#define FTL_cache(flags, name, addr, arg, id) _FTL_cache(flags, name, addr, arg, id, __FILE__, __LINE__)
void _FTL_cache(const unsigned int flags, const char *name, const union all_addr *addr, const char * arg, const int id, const char* file, const int line);

#define FTL_dnssec(status, id) _FTL_dnssec(status, id, __FILE__, __LINE__)
void _FTL_dnssec(const int status, const int id, const char* file, const int line);

#define FTL_header_analysis(header4, rcode, id) _FTL_header_analysis(header4, rcode, id, __FILE__, __LINE__)
void _FTL_header_analysis(const unsigned char header4, const unsigned int rcode, const int id, const char* file, const int line);

void FTL_forwarding_retried(const struct server *server, const int oldID, const int newID, const bool dnssec);

#define FTL_upstream_error(rcode, id) _FTL_upstream_error(rcode, id, __FILE__, __LINE__)
void _FTL_upstream_error(const unsigned int rcode, const int id, const char* file, const int line);

#define FTL_get_blocking_metadata(addrp, flags) _FTL_get_blocking_metadata(addrp, flags, __FILE__, __LINE__)
void _FTL_get_blocking_metadata(union all_addr **addrp, unsigned int *flags, const char* file, const int line);

#define FTL_check_blocking(queryID, domainID, clientID, blockingreason) _FTL_check_blocking(queryID, domainID, clientID, blockingreason, __FILE__, __LINE__)

#define FTL_CNAME(domain, cpp, id) _FTL_CNAME(domain, cpp, id, __FILE__, __LINE__)
bool _FTL_CNAME(const char *domain, const struct crec *cpp, const int id, const char* file, const int line);

unsigned int FTL_extract_question_flags(struct dns_header *header, const size_t qlen);
void FTL_query_in_progress(const int id);
void FTL_duplicate_reply(const int id, int *firstID);

void FTL_dnsmasq_reload(void);
void FTL_fork_and_bind_sockets(struct passwd *ent_pw);
void FTL_TCP_worker_created(const int confd, const char *iface_name);
void FTL_TCP_worker_terminating(bool finished);

void set_debug_dnsmasq_lines(char enabled);
extern char debug_dnsmasq_lines;

bool FTL_unlink_DHCP_lease(const char *ipaddr);

#endif // DNSMASQ_INTERFACE_H
