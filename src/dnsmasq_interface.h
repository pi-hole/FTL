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

extern unsigned char* pihole_privacylevel;
enum protocol { TCP, UDP, INTERNAL };

void FTL_hook(unsigned int flags, const char *name, union all_addr *addr, char *arg, int id, unsigned short type, const char* file, const int line);

#define FTL_iface(iface, addr, addrfamily) _FTL_iface(iface, addr, addrfamily, __FILE__, __LINE__)
void _FTL_iface(struct irec *recviface, const union all_addr *addr, const sa_family_t addrfamily, const char* file, const int line);

#define FTL_new_query(flags, name, addr, arg, qtype, id, edns, proto) _FTL_new_query(flags, name, addr, arg, qtype, id, edns, proto, __FILE__, __LINE__)
bool _FTL_new_query(const unsigned int flags, const char *name, union mysockaddr *addr, char *arg, const unsigned short qtype, const int id, const ednsData *edns, enum protocol proto, const char* file, const int line);

#define FTL_header_analysis(header4, rcode, server, id) _FTL_header_analysis(header4, rcode, server, id, __FILE__, __LINE__)
void _FTL_header_analysis(const unsigned char header4, const unsigned int rcode, const struct server *server, const int id, const char* file, const int line);

void FTL_forwarding_retried(const struct server *server, const int oldID, const int newID, const bool dnssec);

#define FTL_make_answer(header, limit, len, ede) _FTL_make_answer(header, limit, len, ede, __FILE__, __LINE__)
size_t _FTL_make_answer(struct dns_header *header, char *limit, const size_t len, int *ede, const char* file, const int line);

#define FTL_CNAME(dst, src, id) _FTL_CNAME(dst, src, id, __FILE__, __LINE__)
bool _FTL_CNAME(const char *dst, const char *src, const int id, const char* file, const int line);

unsigned int FTL_extract_question_flags(struct dns_header *header, const size_t qlen);
void FTL_query_in_progress(const int id);
void FTL_multiple_replies(const int id, int *firstID);

void FTL_dnsmasq_reload(void);
void FTL_fork_and_bind_sockets(struct passwd *ent_pw);
void FTL_TCP_worker_created(const int confd);
void FTL_TCP_worker_terminating(bool finished);

bool FTL_unlink_DHCP_lease(const char *ipaddr);

// defined in src/dnsmasq/cache.c
extern char *querystr(char *desc, unsigned short type);

#endif // DNSMASQ_INTERFACE_H
