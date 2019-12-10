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

extern int socketfd, telnetfd4, telnetfd6;
extern unsigned char* pihole_privacylevel;
enum { TCP, UDP };

#define FTL_new_query(flags, name, addr, types, id, type) _FTL_new_query(flags, name, addr, types, id, type, __FILE__, __LINE__)
void _FTL_new_query(const unsigned int flags, const char *name, const struct all_addr *addr, const char *types, const int id, const char type, const char* file, const int line);

#define FTL_forwarded(flags, name, addr, id) _FTL_forwarded(flags, name, addr, id, __FILE__, __LINE__)
void _FTL_forwarded(const unsigned int flags, const char *name, const struct all_addr *addr, const int id, const char* file, const int line);

#define FTL_reply(flags, name, addr, id) _FTL_reply(flags, name, addr, id, __FILE__, __LINE__)
void _FTL_reply(const unsigned short flags, const char *name, const struct all_addr *addr, const int id, const char* file, const int line);

#define FTL_cache(flags, name, addr, arg, id) _FTL_cache(flags, name, addr, arg, id, __FILE__, __LINE__)
void _FTL_cache(const unsigned int flags, const char *name, const struct all_addr *addr, const char * arg, const int id, const char* file, const int line);

#define FTL_dnssec(status, id) _FTL_dnssec(status, id, __FILE__, __LINE__)
void _FTL_dnssec(const int status, const int id, const char* file, const int line);

#define FTL_header_analysis(header4, rcode, id) _FTL_header_analysis(header4, rcode, id, __FILE__, __LINE__)
void _FTL_header_analysis(const unsigned char header4, const unsigned int rcode, const int id, const char* file, const int line);

#define FTL_forwarding_failed(server) _FTL_forwarding_failed(server, __FILE__, __LINE__)
void _FTL_forwarding_failed(const struct server *server, const char* file, const int line);

#define FTL_upstream_error(rcode, id) _FTL_upstream_error(rcode, id, __FILE__, __LINE__)
void _FTL_upstream_error(const unsigned int rcode, const int id, const char* file, const int line);

void FTL_dnsmasq_reload(void);
void FTL_fork_and_bind_sockets(struct passwd *ent_pw);
int FTL_database_import(int cache_size, struct crec **rhash, int hashsz);
void set_debug_dnsmasq_lines(char enabled);

extern char debug_dnsmasq_lines;

#endif // DNSMASQ_INTERFACE_H
