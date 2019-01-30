/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
extern int socketfd, telnetfd4, telnetfd6;
extern unsigned char* pihole_privacylevel;
enum { TCP, UDP };

#define FTL_new_query(flags, name, addr, types, id, type) _FTL_new_query(flags, name, addr, types, id, type, __FILE__, __LINE__)
void _FTL_new_query(unsigned int flags, char *name, struct all_addr *addr, char *types, int id, char type, const char* file, const int line);

#define FTL_forwarded(flags, name, addr, id) _FTL_forwarded(flags, name, addr, id, __FILE__, __LINE__)
void _FTL_forwarded(unsigned int flags, char *name, struct all_addr *addr, int id, const char* file, const int line);

#define FTL_reply(flags, name, addr, id) _FTL_reply(flags, name, addr, id, __FILE__, __LINE__)
void _FTL_reply(unsigned short flags, char *name, struct all_addr *addr, int id, const char* file, const int line);

#define FTL_cache(flags, name, addr, arg, id) _FTL_cache(flags, name, addr, arg, id, __FILE__, __LINE__)
void _FTL_cache(unsigned int flags, char *name, struct all_addr *addr, char * arg, int id, const char* file, const int line);

#define FTL_dnssec(status, id) _FTL_dnssec(status, id, __FILE__, __LINE__)
void _FTL_dnssec(int status, int id, const char* file, const int line);

#define FTL_header_ADbit(header4, rcode, id) _FTL_header_ADbit(header4, rcode, id, __FILE__, __LINE__)
void _FTL_header_ADbit(unsigned char header4, unsigned int rcode, int id, const char* file, const int line);

#define FTL_forwarding_failed(server) _FTL_forwarding_failed(server, __FILE__, __LINE__)
void _FTL_forwarding_failed(struct server *server, const char* file, const int line);

#define FTL_query_error(rcode, id) _FTL_query_error(rcode, id, __FILE__, __LINE__)
void _FTL_query_error(unsigned int rcode, int id, const char* file, const int line);

void FTL_dnsmasq_reload(void);
void FTL_fork_and_bind_sockets(struct passwd *ent_pw);
int FTL_listsfile(char* filename, unsigned int index, FILE *f, int cache_size, struct crec **rhash, int hashsz);
