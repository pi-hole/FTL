/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTLDNS
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"
#include "enums.h"
#include "dnsmasq_interface.h"
#include "shmem.h"
#include "overTime.h"
#include "database/common.h"
#include "database/database-thread.h"
#include "datastructure.h"
#include "database/gravity-db.h"
#include "config/setupVars.h"
#include "daemon.h"
#include "timers.h"
#include "gc.h"
#include "regex_r.h"
#include "config/config.h"
#include "capabilities.h"
#include "resolve.h"
#include "files.h"
// add_to_fifo_buffer() u.a.
#include "log.h"
// global variable daemonmode
#include "args.h"
// handle_realtime_signals()
#include "signals.h"
// atomic_flag_test_and_set()
#include <stdatomic.h>
// Eventqueue routines
#include "events.h"
#include <netinet/in.h>
// offsetof()
#include <stddef.h>
// logg_rate_limit_message()
#include "database/message-table.h"
// http_init()
#include "webserver/webserver.h"
// type struct sqlite3_stmt_vec
#include "vector.h"
// init_memory_database()
#include "database/query-table.h"
// reread_config()
#include "config/config.h"
// FTL_fork_and_bind_sockets()
#include "main.h"
// ntp_server_start()
#include "ntp/ntp.h"
// get_process_name()
#include "procps.h"

// Private prototypes
static void print_flags(const unsigned int flags);
#define query_set_reply(flags, reply, addr, query, now) _query_set_reply(flags, reply, addr, query, now, __FILE__, __LINE__)
static void _query_set_reply(const unsigned int flags, const enum reply_type reply, const union all_addr *addr, queriesData *query,
                             const double now, const char *file, const int line);
static bool FTL_check_blocking(const unsigned int queryID, const unsigned int domainID, const unsigned int clientID);
static void query_blocked(queriesData *query, domainsData *domain, clientsData *client, const enum query_status new_status);
static void FTL_forwarded(const unsigned int flags, const char *name, const union all_addr *addr, unsigned short port, const int id, const char *file, const int line);
static void FTL_reply(const unsigned int flags, const char *name, const union all_addr *addr, const char *arg, const int id, const char *file, const int line);
static void FTL_upstream_error(const union all_addr *addr, const unsigned int flags, const int id, const char *file, const int line);
static void FTL_dnssec(const char *result, const union all_addr *addr, const int id, const char *file, const int line);
static void mysockaddr_extract_ip_port(const union mysockaddr *server, char ip[ADDRSTRLEN+1], in_port_t *port);
static void alladdr_extract_ip(union all_addr *addr, const sa_family_t family, char ip[ADDRSTRLEN+1]);
static void check_pihole_PTR(char *domain);
#define query_set_dnssec(query, dnssec) _query_set_dnssec(query, dnssec, __FILE__, __LINE__)
static void _query_set_dnssec(queriesData *query, const enum dnssec_status dnssec, const char *file, const int line);
static char *get_ptrname(const struct in_addr *addr);
static const char *check_dnsmasq_name(const char *name);
static void get_rcode(const unsigned short rcode, const char **rcodestr, enum reply_type *reply);

// Static blocking metadata
static bool aabit = false, adbit = false, rabit = false;
static const char *blockingreason = "";
static enum reply_type force_next_DNS_reply = REPLY_UNKNOWN;
static enum query_status cacheStatus = QUERY_UNKNOWN;
static int last_regex_idx = -1;
static char *pihole_suffix = NULL;
static char *hostname_suffix = NULL;
static char *cname_target = NULL;
#define HOSTNAME "Pi-hole hostname"

// Fork-private copy of the interface data the most recent query came from
static struct {
	bool haveIPv4;
	bool haveIPv6;
	char name[IFNAMSIZ];
	union all_addr addr4;
	union all_addr addr6;
} next_iface = {false, false, "", {}, {}};

// Fork-private copy of the server data the most recent reply came from
static union mysockaddr last_server = {};

const char *flagnames[] = {"F_IMMORTAL ", "F_NAMEP ", "F_REVERSE ", "F_FORWARD ", "F_DHCP ", "F_NEG ", "F_HOSTS ", "F_IPV4 ", "F_IPV6 ", "F_BIGNAME ", "F_NXDOMAIN ", "F_CNAME ", "F_DNSKEY ", "F_CONFIG ", "F_DS ", "F_DNSSECOK ", "F_UPSTREAM ", "F_RRNAME ", "F_SERVER ", "F_QUERY ", "F_NOERR ", "F_AUTH ", "F_DNSSEC ", "F_KEYTAG ", "F_SECSTAT ", "F_NO_RR ", "F_IPSET ", "F_NOEXTRA ", "F_DOMAINSRV", "F_RCODE", "F_RR", "F_STALE" };

void FTL_hook(unsigned int flags, const char *name, const union all_addr *addr, char *arg, int id, unsigned short type, const char *file, const int line)
{
	// Extract filename from path
	const char *path = short_path(file);
	const char *types = (flags & F_RR) ? querystr(arg, type) : "?";
	log_debug(DEBUG_FLAGS, "Processing FTL hook from %s:%d (type: %s, name: \"%s\", id: %i)...", path, line, types, name, id);
	print_flags(flags);

	// The query ID may be negative if this is a TCP query
	if(id < 0)
		id = -id;

	// Check domain name received from dnsmasq
	name = check_dnsmasq_name(name);

	// Note: The order matters here!
	if((flags & F_QUERY) && (flags & F_FORWARD))
		; // New query, handled by FTL_new_query via separate call
	else if(flags & F_FORWARD && flags & F_SERVER)
		// forwarded upstream (type is used to store the upstream port)
		FTL_forwarded(flags, name, addr, type, id, path, line);
	else if(flags == F_SECSTAT)
		// DNSSEC validation result
		FTL_dnssec(arg, addr, id, path, line);
	else if(flags & F_RCODE && !(flags & F_CONFIG) && name && strcasecmp(name, "error") == 0)
		// upstream sent something different than NOERROR or NXDOMAIN
		FTL_upstream_error(addr, flags, id, path, line);
	else if(flags & F_NOEXTRA && flags & F_DNSSEC)
	{
		// This is a new DNSSEC query (dnssec-query[DS])
		if(!config.dns.showDNSSEC.v.b)
			return;

		// Type is overloaded with port since 2d65d55, so we have to
		// derive the real query type from the arg string
		unsigned short qtype = type;
		if(strcmp(arg, "dnssec-query[DNSKEY]") == 0)
		{
			qtype = T_DNSKEY;
			arg = (char*)"dnssec-query";
		}
		else if(strcmp(arg, "dnssec-query[DS]") == 0)
		{
			qtype = T_DS;
			arg = (char*)"dnssec-query";
		}
		else if(strcmp(arg, "dnssec-retry[DNSKEY]") == 0)
		{
			qtype = T_DNSKEY;
			arg = (char*)"dnssec-retry";
		}
		else if(strcmp(arg, "dnssec-retry[DS]") == 0)
		{
			qtype = T_DS;
			arg = (char*)"dnssec-retry";
		}
		else
		{
			arg = (char*)"dnssec-unknown";
		}

		_FTL_new_query(flags, name, NULL, arg, qtype, id, INTERNAL, file, line);
		// forwarded upstream (type is used to store the upstream port)
		FTL_forwarded(flags, name, addr, type, id, path, line);
	}
	else if(flags & F_AUTH)
		; // Ignored
	else if(flags & F_IPSET)
		; // Ignored
	else if(flags == F_UPSTREAM && strcmp(arg, "truncated") == 0)
		; // Ignored - truncated reply
		//
		// flags will by (F_UPSTREAM | F_NOEXTRA) with type being
		// T_DNSKEY or T_DS when this is a truncated DNSSEC reply
		//
		// otherwise, flags will be F_UPSTREAM and the type is not set
		// (== 0)
	else
		FTL_reply(flags, name, addr, arg, id, path, line);
}

// This is inspired by make_local_answer()
size_t _FTL_make_answer(struct dns_header *header, char *limit, const size_t len,
                        unsigned char ede_data[MAX_EDE_DATA], size_t *ede_len,
                        const char *file, const int line)
{
	log_debug(DEBUG_FLAGS, "FTL_make_answer() called from %s:%d", short_path(file), line);
	// Exit early if there are no questions in this query
	if(ntohs(header->qdcount) == 0)
		return 0;

	// Get question name
	char name[MAXDNAME] = { 0 };
	unsigned char *p = (unsigned char *)(header+1);
	if (!extract_name(header, len, &p, name, 1, 4))
		return 0;

	// Debug logging
	log_debug(DEBUG_QUERIES, "Preparing reply for \"%s\"", name);

	// Get question type
	int qtype, flags = 0;
	GETSHORT(qtype, p);

	// Set flags based on what we will reply with
	if(qtype == T_A)
		flags = F_IPV4; // A type
	else if(qtype == T_AAAA)
		flags = F_IPV6; // AAAA type
	else if(qtype == T_ANY)
		flags = F_IPV4 | F_IPV6; // ANY type
	else
		flags = F_NOERR; // empty record

	// Prepare answer records
	bool forced_ip = false;
	// Check first if we need to force our reply to something different than the
	// default/configured blocking mode. For instance, we need to force NXDOMAIN
	// for intercepted _esni.* queries or the Mozilla canary domain.
	if(force_next_DNS_reply == REPLY_NXDOMAIN)
	{
		flags = F_NXDOMAIN;
		// Reset DNS reply forcing
		force_next_DNS_reply = REPLY_UNKNOWN;

		// Debug logging
		log_debug(DEBUG_QUERIES, "Forced DNS reply to NXDOMAIN");
	}
	else if(force_next_DNS_reply == REPLY_NODATA)
	{
		flags = F_NOERR;
		// Reset DNS reply forcing
		force_next_DNS_reply = REPLY_UNKNOWN;

		// Debug logging
		log_debug(DEBUG_QUERIES, "Forced DNS reply to NODATA");
	}
	else if(force_next_DNS_reply == REPLY_REFUSED)
	{
		// Empty flags result in REFUSED
		flags = 0;
		// Reset DNS reply forcing
		force_next_DNS_reply = REPLY_UNKNOWN;

		// Debug logging
		log_debug(DEBUG_QUERIES, "Forced DNS reply to REFUSED");
	}
	else if(force_next_DNS_reply == REPLY_IP)
	{
		// We do not need to change the flags here,
		// they are already properly set (F_IPV4 and/or F_IPV6)
		forced_ip = true;

		// Reset DNS reply forcing
		force_next_DNS_reply = REPLY_UNKNOWN;

		// Debug logging
		log_debug(DEBUG_QUERIES, "Forced DNS reply to IP");
	}
	else if(force_next_DNS_reply == REPLY_NONE)
	{
		// Reset DNS reply forcing
		force_next_DNS_reply = REPLY_UNKNOWN;

		// Debug logging
		log_debug(DEBUG_QUERIES, "Forced DNS reply to NONE - dropping this query");

		return 0;
	}
	else
	{
		// Overwrite flags only if not replying with a forced reply
		if(config.dns.blocking.mode.v.blocking_mode == MODE_NX)
		{
			// If we block in NXDOMAIN mode, we set flags to NXDOMAIN
			// (NEG will be added after setup_reply() below)
			flags = F_NXDOMAIN;
			log_debug(DEBUG_QUERIES, "Configured blocking mode is NXDOMAIN");
		}
		else if(config.dns.blocking.mode.v.blocking_mode == MODE_NODATA ||
				(config.dns.blocking.mode.v.blocking_mode == MODE_IP_NODATA_AAAA && (flags & F_IPV6)))
		{
			// If we block in NODATA mode or NODATA for AAAA queries, we apply
			// the NOERROR response flag. This ensures we're sending an empty response
			flags = F_NOERR;
			log_debug(DEBUG_QUERIES, "Configured blocking mode is NODATA%s",
				     config.dns.blocking.mode.v.blocking_mode == MODE_IP_NODATA_AAAA ? "-IPv6" : "");
		}
	}

	// Check for regex redirecting
	bool redirecting = false;
	union all_addr redirect_addr4 = {}, redirect_addr6 = {};
	if(last_regex_idx > -1)
	{
		redirecting = regex_get_redirect(last_regex_idx, &redirect_addr4.addr4, &redirect_addr6.addr6);
		// Reset regex redirection forcing
		last_regex_idx = -1;

		// Debug logging
		log_debug(DEBUG_QUERIES, "Regex match is %sredirected", redirecting ? "" : "NOT ");
	}

	if(force_next_DNS_reply == REPLY_CNAME && cname_target != NULL)
	{
		// Set flags to CNAME reply
		flags = F_CONFIG | F_CNAME;

		// Add A record (if available)
		if(redirect_addr4.addr4.s_addr != 0)
			flags |= F_IPV4;

		// Add AAAA record (if available)
		if(!IN6_IS_ADDR_UNSPECIFIED(&redirect_addr6.addr6))
			flags |= F_IPV6;

		// Reset DNS reply forcing
		force_next_DNS_reply = REPLY_UNKNOWN;
	}

	// Derive EDE code and text from cacheStatus
	int ede_code = EDE_UNSET;
	const char *ede_text = NULL;
	switch(cacheStatus)
	{
		case QUERY_UNKNOWN:
//		case QUERY_CACHE:
		case QUERY_FORWARDED:
		case QUERY_RETRIED:
		case QUERY_RETRIED_DNSSEC:
		case QUERY_IN_PROGRESS:
		case QUERY_DBBUSY:
		case QUERY_CACHE_STALE:
		case QUERY_STATUS_MAX:
			// Not going through this function
			break;
		case QUERY_GRAVITY:
			ede_code = EDE_BLOCKED;
			ede_text = "gravity";
			break;
		case QUERY_GRAVITY_CNAME:
			ede_code = EDE_BLOCKED;
			ede_text = "gravity (CNAME)";
			break;
		case QUERY_DENYLIST:
			ede_code = EDE_BLOCKED;
			ede_text = "denylist";
			break;
		case QUERY_DENYLIST_CNAME:
			ede_code = EDE_BLOCKED;
			ede_text = "denylist (CNAME)";
			break;
		case QUERY_REGEX:
			ede_code = EDE_BLOCKED;
			ede_text = "regex";
			break;
		case QUERY_REGEX_CNAME:
			ede_code = EDE_BLOCKED;
			ede_text = "regex (CNAME)";
			break;
		case QUERY_SPECIAL_DOMAIN:
			ede_code = EDE_BLOCKED;
			ede_text = "special";
			break;
		case QUERY_EXTERNAL_BLOCKED_NXRA:
			ede_code = EDE_BLOCKED;
			ede_text = "upstream NXRA";
			break;
		case QUERY_EXTERNAL_BLOCKED_NULL:
			ede_code = EDE_BLOCKED;
			ede_text = "upstream NULL";
			break;
		case QUERY_EXTERNAL_BLOCKED_IP:
			ede_code = EDE_BLOCKED;
			ede_text = "upstream IP";
			break;
		case QUERY_EXTERNAL_BLOCKED_EDE15:
			ede_code = EDE_BLOCKED;
			ede_text = "upstream EDE 15";
			break;
		case QUERY_CACHE:
			ede_code = EDE_SYNTHESIZED;
			ede_text = "synthesized";
			break;
	}

	// Reset global DNS cache status
	cacheStatus = QUERY_UNKNOWN;

	// Debug logging
	log_debug(DEBUG_QUERIES, "Setting EDE: %s (%d) + \"%s\"",
	          ede_code != EDE_UNSET ? edestr(ede_code) : "---", ede_code, ede_text ? ede_text : "---");

	if(ede_code != EDE_UNSET && config.dns.blocking.edns.v.edns_mode > EDNS_MODE_NONE)
	{
		// Set EDE INFO-CODE (network byte order)
		uint16_t swap = htons(ede_code);
		memcpy(ede_data, &swap, sizeof(swap));
		*ede_len = sizeof(swap);

		// Set EDE INFO-TEXT (if available)
		if(ede_text && config.dns.blocking.edns.v.edns_mode > EDNS_MODE_CODE)
		{
			size_t extra_len = strlen(ede_text);
			// Truncate if necessary
			if(extra_len > MAX_EDE_DATA - *ede_len)
				extra_len = MAX_EDE_DATA - *ede_len;
			memcpy(ede_data + *ede_len, ede_text, extra_len);
			*ede_len += extra_len;
		}
	}

	// Debug logging
	print_flags(flags);

	// Setup reply header
	setup_reply(header, flags, ede_code);

	// Add NEG flag when replying with NXDOMAIN or NODATA. This is necessary
	// to get proper logging in pihole.log At the same time, we cannot add
	// NEG before calling setup_reply() as it would, otherwise, result in an
	// incorrect "nowhere to forward to" log entry (because setup_reply()
	// checks for equality of flags instead of doing a bitmask comparison).
	if(flags == F_NXDOMAIN || flags == F_NOERR)
		flags |= F_NEG;

	// Add flags according to current blocking mode
	// Set blocking_flags to F_HOSTS so dnsmasq logs blocked queries being answered from a specific source
	// (it would otherwise assume it knew the blocking status from cache which would prevent us from
	// printing the blocking source (blacklist, regex, gravity) in dnsmasq's log file, our pihole.log)
	if(flags != 0)
		flags |= F_HOSTS;

	// Skip questions so we can start adding answers (if applicable)
	if (!(p = skip_questions(header, len)))
		return 0;

	// Are we replying to pi.hole / <hostname> / pi.hole.<local> / <hostname>.<local> ?
	const bool hostn = strcmp(blockingreason, HOSTNAME) == 0;

	int trunc = 0;
	// Add CNAME answer record if requested
	if(flags & F_CNAME)
	{
		// Debug logging
		if(config.debug.queries.v.b)
			log_debug(DEBUG_QUERIES, "  Adding RR: \"%s CNAME %s\"", name, cname_target);

		// Add CNAME resource record
		header->ancount = htons(ntohs(header->ancount) + 1);
		if(add_resource_record(header, limit, &trunc, sizeof(struct dns_header),
		                       &p, daemon->local_ttl, NULL,
		                       T_CNAME, C_IN, (char*)"d", cname_target))
			log_query(flags, name, NULL, (char*)blockingreason, 0);
	}

	// Add A answer record if requested
	if(flags & F_IPV4)
	{
		union all_addr addr = {};

		// Overwrite with IP address if requested
		if(redirecting)
		{
			log_debug(DEBUG_QUERIES, "Using regex redirected A address");
			memcpy(&addr, &redirect_addr4, sizeof(addr));
		}
		else if(config.dns.blocking.mode.v.blocking_mode == MODE_IP ||
		        config.dns.blocking.mode.v.blocking_mode == MODE_IP_NODATA_AAAA ||
		        forced_ip)
		{
			if(hostn && config.dns.reply.host.force4.v.b)
			{
				log_debug(DEBUG_QUERIES, "Using dns.reply.host.force4");
				memcpy(&addr, &config.dns.reply.host.v4.v.in_addr, sizeof(addr.addr4));
			}
			else if(!hostn && config.dns.reply.blocking.force4.v.b)
			{
				log_debug(DEBUG_QUERIES, "Using dns.reply.blocking.force4");
				memcpy(&addr, &config.dns.reply.blocking.v4.v.in_addr, sizeof(addr.addr4));
			}
			else
			{
				log_debug(DEBUG_QUERIES, "Using next_iface A address");
				memcpy(&addr, &next_iface.addr4, sizeof(addr.addr4));
			}
		}

		// Debug logging
		if(config.debug.queries.v.b)
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			alladdr_extract_ip(&addr, AF_INET, ip);
			log_debug(DEBUG_QUERIES, "  Adding RR: \"%s A %s\"", name, ip);
		}

		// Add A resource record
		header->ancount = htons(ntohs(header->ancount) + 1);
		if(add_resource_record(header, limit, &trunc, sizeof(struct dns_header),
		                       &p, hostn ? daemon->local_ttl : config.dns.blockTTL.v.ui,
		                       NULL, T_A, C_IN, (char*)"4", &addr.addr4))
			log_query(flags & ~F_IPV6, name, &addr, (char*)blockingreason, 0);
	}

	// Add AAAA answer record if requested
	if(flags & F_IPV6)
	{
		union all_addr addr = {};

		// Overwrite with IP address if requested
		if(redirecting)
		{
			log_debug(DEBUG_QUERIES, "Using regex redirected AAAA address");
			memcpy(&addr, &redirect_addr6, sizeof(addr));
		}
		else if(config.dns.blocking.mode.v.blocking_mode == MODE_IP ||
		        forced_ip)
		{
			if(hostn && config.dns.reply.host.force6.v.b)
			{
				log_debug(DEBUG_QUERIES, "Using dns.reply.host.force6");
				memcpy(&addr, &config.dns.reply.host.v6.v.in6_addr, sizeof(addr.addr6));
			}
			else if(!hostn && config.dns.reply.blocking.force6.v.b)
			{
				log_debug(DEBUG_QUERIES, "Using dns.reply.blocking.force6");
				memcpy(&addr, &config.dns.reply.blocking.v6.v.in6_addr, sizeof(addr.addr6));
			}
			else
			{
				log_debug(DEBUG_QUERIES, "Using next_iface AAAA address");
				memcpy(&addr, &next_iface.addr6, sizeof(addr.addr6));
			}
		}

		// Debug logging
		if(config.debug.queries.v.b)
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			alladdr_extract_ip(&addr, AF_INET6, ip);
			log_debug(DEBUG_QUERIES, "  Adding RR: \"%s AAAA %s\"", name, ip);
		}

		// Add AAAA resource record
		header->ancount = htons(ntohs(header->ancount) + 1);
		if(add_resource_record(header, limit, &trunc, sizeof(struct dns_header),
		                       &p, hostn ? daemon->local_ttl : config.dns.blockTTL.v.ui,
		                       NULL, T_AAAA, C_IN, (char*)"6", &addr.addr6))
			log_query(flags & ~F_IPV4, name, &addr, (char*)blockingreason, 0);
	}

	// Log empty replies
	if(!(flags & (F_IPV4 | F_IPV6)))
	{
		if(flags == 0)
		{
			// REFUSED
			union all_addr addr = {};
			addr.log.rcode = REFUSED;
			addr.log.ede = EDE_BLOCKED;
			log_query(F_RCODE | F_HOSTS, name, &addr, (char*)blockingreason, 0);
		}
		else
		{
			// NODATA/NXDOMAIN
			// gravity blocked abc.com is NODATA/NXDOMAIN
			log_query(flags, name, NULL, (char*)blockingreason, 0);
		}
	}

	// Indicate if truncated (client should retry over TCP)
	if (trunc)
		header->hb3 |= HB3_TC;

	// Unset the blocking reason
	blockingreason = "<not set>";

	return p - (unsigned char *)header;
}

static bool is_pihole_domain(const char *domain)
{
	if(!pihole_suffix && daemon->domain_suffix)
	{
		// Build "pi.hole.<local suffix>" domain
		pihole_suffix = calloc(strlen(daemon->domain_suffix) + 9, sizeof(char));
		strcpy(pihole_suffix, "pi.hole.");
		strcat(pihole_suffix, daemon->domain_suffix);
		log_debug(DEBUG_QUERIES, "Domain suffix is \"%s\"", daemon->domain_suffix);
	}
	if(!hostname_suffix && daemon->domain_suffix)
	{
		// Build "<hostname>.<local suffix>" domain
		hostname_suffix = calloc(strlen(hostname()) + strlen(daemon->domain_suffix) + 2, sizeof(char));
		strcpy(hostname_suffix, hostname());
		strcat(hostname_suffix, ".");
		strcat(hostname_suffix, daemon->domain_suffix);
	}
	return strcasecmp(domain, "pi.hole") == 0 || strcasecmp(domain, hostname()) == 0 ||
	       (pihole_suffix && strcasecmp(domain, pihole_suffix) == 0) ||
	       (hostname_suffix && strcasecmp(domain, hostname_suffix) == 0);
}

bool _FTL_new_query(const unsigned int flags, const char *name,
                    union mysockaddr *addr, char *arg,
                    const unsigned short qtype, int id,
                    enum protocol proto,
                    const char *file, const int line)
{
	// Create new query in data structure

	// Get timestamp
	const double querytimestamp = double_time();

	// Save request time
	struct timeval request;
	gettimeofday(&request, 0);

	// Determine query type
	enum query_type querytype;
	switch(qtype)
	{
		case 0:
			// Non-query, e.g., zone update
			// dnsmasq does not support such non-queries. RFC5625
			// does not specify how a resolver should behave when it
			// does not support them. dnsmasq decided to reply with
			// a NOTIMP reply to such non-queries
			querytype = TYPE_NONE;
			break;
		case T_A:
			querytype = TYPE_A;
			break;
		case T_AAAA:
			querytype = TYPE_AAAA;
			break;
		case T_ANY:
			querytype = TYPE_ANY;
			break;
		case T_SRV:
			querytype = TYPE_SRV;
			break;
		case T_SOA:
			querytype = TYPE_SOA;
			break;
		case T_PTR:
			querytype = TYPE_PTR;
			break;
		case T_TXT:
			querytype = TYPE_TXT;
			break;
		case T_NAPTR:
			querytype = TYPE_NAPTR;
			break;
		case T_MX:
			querytype = TYPE_MX;
			break;
		case T_DS:
			querytype = TYPE_DS;
			break;
		case T_RRSIG:
			querytype = TYPE_RRSIG;
			break;
		case T_DNSKEY:
			querytype = TYPE_DNSKEY;
			break;
		case T_NS:
			querytype = TYPE_NS;
			break;
		case 64: // Scn. 2 of https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
			querytype = TYPE_SVCB;
			break;
		case 65: // Scn. 2 of https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/
			querytype = TYPE_HTTPS;
			break;
		default:
			querytype = TYPE_OTHER;
			break;
	}

	// Check domain name received from dnsmasq
	name = check_dnsmasq_name(name);

	// If domain is "pi.hole" or the local hostname we skip analyzing this query
	// and, instead, immediately reply with the IP address - these queries are not further analyzed
	if(querytype != TYPE_NONE && is_pihole_domain(name))
	{
		if(querytype == TYPE_A || querytype == TYPE_AAAA || querytype == TYPE_ANY)
		{
			// "Block" this query by sending the interface IP address
			// Send NODATA when the current interface doesn't have
			// the requested IP address, for instance AAAA on an
			// virtual interface that has only an IPv4 address
			if((querytype == TYPE_A &&
			    !next_iface.haveIPv4 &&
			    !config.dns.reply.host.force4.v.b) ||
			   (querytype == TYPE_AAAA &&
			    !next_iface.haveIPv6 &&
			    !config.dns.reply.host.force6.v.b))
				force_next_DNS_reply = REPLY_NODATA;
			else
				force_next_DNS_reply = REPLY_IP;

			blockingreason = HOSTNAME;

			log_debug(DEBUG_QUERIES, "Replying to %s with %s", name,
			          force_next_DNS_reply == REPLY_IP ?
			            "interface-local IP address" :
			            "NODATA due to missing iface address");

			cacheStatus = QUERY_CACHE;
			return true;
		}
		else
		{
			// Don't block this query
			return false;
		}
	}

	// Check if this is a PTR request for a local interface.
	// If so, we inject a "pi.hole" reply here
	if(querytype == TYPE_PTR && config.dns.piholePTR.v.ptr_type != PTR_NONE)
		check_pihole_PTR((char*)name);

	// Convert domain to lower case
	char domainString[MAXDOMAINLEN];
	strncpy(domainString, name, sizeof(domainString));
	domainString[sizeof(domainString) - 1] = '\0';
	strtolower(domainString);

	// Get client IP address
	// The requestor's IP address can be rewritten using EDNS(0) client
	// subnet (ECS) data), however, we do not rewrite the IPs ::1 and
	// 127.0.0.1 to avoid queries originating from localhost of the
	// *distant* machine as queries coming from the *local* machine
	const sa_family_t family = addr ? addr->sa.sa_family : AF_INET;
	in_port_t clientPort = daemon->port;
	bool internal_query = false;
	char clientIP[ADDRSTRLEN+1] = { 0 };
	ednsData *edns = getEDNS();
	if(config.dns.EDNS0ECS.v.b && edns && edns->client_set)
	{
		// Use ECS provided client
		strncpy(clientIP, edns->client, ADDRSTRLEN);
		clientIP[ADDRSTRLEN] = '\0';
	}
	else if(addr)
	{
		// Use original requestor
		mysockaddr_extract_ip_port(addr, clientIP, &clientPort);
	}
	else
	{
		// No client address available, this is an automatically generated (e.g.
		// DNSSEC) query
		internal_query = true;
		strcpy(clientIP, "::");
	}

	// Check if user wants to skip queries coming from localhost
	if(config.dns.ignoreLocalhost.v.b &&
	   (strcmp(clientIP, "127.0.0.1") == 0 || strcmp(clientIP, "::1") == 0))
		return false;

	// Lock shared memory
	lock_shm();
	const int queryID = counters->queries;

	// Find client IP
	const int clientID = findClientID(clientIP, true, false, querytimestamp);

	// Get client pointer
	clientsData *client = getClient(clientID, true);
	if(client == NULL)
	{
		// Encountered memory error, skip query
		// Release thread lock
		unlock_shm();
		return false;
	}

	// Update rolling window of queries per second
	update_qps(querytimestamp);

	// Interface name is only available for regular queries, not for
	// automatically generated DNSSEC queries
	const char *interface = internal_query ? "-" : next_iface.name;

	// Check rate-limit for this client
	if(!internal_query && config.dns.rateLimit.count.v.ui > 0 &&
	   (++client->rate_limit > config.dns.rateLimit.count.v.ui  || client->flags.rate_limited))
	{
		if(!client->flags.rate_limited)
		{
			// Log the first rate-limited query for this client in
			// this interval. We do not log the blocked domain for
			// privacy reasons
			logg_rate_limit_message(clientIP, client->rate_limit);
			// Reset rate-limiting counter so we can count what
			// comes within the adjacent interval
			client->rate_limit = 0;
		}

		// Memorize this client needs rate-limiting
		client->flags.rate_limited = true;

		// Block this query
		force_next_DNS_reply = REPLY_REFUSED;
		blockingreason = "Rate-limiting";

		// Do not further process this query, Pi-hole has never seen it
		unlock_shm();
		return true;
	}

	// The query ID is negative if this is a TCP query
	if(id < 0)
	{
		id = -id;

		// Safety check: If the query ID is negative, the protocol
		// should be TCP
		if(proto != TCP)
		{
			proto = TCP;
			log_debug(DEBUG_ANY, "Query %d has negative ID, but protocol is not TCP", id);
		}
	}

	// Log new query if in debug mode
	if(config.debug.queries.v.b)
	{
		const char *types = querystr(arg, qtype);
		log_debug(DEBUG_QUERIES, "**** new %sIPv%d %s%s \"%s\" from %s/%s#%d (ID %i, FTL %i, %s:%i)",
		          proto == TCP ? "TCP " : proto == UDP ? "UDP " : "", family == AF_INET ? 4 : 6,
		          types, querytype == TYPE_NONE ? "" : " query", name, interface,
		          internal_query ? "<internal>" : clientIP, clientPort,
		          id, queryID, short_path(file), line);
	}

	// Update overTime
	const unsigned int timeidx = getOverTimeID(querytimestamp);

	// Skip rest of the analysis if this query is not of type A or AAAA
	// but user wants to see only A and AAAA queries (pre-v4.1 behavior)
	if(config.dns.analyzeOnlyAandAAAA.v.b && querytype != TYPE_A && querytype != TYPE_AAAA)
	{
		// Don't process this query further here, we already counted it
		if(config.debug.queries.v.b)
			log_debug(DEBUG_QUERIES, "Skipping new query (%i)", id);

		unlock_shm();
		return false;
	}

	// Go through already knows domains and see if it is one of them
	const int domainID = findDomainID(domainString, true);

	// Save everything
	queriesData *query = getQuery(queryID, false);
	if(query == NULL)
	{
		// Encountered memory error, skip query
		log_err("No memory available, skipping query analysis");
		// Release thread lock
		unlock_shm();
		return false;
	}

	// Fill query object with available data
	query->magic = MAGICBYTE;
	query->timestamp = querytimestamp;
	query->type = querytype;
	counters->querytype[querytype]++;
	log_debug(DEBUG_STATUS, "query type %d set (new query), ID = %d, new count = %u", query->type, id, counters->querytype[query->type]);
	query->qtype = qtype;
	query->id = id; // Has to be set before calling query_set_status()

	// This query is unknown as long as no reply has been found and analyzed
	query_set_status_init(query, QUERY_UNKNOWN);
	query->domainID = domainID;
	query->clientID = clientID;
	// Initialize database field, will be set when the query is stored in the long-term DB
	query->flags.database.stored = false;
	query->flags.database.changed = true;
	query->flags.complete = false;
	query->response = querytimestamp;
	query->flags.response_calculated = false;
	// Initialize reply type
	query->reply = REPLY_UNKNOWN;
	counters->reply[REPLY_UNKNOWN]++;
	log_debug(DEBUG_STATUS, "reply type %u set (new query), ID = %d, new count = %u", query->reply, query->id, counters->reply[query->reply]);
	// Store DNSSEC result for this domain
	query->dnssec = DNSSEC_UNKNOWN;
	query->CNAME_domainID = -1;
	// This query is not yet known ad forwarded or blocked
	query->flags.blocked = false;
	query->flags.allowed = false;

	// Indicator that this query was not forwarded so far
	query->upstreamID = -1;

	// Check and apply possible privacy level rules
	// The currently set privacy level (at the time the query is
	// generated) is stored in the queries structure
	query->privacylevel = config.misc.privacylevel.v.privacy_level;

	// Query extended DNS error
	query->ede = EDE_UNSET;

	// Initialize cache ID, may be reusing an existing one if this
	// (domain,client,type) tuple was already seen before
	query->cacheID = findCacheID(domainID, clientID, querytype, true);

	// This query is new and not yet known to the database
	query->db = -1;

	// Increase DNS queries counter
	counters->queries++;

	// Update overTime data structure with the new client
	change_clientcount(client, 0, 0, timeidx, 1);

	// Set lastQuery timer and add one query for network table
	client->lastQuery = querytimestamp;
	client->numQueriesARP++;

	// Update domain's last query time
	domainsData *domain = getDomain(domainID, false);
	if(domain != NULL)
		domain->lastQuery = querytimestamp;

	// Process interface information of client (if available)
	// Skip interface name length 1 to skip "-". No real interface should
	// have a name with a length of 1...
	if(!internal_query && strlen(interface) > 1)
	{
		if(client->ifacepos == 0u)
		{
			// Store in the client data if unknown so far
			client->ifacepos = addstr(interface);
		}
		else
		{
			// Check if this is still the same interface or
			// if the client moved to another interface
			// (may require group re-processing)
			const char *oldiface = getstr(client->ifacepos);
			if(strcasecmp(oldiface, interface) != 0)
			{
				if(config.debug.clients.v.b)
				{
					const char *clientName = getstr(client->namepos);
					log_debug(DEBUG_CLIENTS, "Client %s (%s) changed interface: %s -> %s",
					          clientIP, clientName, oldiface, interface);
				}

				gravityDB_reload_groups(client);
			}
		}
	}

	// Set client MAC address from EDNS(0) information (if available)
	if(config.dns.EDNS0ECS.v.b && edns && edns->mac_set)
	{
		memcpy(client->hwaddr, edns->mac_byte, 6);
		client->hwlen = 6;
	}

	// Try to obtain MAC address from dnsmasq's cache (also asks the kernel)
	// Don't do this for internally generated queries (e.g., DNSSEC), if the
	// MAC address is already known or if the netlink socket is not available
	// (e.g., when retrying a query using TCP after UDP truncation)
	if(!internal_query && client->hwlen < 1 && daemon->netlinkfd > 0)
	{
		client->hwlen = find_mac(addr, client->hwaddr, 1, time(NULL));
		if(config.debug.arp.v.b)
		{
			if(client->hwlen == 6)
			{
				log_debug(DEBUG_ARP, "find_mac(\"%s\") returned hardware address "
				          "%02X:%02X:%02X:%02X:%02X:%02X", clientIP,
				          client->hwaddr[0], client->hwaddr[1], client->hwaddr[2],
				          client->hwaddr[3], client->hwaddr[4], client->hwaddr[5]);
			}
			else
			{
				log_debug(DEBUG_ARP, "find_mac(\"%s\") returned %i bytes of data",
				          clientIP, client->hwlen);
			}
		}
	}

	bool blockDomain = false;
	// Check if this should be blocked only for active queries
	// (skipped for internally generated ones, e.g., DNSSEC)
	if(!internal_query && querytype != TYPE_NONE)
		blockDomain = FTL_check_blocking(queryID, domainID, clientID);

	// Store query in database
	query->flags.database.changed = true;

	// Release thread lock
	unlock_shm();

	return blockDomain;
}

void _FTL_iface(struct irec *recviface, const union all_addr *addr, const sa_family_t addrfamily,
                const char *file, const int line)
{
	// Invalidate data we have from the last interface/query
	// Set addresses to 0.0.0.0 and ::, respectively
	memset(&next_iface.addr4, 0, sizeof(next_iface.addr4));
	memset(&next_iface.addr6, 0, sizeof(next_iface.addr6));
	next_iface.haveIPv4 = next_iface.haveIPv6 = false;

	// Debug logging
	log_debug(DEBUG_NETWORKING, "Interfaces: Called from %s:%d", short_path(file), line);

	// Use dummy when interface record is not available
	next_iface.name[0] = '-';
	next_iface.name[1] = '\0';

	// Check if we need to identify the receiving interface by its address
	if(!recviface && addr &&
	   ((addrfamily == AF_INET && addr->addr4.s_addr != INADDR_ANY) ||
	    (addrfamily == AF_INET6 && !IN6_IS_ADDR_UNSPECIFIED(&addr->addr6))))
	{
		if(config.debug.networking.v.b)
		{
			char addrstr[INET6_ADDRSTRLEN] = { 0 };
			if(addrfamily == AF_INET)
				inet_ntop(AF_INET, &addr->addr4, addrstr, INET6_ADDRSTRLEN);
			else // if(addrfamily == AF_INET6)
				inet_ntop(AF_INET6, &addr->addr6, addrstr, INET6_ADDRSTRLEN);

			log_debug(DEBUG_NETWORKING, "Identifying interface (looking for %s):", addrstr);
		}

		// Loop over interfaces and try to find match
		for (struct irec *iface = daemon->interfaces; iface; iface = iface->next)
		{
			char addrstr[INET6_ADDRSTRLEN] = { 0 };
			const char *iname = iface->slabel ? iface->slabel : iface->name;
			if(iface->addr.sa.sa_family == AF_INET)
			{
				if(config.debug.networking.v.b)
				{
					inet_ntop(AF_INET, &iface->addr.in.sin_addr, addrstr, INET6_ADDRSTRLEN);
					log_debug(DEBUG_NETWORKING, "  - IPv4 interface %s (%d,%d) is %s",
					          iname, iface->index, iface->label, addrstr);
				}

				if(iface->addr.in.sin_addr.s_addr == addr->addr4.s_addr)
				{
					// Set receiving interface
					recviface = iface;
					break;
				}
			}
			else if(iface->addr.sa.sa_family == AF_INET6)
			{
				if(config.debug.networking.v.b)
				{
					inet_ntop(AF_INET6, &iface->addr.in6.sin6_addr, addrstr, INET6_ADDRSTRLEN);
					log_debug(DEBUG_NETWORKING, "  - IPv6 interface %s (%d,%d) is %s",
					          iname, iface->index, iface->label, addrstr);
				}

				if(IN6_ARE_ADDR_EQUAL(&iface->addr.in6.sin6_addr, &addr->addr6))
				{
					// Set receiving interface
					recviface = iface;
					break;
				}
			}
		}

		log_debug(DEBUG_NETWORKING, recviface ?
		                            "    ^^^^^ MATCH ^^^^^" :
		                            "    --> NO MATCH <--");
	}

	// Return early when there is no interface available at this point
	// This means we didn't get one passed + we didn't find one above
	if(!recviface)
	{
		log_debug(DEBUG_NETWORKING, "No receiving interface available at this point");
		return;
	}

	// Determine addresses of this interface, we have to loop over all interfaces as
	// recviface will always only contain *either* IPv4 or IPv6 information
	bool haveGUAv6 = false, haveULAv6 = false;
	log_debug(DEBUG_NETWORKING, "Analyzing interfaces:");
	for (struct irec *iface = daemon->interfaces; iface != NULL; iface = iface->next)
	{
		const sa_family_t family = iface->addr.sa.sa_family;
		const char *iname = iface->slabel ? iface->slabel : iface->name;
		// If this interface has no name, we skip it
		if(iname == NULL)
		{
			if(config.debug.networking.v.b)
				log_debug(DEBUG_NETWORKING, "  - SKIP IPv%d interface (%d,%d): no name",
				     family == AF_INET ? 4 : 6, iface->index, iface->label);
			continue;
		}

		// Check if this is the interface we want
		if(iface->index != recviface->index || iface->label != recviface->label)
		{
			if(config.debug.networking.v.b)
				log_debug(DEBUG_NETWORKING, "  - SKIP IPv%d interface %s: (%d,%d) != (%d,%d)",
				     family == AF_INET ? 4 : 6, iname, iface->index, iface->label,
				     recviface->index, recviface->label);
			continue;
		}

		// *** If we reach this point, we know this interface is the one we are looking for ***//

		// Copy interface name
		strncpy(next_iface.name, iname, sizeof(next_iface.name)-1);
		next_iface.name[sizeof(next_iface.name)-1] = '\0';

		bool isULA = false, isGUA = false, isLL = false;
		// Check if this address is different from 0000:0000:0000:0000:0000:0000:0000:0000
		if(family == AF_INET6 && memcmp(&next_iface.addr6.addr6, &iface->addr.in6.sin6_addr, sizeof(iface->addr.in6.sin6_addr)) != 0)
		{
			// Extract first byte
			// We do not directly access the underlying union as
			// MUSL defines it differently than GNU C
			uint8_t bytes[2];
			memcpy(&bytes, &iface->addr.in6.sin6_addr, 2);
			// Global Unicast Address (2000::/3, RFC 4291)
			isGUA = (bytes[0] & 0x70) == 0x20;
			// Unique Local Address   (fc00::/7, RFC 4193)
			isULA = (bytes[0] & 0xfe) == 0xfc;
			// Link Local Address   (fe80::/10, RFC 4291)
			isLL = (bytes[0] & 0xff) == 0xfe && (bytes[1] & 0x30) == 0;
			// Store IPv6 address only if we don't already have a GUA or ULA address
			// This makes the preference:
			//  1. ULA
			//  2. GUA
			//  3. Link-local
			if((!haveGUAv6 && !haveULAv6) || (haveGUAv6 && isULA))
			{
				next_iface.haveIPv6 = true;
				// Store IPv6 address
				memcpy(&next_iface.addr6.addr6, &iface->addr.in6.sin6_addr, sizeof(iface->addr.in6.sin6_addr));
				if(isGUA)
					haveGUAv6 = true;
				else if(isULA)
					haveULAv6 = true;
			}
		}
		// Check if this address is different from 0.0.0.0
		else if(family == AF_INET && memcmp(&next_iface.addr4.addr4, &iface->addr.in.sin_addr, sizeof(iface->addr.in.sin_addr)) != 0)
		{
			next_iface.haveIPv4 = true;
			// Store IPv4 address
			memcpy(&next_iface.addr4.addr4, &iface->addr.in.sin_addr, sizeof(iface->addr.in.sin_addr));
		}

		// Debug logging
		if(config.debug.networking.v.b)
		{
			char buffer[ADDRSTRLEN+1] = { 0 };
			if(family == AF_INET)
				inet_ntop(AF_INET, &iface->addr.in.sin_addr, buffer, ADDRSTRLEN);
			else if(family == AF_INET6)
				inet_ntop(AF_INET6, &iface->addr.in6.sin6_addr, buffer, ADDRSTRLEN);

			const char *type = family == AF_INET6 ? isGUA ? " (GUA)" : isULA ? " (ULA)" : isLL ? " (LL)" : " (other)" : "";
			log_debug(DEBUG_NETWORKING, "  -  OK  IPv%d interface %s (%d,%d) is %s%s",
			          family == AF_INET ? 4 : 6, next_iface.name,
			          iface->index, iface->label, buffer, type);
		}

		// Exit loop early if we already have everything we need
		// (a valid IPv4 address + a valid ULA IPv6 address)
		if(next_iface.haveIPv4 && haveULAv6)
		{
			log_debug(DEBUG_NETWORKING, "Exiting interface analysis early (have IPv4 + ULAv6)");
			break;
		}
	}
}

static void check_pihole_PTR(char *domain)
{
	// Iterate through the already configured PTR entries in dnsmasq's
	// structure and check if we already have a PTR record for this address
	// This avoids adding work into defining PTR records that have already
	// been added but also overwriting PTR records manually added by users
	// using custom dnsmasq config lines like "ptr-record=<name>,<target>"
	for(struct ptr_record *ptr = daemon->ptr; ptr; ptr = ptr->next)
	{
		log_debug(DEBUG_EXTRA, "Known PTR record %p: %s -> %s (next = %p)", ptr, ptr->name, ptr->ptr, ptr->next);

		if(ptr->name != NULL && strcmp(ptr->name, domain) == 0)
		{
			// We already have a PTR record for this address
			log_debug(DEBUG_QUERIES, "PTR record for %s exists", domain);
			return;
		}
	}

	// Convert PTR request into numeric form
	union all_addr addr = {};
	const int flags = in_arpa_name_2_addr(domain, &addr);

	// Check if this is a valid in-addr.arpa (IPv4) or ip6.[int|arpa] (IPv6)
	// specifier. If not, nothing is to be done here and we return early
	if(flags == 0)
		return;

	// We do not want to reply with "pi.hole" to loopback PTRs
	if((flags == F_IPV4 && addr.addr4.s_addr == htonl(INADDR_LOOPBACK)) ||
	   (flags == F_IPV6 && IN6_IS_ADDR_LOOPBACK(&addr.addr6)))
		return;

	// If we reached this point, addr contains the address the client requested
	// a name for. We compare this address against all addresses of the local
	// interfaces to see if we should reply with "pi.hole"
	for (struct irec *iface = daemon->interfaces; iface != NULL; iface = iface->next)
	{
		const sa_family_t family = iface->addr.sa.sa_family;
		// If the family matches but the address doesn't, we skip this address
		if(!(family == AF_INET && flags == F_IPV4 && iface->addr.in.sin_addr.s_addr == addr.addr4.s_addr) &&
		   !(family == AF_INET6 && flags == F_IPV6 && IN6_ARE_ADDR_EQUAL(&iface->addr.in6.sin6_addr, &addr.addr6)))
			continue;

		// If we reached this point, we have a match between the address the client
		struct ptr_record *pihole_ptr = calloc(1, sizeof(struct ptr_record));
		// It is okay to use allocate heap memory here as this branch of
		// the code is only ever called once per interface on demand
		pihole_ptr->name = strdup(domain);
		if(family == AF_INET)
		{
			// IPv4 supports conditional domains
			pihole_ptr->ptr = get_ptrname(&iface->addr.in.sin_addr);
		}
		else
		{
			// IPv6 does not support conditional domains
			pihole_ptr->ptr = get_ptrname(NULL);
		}

		// If we have a PTR record, we add it to the list
		if(daemon->ptr != NULL)
		{
			// Iterate to the last PTR entry in dnsmasq's structure
			struct ptr_record *ptr;
			for(ptr = daemon->ptr; ptr && ptr->next; ptr = ptr->next);

			// Add our record after the last existing ptr-record
			ptr->next = pihole_ptr;
		}
		else
		{
			// We do not have any PTR records yet, so we add our
			// record as the first one
			daemon->ptr = pihole_ptr;
		}

		// Debug logging
		log_debug(DEBUG_QUERIES, "Generating PTR record (%p): %s -> %s", pihole_ptr, pihole_ptr->name, pihole_ptr->ptr);

		return;
	}
}

static bool check_domain_blocked(const char *domain,
                                 clientsData *client, queriesData *query, DNSCacheData *dns_cache,
                                 enum query_status *new_status, bool *db_okay)
{
	// Return early if this domain is explicitly allowed
	if(query->flags.allowed)
		return false;

	// Check domains against exact blacklist
	const enum db_result blacklist = in_denylist(domain, dns_cache, client);
	if(blacklist == FOUND)
	{
		// Set new status
		*new_status = QUERY_DENYLIST;
		blockingreason = "exactly denied";

		// We block this domain
		return true;
	}

	// Generate ABP patterns for domain
	cJSON *abp_patterns = gen_abp_patterns(domain);

	// Check domain against antigravity
	int list_id = -1;
	const enum db_result antigravity = in_gravity(domain, abp_patterns, client, true, &list_id);
	if(antigravity == FOUND)
	{
		log_debug(DEBUG_QUERIES, "Allowing query due to antigravity match (list ID %i)", list_id);

		// Store ID of the matching antigravity list
		// positive values (incl. 0) are used for domainlists
		// -1 means "not set"
		// -2 is gravity list 0
		// -3 is gravity list 1
		// ...
		dns_cache->list_id = -1 * (list_id + 2);

		// Mark query as allowed to prevent further checks such as CNAME
		// inspection. This ensures antigravity matches have similar effects
		// than explicitly allowed domains.
		query->flags.allowed = true;

		// Free allocated memory
		if(abp_patterns != NULL)
			cJSON_Delete(abp_patterns);

		return false;
	}

	// Check domains against gravity domains
	const enum db_result gravity = in_gravity(domain, abp_patterns, client, false, &list_id);
	if(gravity == FOUND)
	{
		// Set new status
		*new_status = QUERY_GRAVITY;
		blockingreason = "gravity blocked";

		log_debug(DEBUG_QUERIES, "Blocking query due to gravity match (list ID %i)", list_id);

		// Store ID of the matching gravity list
		// see remarks above for the list_id values
		dns_cache->list_id = -1 * (list_id + 2);

		// Free allocated memory
		if(abp_patterns != NULL)
			cJSON_Delete(abp_patterns);

		// We block this domain
		return true;
	}

	if(abp_patterns != NULL)
		cJSON_Delete(abp_patterns);

	// Check if one of the database lookups returned that the database is
	// currently busy
	if(blacklist == LIST_NOT_AVAILABLE ||
	   antigravity == LIST_NOT_AVAILABLE ||
	   gravity == LIST_NOT_AVAILABLE)
	{
		*db_okay = false;
		// Handle reply to this query as configured
		if(config.dns.replyWhenBusy.v.busy_reply == BUSY_ALLOW)
		{
			log_debug(DEBUG_QUERIES, "Allowing query as gravity database is not available");

			// Permit this query
			// As we set db_okay to false, this allowing here does not enter the
			// DNS cache so this domain will be rechecked on the next query
			return false;
		}
		else if(config.dns.replyWhenBusy.v.busy_reply == BUSY_REFUSE)
		{
			blockingreason = "to be refused (gravity database is not available)";
			force_next_DNS_reply = REPLY_REFUSED;
			*new_status = QUERY_DBBUSY;
		}
		else if(config.dns.replyWhenBusy.v.busy_reply == BUSY_DROP)
		{
			blockingreason = "to be dropped (gravity database is not available)";
			force_next_DNS_reply = REPLY_NONE;
			*new_status = QUERY_DBBUSY;
		}
		else
		{
			blockingreason = "to be blocked (gravity database is not available)";
			*new_status = QUERY_DBBUSY;
		}

		// We block this query
		return true;
	}

	// Check domain against blacklist regex filters
	// Skipped when the domain is whitelisted or blocked by exact blacklist or gravity
	if(in_regex(domain, dns_cache, client->id, REGEX_DENY))
	{
		// Set new status
		*new_status = QUERY_REGEX;
		blockingreason = "regex denied";

		// Regex may be overwriting reply type for this domain
		if(dns_cache->force_reply != REPLY_UNKNOWN)
			force_next_DNS_reply = dns_cache->force_reply;
		cname_target = dns_cache->cname_target;

		// Store ID of this regex (fork-private)
		last_regex_idx = dns_cache->list_id;

		// We block this domain
		return true;
	}

	// Not blocked because not found on any list
	return false;
}

// Special domain checking
static bool special_domain(const queriesData *query, const char *domain)
{
	// Mozilla canary domain
	// Network administrators may configure their networks as follows to signal
	// that their local DNS resolver implemented special features that make the
	// network unsuitable for DoH:
	// DNS queries for the A and AAAA records for the domain
	// “use-application-dns.net” must respond with either: a response code other
	// than NOERROR, such as NXDOMAIN (non-existent domain) or SERVFAIL; or
	// respond with NOERROR, but return no A or AAAA records.
	// https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https
	if(config.dns.specialDomains.mozillaCanary.v.b &&
	   strcasecmp(domain, "use-application-dns.net") == 0 &&
	   (query->type == TYPE_A || query->type == TYPE_AAAA))
	{
		blockingreason = "Mozilla canary domain";
		force_next_DNS_reply = REPLY_NXDOMAIN;
		return true;
	}

	// Apple iCloud Private Relay
	// Some enterprise or school networks might be required to audit all
	// network traffic by policy, and your network can block access to
	// Private Relay in these cases. The user will be alerted that they need
	// to either disable Private Relay for your network or choose another
	// network.
	// The fastest and most reliable way to alert users is to return a
	// negative answer from your network’s DNS resolver, preventing DNS
	// resolution for the following hostnames used by Private Relay traffic.
	// Avoid causing DNS resolution timeouts or silently dropping IP packets
	// sent to the Private Relay server, as this can lead to delays on
	// client devices.
	// > mask.icloud.com
	// > mask-h2.icloud.com
	// https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay
	if(config.dns.specialDomains.iCloudPrivateRelay.v.b &&
	   (strcasecmp(domain, "mask.icloud.com") == 0 ||
	    strcasecmp(domain, "mask-h2.icloud.com") == 0))
	{
		blockingreason = "Apple iCloud Private Relay domain";
		force_next_DNS_reply = REPLY_NXDOMAIN;
		return true;
	}

	// RFC 9462: Designated Resolver Domain
	// The domain "_dns.resolver.arpa" is reserved for use by DNS resolvers
	// that are designated by the network administrator to provide special
	// services to the network, e.g., DoH, DoQ, or DoT.
	//
	// Example (Google's 8.8.8.8):
	// ;; QUESTION SECTION:
	// ;_dns.resolver.arpa.            IN      SVCB
	//
	// ;; ANSWER SECTION:
	// _dns.resolver.arpa.     86400   IN      SVCB    1 dns.google. alpn="dot"
	// _dns.resolver.arpa.     86400   IN      SVCB    2 dns.google. alpn="h2,h3" key7="/dns-query{?dns}"
	//
	// RFC 9462, Section 4 says:
	// 
	// If the recursive resolver that receives this query has no Designated
	// Resolvers, it SHOULD return NODATA for queries to the "resolver.arpa"
	// zone, to provide a consistent and accurate signal to clients that it
	// does not have a Designated Resolver.
	if(config.dns.specialDomains.designatedResolver.v.b &&
	   strlen(domain) > 13 && strcasecmp(&domain[strlen(domain) - 13], "resolver.arpa") == 0)
	{
		blockingreason = "Designated Resolver domain";
		force_next_DNS_reply = REPLY_NODATA;
		return true;
	}

	return false;
}

static bool FTL_check_blocking(const unsigned int queryID, const unsigned int domainID, const unsigned int clientID)
{
	// Only check blocking conditions when global blocking is enabled
	if(get_blockingstatus() == BLOCKING_DISABLED)
	{
		return false;
	}

	// Get query, domain and client pointers
	queriesData *query  = getQuery(queryID, true);
	domainsData *domain = getDomain(domainID, true);
	clientsData *client = getClient(clientID, true);
	if(query == NULL || domain == NULL || client == NULL)
	{
		log_err("No memory available, skipping query analysis");
		return false;
	}

	// Get cache pointer
	DNSCacheData *dns_cache = getDNSCache(query->cacheID, true);
	if(dns_cache == NULL)
	{
		log_err("No memory available, skipping query analysis");
		return false;
	}

	// If this cache record can expire, check if it is still valid and/or if
	// caching is generally disabled
	if((dns_cache->expires > 0 && dns_cache->expires < time(NULL)) ||
	    config.dns.cache.upstreamBlockedTTL.v.ui == 0)
	{
		// This cache record is expired or caching is disabled, we have
		// to re-check if this domain is blocked
		log_debug(DEBUG_QUERIES, "DNS cache record expired or caching disabled");
		dns_cache->blocking_status = QUERY_UNKNOWN;
		dns_cache->flags.allowed = false;
		dns_cache->expires = 0;
		dns_cache->list_id = -1;
	}

	// Check if the cache record we have applies to the current query
	// If not, ensure we re-check the domain (happens during CNAME inspection)
	enum query_status blocking_status = QUERY_UNKNOWN;
	if(query->clientID == clientID && query->domainID == domainID)
		blocking_status = dns_cache->blocking_status;

	// Memorize blocking status DNS cache for the domain/client combination
	cacheStatus = blocking_status;
	log_debug(DEBUG_QUERIES, "Set global cache status to %d", cacheStatus);

	// Skip the entire chain of tests if we already know the answer for this
	// particular client
	char *domainstr = (char*)getstr(domain->domainpos);
	switch(blocking_status)
	{
		case QUERY_UNKNOWN:
			// New domain/client combination.
			// We have to go through all the tests below
			log_debug(DEBUG_QUERIES, "%s is not known", domainstr);

			break;

		case QUERY_DENYLIST:
		case QUERY_DENYLIST_CNAME:
			// Known as exactly denied, we return this result early, skipping
			// all the lengthy tests below
			blockingreason = blocking_status == QUERY_DENYLIST ? "exactly denied" : "exactly denied (CNAME)";
			log_debug(DEBUG_QUERIES, "%s is known as %s", domainstr, blockingreason);

			// Do not block if the entire query is to be permitted
			// as something along the CNAME path hit the whitelist
			if(!query->flags.allowed)
			{
				force_next_DNS_reply = dns_cache->force_reply;
				query_blocked(query, domain, client, blocking_status);
				if(blocking_status == QUERY_DENYLIST_CNAME)
					query->CNAME_domainID = dns_cache->CNAME_domainID;
				return true;
			}
			break;

		case QUERY_GRAVITY:
		case QUERY_GRAVITY_CNAME:
			// Known as gravity blocked, we return this result early, skipping
			// all the lengthy tests below
			blockingreason = blocking_status == QUERY_GRAVITY ? "gravity blocked" : "gravity blocked (CNAME)";
			log_debug(DEBUG_QUERIES, "%s is known as %s", domainstr, blockingreason);

			// Do not block if the entire query is to be permitted
			// as sometving along the CNAME path hit the whitelist
			if(!query->flags.allowed)
			{
				force_next_DNS_reply = dns_cache->force_reply;
				query_blocked(query, domain, client, blocking_status);
				if(blocking_status == QUERY_GRAVITY_CNAME)
					query->CNAME_domainID = dns_cache->CNAME_domainID;
				return true;
			}
			break;

		case QUERY_REGEX:
		case QUERY_REGEX_CNAME:
			// Known as regex denied, we return this result early, skipping all
			// the lengthy tests below
			blockingreason = blocking_status == QUERY_REGEX ? "regex denied" : "regex denied (CNAME)";
			log_debug(DEBUG_QUERIES, "%s is known as %s (cache regex ID: %i)",
			          domainstr, blockingreason, dns_cache->list_id);

			// Do not block if the entire query is to be permitted as something
			// along the CNAME path hit the whitelist
			if(!query->flags.allowed)
			{
				force_next_DNS_reply = dns_cache->force_reply;
				last_regex_idx = dns_cache->list_id;
				query_blocked(query, domain, client, blocking_status);
				if(blocking_status == QUERY_REGEX_CNAME)
					query->CNAME_domainID = dns_cache->CNAME_domainID;
				return true;
			}
			break;

		case QUERY_SPECIAL_DOMAIN:
			// Known as a special domain, we return this result early, skipping
			// all the lengthy tests below
			blockingreason = "special domain";
			log_debug(DEBUG_QUERIES, "%s is known as special domain", domainstr);

			force_next_DNS_reply = dns_cache->force_reply;
			query_blocked(query, domain, client, QUERY_SPECIAL_DOMAIN);
			return true;

		case QUERY_EXTERNAL_BLOCKED_IP:
		case QUERY_EXTERNAL_BLOCKED_NULL:
		case QUERY_EXTERNAL_BLOCKED_NXRA:
		case QUERY_EXTERNAL_BLOCKED_EDE15:
		{
			bool shortcircuit = true;
			switch(blocking_status)
			{
				case QUERY_UNKNOWN:
				case QUERY_GRAVITY:
				case QUERY_DENYLIST:
				case QUERY_REGEX:
				case QUERY_FORWARDED:
				case QUERY_CACHE:
				case QUERY_GRAVITY_CNAME:
				case QUERY_REGEX_CNAME:
				case QUERY_DENYLIST_CNAME:
				case QUERY_RETRIED:
				case QUERY_RETRIED_DNSSEC:
				case QUERY_IN_PROGRESS:
				case QUERY_DBBUSY:
				case QUERY_SPECIAL_DOMAIN:
				case QUERY_CACHE_STALE:
				case QUERY_STATUS_MAX:
					// Cannot happen
					break;
				case QUERY_EXTERNAL_BLOCKED_IP:
					blockingreason = "blocked upstream with known address";
					// We do not want to short-circuit this
					// query as to get the address contained
					// in the upstream reply being sent
					// downstream to the client.
					// Otherwise, Pi-hole's short-circuiting
					// would reply to the client with the
					// configured blocking mode (probably
					// NULL)
					shortcircuit = false;
					break;
				case QUERY_EXTERNAL_BLOCKED_NULL:
					blockingreason = "blocked upstream with NULL address";
					break;
				case QUERY_EXTERNAL_BLOCKED_EDE15:
					blockingreason = "blocked upstream with EDE15";
					break;
				case QUERY_EXTERNAL_BLOCKED_NXRA:
					blockingreason = "blocked upstream with NXRA address";
					break;
			}

			// Known as upstream blocked, we return this result
			// early, skipping all the lengthy tests below
			log_debug(DEBUG_QUERIES, "%s is known as %s (expires in %lus)",
			          domainstr, blockingreason, (unsigned long)(dns_cache->expires - time(NULL)));

			force_next_DNS_reply = dns_cache->force_reply;
			query_blocked(query, domain, client, blocking_status);
			return shortcircuit;
		}

		case QUERY_CACHE:
		case QUERY_FORWARDED:
		case QUERY_RETRIED:
		case QUERY_RETRIED_DNSSEC:
		case QUERY_IN_PROGRESS:
		case QUERY_DBBUSY:
		case QUERY_CACHE_STALE:
		case QUERY_STATUS_MAX:
			// Known as not to be blocked, possibly even explicitly
			// allowed - we return this result early, skipping all
			// the lengthy tests below
			log_debug(DEBUG_QUERIES, "%s is known as not to be blocked%s", domainstr,
			          dns_cache->flags.allowed ? " (allowed)" : "");

			if(dns_cache->flags.allowed)
				query->flags.allowed = true;

			return false;
	}

	// Skip all checks and continue if we hit already at least one allowlist in the chain
	if(query->flags.allowed)
	{
		log_debug(DEBUG_QUERIES, "Query is permitted as at least one allowlist entry matched");
		return false;
	}

	// when we reach this point: the query is not in FTL's cache (for this client)

	// Make a local copy of the domain string. The string memory may get
	// reorganized in the following. We cannot expect domainstr to remain
	// valid for all time.
	char domain_lower[MAXDOMAINLEN];
	strncpy(domain_lower, domainstr, sizeof(domain_lower) - 1);
	domain_lower[sizeof(domain_lower) - 1] = '\0';
	const char *blockedDomain = domain_lower;

	// Check exact whitelist for match
	TIMED_DB_OP_RESULT(query->flags.allowed, in_allowlist(domain_lower, dns_cache, client) == FOUND);

	// If not found: Check regex whitelist for match
	if(!query->flags.allowed)
		TIMED_DB_OP_RESULT(query->flags.allowed, in_regex(domain_lower, dns_cache, client->id, REGEX_ALLOW));

	// Check if this is a special domain
	if(!query->flags.allowed && special_domain(query, domain_lower))
	{
		// Set DNS cache properties
		dns_cache->blocking_status = QUERY_SPECIAL_DOMAIN;
		cacheStatus = dns_cache->blocking_status;
		dns_cache->force_reply = force_next_DNS_reply;

		// Adjust counters
		query_blocked(query, domain, client, QUERY_SPECIAL_DOMAIN);

		// Debug output
		log_debug(DEBUG_QUERIES, "Special domain: %s is %s", domain_lower, blockingreason);

		return true;
	}

	// Check blacklist (exact + regex) and gravity for queried domain
	unsigned char new_status = QUERY_UNKNOWN;
	bool db_okay = true;
	bool blockDomain;
	TIMED_DB_OP_RESULT(blockDomain, check_domain_blocked(domain_lower, client, query, dns_cache, &new_status, &db_okay));

	// Check blacklist (exact + regex) and gravity for _esni.domain if enabled
	// (defaulting to true)
	if(config.dns.blockESNI.v.b &&
	   !query->flags.allowed && blockDomain == NOT_FOUND &&
	   strlen(domain_lower) > 6 && strncasecmp(domain_lower, "_esni.", 6u) == 0)
	{
		TIMED_DB_OP_RESULT(blockDomain, check_domain_blocked(domain_lower + 6u, client, query, dns_cache, &new_status, &db_okay));

		// Update DNS cache status
		cacheStatus = dns_cache->blocking_status;

		if(blockDomain)
		{
			// Truncate "_esni." from queried domain if the parenting domain was
			// the reason for blocking this query
			blockedDomain = domain_lower + 6u;
			// Force next DNS reply to be NXDOMAIN for _esni.* queries
			force_next_DNS_reply = REPLY_NXDOMAIN;

			// Store this in the DNS cache only if the database is available at
			// this point
			if(db_okay)
				dns_cache->force_reply = REPLY_NXDOMAIN;
		}
	}

	// Common actions regardless what the possible blocking reason is
	if(blockDomain)
	{
		// Adjust counters
		query_blocked(query, domain, client, new_status);

		// Debug output
		if(config.debug.queries.v.b)
		{
			log_debug(DEBUG_QUERIES, "Blocking %s as %s is %s (domainlist ID: %i)",
			          domain_lower, blockedDomain, blockingreason, dns_cache->list_id);
			if(force_next_DNS_reply != 0)
				log_debug(DEBUG_QUERIES, "Forcing next reply to %s", get_query_reply_str(force_next_DNS_reply));
		}
	}
	else if(db_okay)
	{
		// Explicitly mark as not blocked to skip the entire gravity/blacklist
		// chain when the same client asks for the same domain in the future.
		// Store domain as allowed if this is the case
		dns_cache->flags.allowed = query->flags.allowed;

		// Debug output
		// client is guaranteed to be non-NULL above
		log_debug(DEBUG_QUERIES, "DNS cache: %s/%s/%s is %s (domainlist ID: %i)",
		          get_query_type_str(query->type, NULL, NULL), getstr(client->ippos),
		          domain_lower, query->flags.allowed ? "allowed" : "not blocked", dns_cache->list_id);
	}

	return blockDomain;
}

/**
 * @brief Updates the cache record for the "pi.hole" domain with the current interface addresses.
 *
 * This function searches the DNS cache for entries corresponding to the "pi.hole" domain,
 * for both IPv4 and IPv6 address families. For each matching cache entry found, it updates
 * the stored address with the address from the next available network interface. It also
 * sets flags indicating the presence of IPv4 and/or IPv6 addresses in the interface structure.
 */
static void update_pihole_cache_record(void)
{
	struct crec *lookup = NULL;
	while ((lookup = cache_find_by_name(lookup, (char*)"pi.hole", 0, F_IPV4 | F_IPV6)))
	{
		// We have a cache entry for "pi.hole", so we can use it
		log_debug(DEBUG_NETWORKING, "Found cache entry for pi.hole: %p", lookup);
		if(lookup->flags & F_IPV4)
		{
			if(config.dns.reply.host.force4.v.b)
				memcpy(&lookup->addr.addr4, &config.dns.reply.host.v4.v.in_addr, sizeof(lookup->addr.addr4));
			else
				memcpy(&lookup->addr.addr4, &next_iface.addr4.addr4, sizeof(lookup->addr.addr4));
			log_debug(DEBUG_NETWORKING, "Updating IPv4 address in cache");
		}
		if(lookup->flags & F_IPV6)
		{
			if(config.dns.reply.host.force6.v.b)
				memcpy(&lookup->addr.addr6, &config.dns.reply.host.v6.v.in6_addr, sizeof(lookup->addr.addr6));
			else
				memcpy(&lookup->addr.addr6, &next_iface.addr6.addr6, sizeof(lookup->addr.addr6));
			log_debug(DEBUG_NETWORKING, "Updating IPv6 address in cache");
		}
	}
}

bool FTL_CNAME(const char *dst, const char *src, const int id)
{
	const double now = double_time();
	log_debug(DEBUG_QUERIES, "FTL_CNAME called with: src = %s, dst = %s, id = %d", src, dst, id);

	if((src != NULL && strcasecmp(src, "pi.hole") == 0) ||
	   (dst != NULL && strcasecmp(dst, "pi.hole") == 0))
	{
		// If "pi.hole" occurs in the CNAME chain we need to make sure
		// the "pi.hole" cache record is up-to-date with the current
		// interface addresses for interface-dependent replies
		log_debug(DEBUG_QUERIES, "Updating pi.hole cache record as it is part of the CNAME chain");
		update_pihole_cache_record();
	}

	// Does the user want to skip deep CNAME inspection?
	if(!config.dns.CNAMEdeepInspect.v.b)
	{
		log_debug(DEBUG_QUERIES, "Skipping analysis as CNAME inspection is disabled");
		return false;
	}

	// Lock shared memory
	lock_shm();

	// Save status and upstreamID in corresponding query identified by dnsmasq's ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was a PTR query
		// or "pi.hole" and we ignored them altogether
		unlock_shm();
		log_debug(DEBUG_QUERIES, "Skipping analysis as parent query is not found");
		return false;
	}

	// Get query pointer so we can later extract the client requesting this domain for
	// the per-client blocking evaluation
	queriesData *query = getQuery(queryID, true);
	if(query == NULL)
	{
		// Nothing to be done here
		unlock_shm();
		log_debug(DEBUG_QUERIES, "Skipping analysis as parent query is not valid");
		return false;
	}

	// Example to make the terminology used in here clear:
	// CNAME abc -> 123
	// CNAME 123 -> 456
	// CNAME 456 -> 789
	// parent_domain: abc
	// child_domains: [123, 456, 789]

	// parent_domain = Domain at the top of the CNAME path
	// This is the domain which was queried first in this chain
	const int parent_domainID = query->domainID;

	// child_domain = Intermediate domain in CNAME path
	// This is the domain which was queried later in this chain
	char child_domain[MAXDOMAINLEN];
	strncpy(child_domain, dst, sizeof(child_domain) - 1);
	child_domain[sizeof(child_domain) - 1] = '\0';

	// Convert to lowercase for matching
	strtolower(child_domain);
	const int child_domainID = findDomainID(child_domain, false);

	// Set child domains's last query time
	if(child_domainID >= 0)
	{
		domainsData *cdomain = getDomain(child_domainID, true);
		if(cdomain != NULL)
			cdomain->lastQuery = now;
	}

	// Get client ID from the original query (the entire chain always
	// belongs to the same client)
	const int clientID = query->clientID;

	// Check per-client blocking for the child domain
	const bool block = FTL_check_blocking(queryID, child_domainID, clientID);

	// If we find during a CNAME inspection that we want to block the entire chain,
	// the originally queried domain itself was not counted as blocked. We have to
	// correct this when we are going to short-circuit the entire query
	if(block)
	{
		// Increase blocked count of parent domain
		domainsData *parent_domain = getDomain(parent_domainID, true);
		if(parent_domain == NULL)
		{
			// Memory error, return
			unlock_shm();
			return false;
		}
		parent_domain->blockedcount++;

		// Store query response as CNAME type
		query_set_reply(F_CNAME, 0, NULL, query, now);

		// Store domain that was the reason for blocking the entire chain
		query->CNAME_domainID = child_domainID;

		// Store CNAME domain ID in DNS cache
		const int parent_cacheID = query->cacheID > -1 ? query->cacheID : findCacheID(parent_domainID, clientID, query->type, false);
		DNSCacheData *parent_cache = parent_cacheID < 0 ? NULL : getDNSCache(parent_cacheID, true);
		if(parent_cache != NULL)
			parent_cache->CNAME_domainID = child_domainID;

		// Change blocking reason into CNAME-caused blocking
		if(query->status == QUERY_GRAVITY)
		{
			query_set_status(query, QUERY_GRAVITY_CNAME);
		}
		else if(query->status == QUERY_REGEX)
		{
			// Get child DNS cache entries
			const int child_cacheID = findCacheID(child_domainID, clientID, query->type, false);

			// Get child's cache pointer
			const DNSCacheData *child_cache = child_cacheID < 0 ? NULL : getDNSCache(child_cacheID, true);

			// Propagate ID of responsible regex up from the child to the parent
			// domain (but only if set)
			if(parent_cache != NULL && child_cache != NULL && child_cache->list_id != -1)
				parent_cache->list_id = child_cache->list_id;

			// Set status
			query_set_status(query, QUERY_REGEX_CNAME);
		}
		else if(query->status == QUERY_DENYLIST)
		{
			// Only set status
			query_set_status(query, QUERY_DENYLIST_CNAME);
		}
	}

	// Debug logging for deep CNAME inspection (if enabled)
	log_debug(DEBUG_QUERIES, "Query %d: CNAME %s ---> %s", id, src, dst);

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Return result
	unlock_shm();
	return block;
}

static void FTL_forwarded(const unsigned int flags, const char *name, const union all_addr *addr,
                          unsigned short port, const int id, const char *file, const int line)
{
	// Save that this query got forwarded to an upstream server
	const double now = double_time();

	// Lock shared memory
	lock_shm();

	// Get forward destination IP address and port
	in_port_t upstreamPort = 53;
	char dest[ADDRSTRLEN];
	// If addr == NULL, we will only duplicate an empty string instead of uninitialized memory
	dest[0] = '\0';
	if(addr != NULL)
	{
		if(flags & F_IPV4)
		{
			inet_ntop(AF_INET, addr, dest, ADDRSTRLEN);
			// Reverse-engineer port from underlying sockaddr_in structure
			const in_port_t *rport = (in_port_t*)((void*)addr
			                                     - offsetof(struct sockaddr_in, sin_addr)
			                                     + offsetof(struct sockaddr_in, sin_port));
			upstreamPort = ntohs(*rport);
			if(upstreamPort != port)
				log_err("Port mismatch for %s: we derived %d, dnsmasq told us %d", dest, upstreamPort, port);
		}
		else
		{
			inet_ntop(AF_INET6, addr, dest, ADDRSTRLEN);
			// Reverse-engineer port from underlying sockaddr_in6 structure
			const in_port_t *rport = (in_port_t*)((void*)addr
			                                     - offsetof(struct sockaddr_in6, sin6_addr)
			                                     + offsetof(struct sockaddr_in6, sin6_port));
			upstreamPort = ntohs(*rport);
			if(upstreamPort != port)
				log_err("Port mismatch for %s: we derived %d, dnsmasq told us %d", dest, upstreamPort, port);
		}
	}

	// Convert upstreamIP to lower case
	char upstreamIP[INET6_ADDRSTRLEN];
	strncpy(upstreamIP, dest, INET6_ADDRSTRLEN);
	upstreamIP[INET6_ADDRSTRLEN - 1] = '\0';
	strtolower(upstreamIP);

	// Debug logging
	log_debug(DEBUG_QUERIES, "**** forwarded %s to %s#%u (ID %i, %s:%i)",
	          name, upstreamIP, upstreamPort, id, file, line);

	// Save status and upstreamID in corresponding query identified by dnsmasq's ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was a PTR query or "pi.hole"
		// as we ignore them altogether
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData *query = getQuery(queryID, true);
	if(query == NULL)
	{
		unlock_shm();
		return;
	}

	// Check if this query is already marked as complete
	// This can happen when multiple upstream servers respond to the same
	// query or when the query has already been replied to from stale cache
	// data (cache-optimizer) and this is the followup to refresh the cache
	// record with possibly changed data
	if(query->flags.complete)
	{
		unlock_shm();
		return;
	}

	// Get ID of upstream destination, create new upstream record
	// if not found in current data structure
	const unsigned int upstreamID = findUpstreamID(upstreamIP, upstreamPort);
	query->upstreamID = upstreamID;

	upstreamsData *upstream = getUpstream(upstreamID, true);
	if(upstream != NULL)
	{
		upstream->count++;
		upstream->lastQuery = now;
	}

	// Proceed only if
	// - current query has not been marked as replied to so far
	//   (it could be that answers from multiple forward
	//    destinations are coming in for the same query)
	// - the query was formally known as cached but had to be forwarded
	//   (this is a special case further described below)
	if(query->flags.complete && query->status != QUERY_CACHE)
	{
		unlock_shm();
		return;
	}

	if(query->status == QUERY_CACHE)
	{
		// Detect if we cached the <CNAME> but need to ask the upstream
		// servers for the actual IPs now, we remove this query from the
		// counters for cache replied queries as we had to forward a
		// request for it. Example:
		// Assume a domain a.com is a CNAME which is cached and has a very
		// long TTL. It point to another domain server.a.com which has an
		// A record but this has a much lower TTL.
		// If you now query a.com and then again after some time, you end
		// up in a situation where dnsmasq can answer the first level of
		// the DNS result (the CNAME) from cache, hence the status of this
		// query is marked as "answered from cache" in FTLDNS. However, for
		// server.a.com with the much shorter TTL, we still have to forward
		// something and ask the upstream server for the final IP address.

		// Correct reply timer if a response time has already been calculated
		if(query->flags.response_calculated)
		{
			struct timeval response;
			gettimeofday(&response, 0);
			// Reset timer to measure how long it takes until an answer arrives
			// If a response time has already been calculated, we
			// can go back in time to measure both the initial cache
			// lookup and the (now starting) time it takes for the
			// upstream to respond
			query->response = now - query->response;
			query->flags.response_calculated = false;
		}
	}
	else
	{
		// Normal forwarded query (status is set below)
		// Hereby, this query is now fully determined
		query->flags.complete = true;
	}

	// Set query status to forwarded only after the
	// if(query->status == QUERY_CACHE) { ... }
	// from above as otherwise this check will always
	// be negative
	query_set_status(query, QUERY_FORWARDED);

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Unlock shared memory
	unlock_shm();
}

static unsigned int reload = 0u;
void FTL_dnsmasq_reload(void)
{
	// This function is called by the dnsmasq code on receive of SIGHUP
	// *before* clearing the cache and re-reading the lists
	if(reload++ > 0)
		log_info("Flushing cache and re-reading config");

	// Gravity database updates
	// - (Re-)open gravity database connection
	// - Get number of blocked domains
	// - check adlist table for inaccessible adlists
	// - Read and compile regex filters (incl. per-client)
	// - Flush FTL's DNS cache
	set_event(RELOAD_GRAVITY);

	// Print current set of capabilities if requested via debug flag
	if(config.debug.caps.v.b)
		check_capabilities();

	// Re-read pihole.toml (incl. rewriting) on every but the first reload
	// (which is happening right after the start of dnsmasq)
	if(reload > 1)
		reread_config();

	// Report blocking mode
	log_info("Blocking status is %s", config.dns.blocking.active.v.b ? "enabled" : "disabled");

	// Set resolver as ready
	resolver_ready = true;
}

static void alladdr_extract_ip(union all_addr *addr, const sa_family_t family, char ip[ADDRSTRLEN+1])
{
	// Extract IP address
	inet_ntop(family, addr, ip, ADDRSTRLEN);
}

static void mysockaddr_extract_ip_port(const union mysockaddr *server, char ip[ADDRSTRLEN+1], in_port_t *port)
{
	// Extract IP address
	inet_ntop(server->sa.sa_family,
	          server->sa.sa_family == AF_INET ?
	            (void*)&server->in.sin_addr :
	            (void*)&server->in6.sin6_addr,
	          ip, ADDRSTRLEN);

	// Extract port (only if requested)
	if(port != NULL)
	{
		*port = ntohs(server->sa.sa_family == AF_INET ?
		                server->in.sin_port :
		                server->in6.sin6_port);
	}
}

// Compute cache/upstream response time
static inline void set_response_time(queriesData *query, const double now)
{
	// Do this only if this is the first time we set a reply
	if(query->flags.response_calculated)
		return;

	// Convert absolute timestamp to relative timestamp
	query->response = now - query->response;
	query->flags.response_calculated = true;
}

// Changes upstream server (only relevant when multiple servers are defined)
// If this is an upstream response and the answering upstream is known (may not
// be the case for internally generated DNSSEC queries), we have to check if the
// first answering upstream server is also the first one we sent the query to.
// If not, we need to change the upstream server associated with this query to
// get accurate statistics
static void update_upstream(queriesData *query, const int id)
{
	// We use query->flags.response_calculated to check if this is the first
	// response received for this query and check the family of last server
	// to see if it is available
	if(query->flags.response_calculated || last_server.sa.sa_family == 0)
		return;

	char ip[ADDRSTRLEN+1] = { 0 };
	in_port_t port = 0;
	mysockaddr_extract_ip_port(&last_server, ip, &port);
	int upstreamID = findUpstreamID(ip, port);
	if(upstreamID != query->upstreamID)
	{
		// Debug output
		if(config.debug.queries.v.b && query->upstreamID > 0)
		{
			const upstreamsData *upstream = getUpstream(query->upstreamID, true);
			if(upstream)
			{
				const char *oldaddr = getstr(upstream->ippos);
				const in_port_t oldport = upstream->port;
				log_debug(DEBUG_QUERIES, "Query ID %d: Associated upstream changed (was %s#%d) as %s#%d replied earlier",
				          id, oldaddr, oldport, ip, port);
			}
		}

		// Update upstream server ID
		query->upstreamID = upstreamID;
	}
}

static void FTL_reply(const unsigned int flags, const char *name, const union all_addr *addr,
                      const char *arg, const int id, const char *file, const int line)
{
	const double now = double_time();
	// If domain is "pi.hole", we skip this query
	// We compare case-insensitive here
	// Hint: name can be NULL, e.g. for NODATA/NXDOMAIN replies
	if(name != NULL && strcasecmp(name, "pi.hole") == 0)
	{
		return;
	}

	// Lock shared memory
	lock_shm();

	// Save status in corresponding query identified by dnsmasq's ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was "pi.hole"
		log_debug(DEBUG_QUERIES, "FTL_reply(): Query %i has not been found", id);
		unlock_shm();
		return;
	}

	// Get and check query pointer
	queriesData *query = getQuery(queryID, true);
	if(query == NULL)
	{
		// Nothing to be done here
		unlock_shm();
		return;
	}

	// Check if this reply came from our local cache (query->type == TYPE_NONE is non-query but has F_UPSTREAM)
	bool cached = false;
	if(!(flags & F_UPSTREAM) || query->type == TYPE_NONE)
	{
		cached = true;
		if((flags & F_HOSTS) || // hostname.list, /etc/hosts and others
		   ((flags & F_NAMEP) && (flags & F_DHCP)) || // DHCP server reply
		   (flags & F_FORWARD) || // cached answer to previously forwarded request
		   (flags & F_REVERSE) || // cached answer to reverse request (PTR)
		   (flags & F_RRNAME)) // cached answer to TXT query
		{
			; // Okay
		}
		else
			log_debug(DEBUG_FLAGS, "***** Unknown cache query");
	}

	// Is this a stale reply?
	const bool stale = flags & F_STALE;

	// Possible debugging output
	if(config.debug.queries.v.b)
	{
		// Human-readable answer may be provided by arg
		// (e.g. for non-cached queries such as SOA)
		const char *answer = arg;
		// Determine returned address (if applicable)
		char dest[ADDRSTRLEN]; dest[0] = '\0';
		if(addr && flags & (F_IPV4 | F_IPV6))
		{
			inet_ntop((flags & F_IPV4) ? AF_INET : AF_INET6, addr, dest, ADDRSTRLEN);
			answer = dest; // Overwrite answer with human-readable IP address
		}

		// Extract answer (used e.g. for detecting if a local config is a user-defined
		// wildcard blocking entry in form "server=/tobeblocked.com/")
		if(flags & F_CNAME)
			answer = "(CNAME)";
		else if((flags & F_NEG) && (flags & F_NXDOMAIN))
			answer = "(NXDOMAIN)";
		else if(flags & F_NEG)
			answer = "(NODATA)";
		else if(flags & F_RCODE && addr != NULL)
		{
			unsigned int rcode = addr->log.rcode;
			if(rcode == REFUSED)
			{
				// This happens, e.g., in a "nowhere to forward to" situation
				answer = "REFUSED (nowhere to forward to)";
			}
			else if(rcode == SERVFAIL)
			{
				// This happens on upstream destination errors
				answer = "SERVFAIL";
			}
		}
		else if(flags & F_NOEXTRA)
		{
			if(flags & F_KEYTAG)
				answer = "DNSKEY";
			else
				answer = arg; // e.g. "reply <TLD> is no DS"
		}

		// Substitute "." if we are querying the root domain (e.g. DNSKEY)
		const char *dispname = name;
		if(!name || strlen(name) == 0)
			dispname = ".";

		// Swap display name with answer if this is a reverse query
		// Check for reverse query by looking at the query type not only
		// the flag as some PTR queries are not flagged (DNS-SD)
		if(flags & F_REVERSE || query->type == TYPE_PTR)
		{
			const char *tmp = dispname;
			dispname = answer;
			answer = tmp;
		}

		if(cached || last_server.sa.sa_family == 0)
		{
			// Log cache or upstream reply from unknown source
			log_debug(DEBUG_QUERIES, "**** got %s%s reply: %s is %s (ID %i, %s:%i)",
			          stale ? "stale ": "", cached ? "cache" : "upstream",
			          dispname, answer, id, file, line);
		}
		else
		{
			char ip[ADDRSTRLEN + 1] = { 0 };
			in_port_t port = 0;
			mysockaddr_extract_ip_port(&last_server, ip, &port);
			// Log server which replied to our request
			log_debug(DEBUG_QUERIES, "**** got %s%s reply from %s#%d: %s is %s (ID %i, %s:%i)",
			          stale ? "stale ": "", cached ? "cache" : "upstream",
			          ip, port, dispname, answer, id, file, line);
		}

		if(flags & F_RCODE && addr != NULL)
		{
			// Translate dnsmasq's rcode into something we can use
			const char *rcodestr = NULL;
			enum reply_type reply = REPLY_UNKNOWN;
			get_rcode(addr->log.rcode, &rcodestr, &reply);
			// Log RCODE if available
			log_debug(DEBUG_QUERIES, "     RCODE: %s (%d)", rcodestr, addr->log.rcode);
		}
	}

	// EDE analysis
	if(addr && flags & (F_RCODE | F_SECSTAT) && addr->log.ede != EDE_UNSET)
	{
		query->ede = addr->log.ede;
		log_debug(DEBUG_QUERIES, "     EDE (1): %s (%d)", edestr(addr->log.ede), addr->log.ede);
	}
	ednsData *edns = getEDNS();
	if(edns != NULL && edns->ede != EDE_UNSET)
	{
		query->ede = edns->ede;
		log_debug(DEBUG_QUERIES, "     EDE (2): %s (%d)", edestr(edns->ede), edns->ede);
	}

	// Update upstream server (if applicable)
	if(!cached)
		update_upstream(query, id);

	// Reset last_server to avoid possibly changing the upstream server
	// again in the next query
	memset(&last_server, 0, sizeof(last_server));

	// Save response time
	// Skipped internally if already computed
	set_response_time(query, now);

	// We only process the first reply further in here
	// Check if reply type is still UNKNOWN
	if(query->reply != REPLY_UNKNOWN)
	{
		// Nothing to be done here
		unlock_shm();
		return;
	}

	// Determine if this reply is an exact match for the queried domain
	const int domainID = query->domainID;

	// Get domain pointer
	const domainsData *domain = getDomain(domainID, true);
	if(domain == NULL)
	{
		// Memory error, skip reply
		unlock_shm();
		return;
	}

	// Determine query status (live or stale data?)
	const enum query_status qs = stale ? QUERY_CACHE_STALE : QUERY_CACHE;

	// This is either a reply served from cache or a blocked query (which appear
	// to be from cache because of flags containing F_HOSTS)
	if(cached)
	{
		// Set status of this query only if this is not a blocked query
		if(!is_blocked(query->status))
			query_set_status(query, qs);

		// Save reply type and update individual reply counters
		query_set_reply(flags, 0, addr, query, now);

		// We know from cache that this domain is either SECURE or
		// INSECURE, bogus queries are not cached
		if(flags & F_DNSSECOK)
			query_set_dnssec(query, DNSSEC_SECURE);
		else
			query_set_dnssec(query, DNSSEC_INSECURE);

		// Hereby, this query is now fully determined
		query->flags.complete = true;

		// Mark query for updating in the database
		query->flags.database.changed = true;

		unlock_shm();
		return;
	}

	// else: This is a reply from upstream
	// Check if this domain matches exactly
	const bool isExactMatch = name != NULL && strcasecmp(name, getstr(domain->domainpos)) == 0;

	if((flags & F_CONFIG) && isExactMatch && !query->flags.complete)
	{
		// Answered from local configuration, might be a wildcard or user-provided

		// Answered from a custom (user provided) cache file or because
		// we're the authoritative DNS server (e.g. DHCP server and this
		// is our own domain)
		query_set_status(query, qs);

		// Save reply type and update individual reply counters
		query_set_reply(flags, 0, addr, query, now);

		// Hereby, this query is now fully determined
		query->flags.complete = true;

		// Mark query for updating in the database
		query->flags.database.changed = true;
	}
	else if((flags & (F_FORWARD | F_UPSTREAM)) && isExactMatch && query->type != TYPE_NONE)
	{
		// type != 0: Answered from upstream server
		// type == 0: Answered from cache (probably a non-query reply)
		if(query->upstreamID < 0)
		{
			// This should not happen, but if it does, we skip this
			// reply
			log_err("Upstream ID is negative for query %d", id);
			unlock_shm();
			return;
		}
		upstreamsData *upstream = getUpstream(query->upstreamID, true);
		if(upstream == NULL)
		{
			// Warning has already been logged by getUpstream(),
			// skip this reply
			unlock_shm();
			return;
		}
		upstream->responses++;

		// Re-compute upstream average response time and uncertainty
		upstream->rtime += query->response;
		const double mean = upstream->rtime / upstream->responses;
		upstream->rtuncertainty += (mean - query->response)*(mean - query->response);

		// Only proceed if query is not already known to have been
		// blocked upstream AND short-circuited.
		// Note: The reply needs to be analyzed further in case of
		// QUERY_EXTERNAL_BLOCKED_IP as this is a "normal" upstream
		// reply and we need to process it further (DNSSEC status, etc.)
		if(query->status == QUERY_EXTERNAL_BLOCKED_NULL ||
		   query->status == QUERY_EXTERNAL_BLOCKED_NXRA ||
		   query->status == QUERY_EXTERNAL_BLOCKED_EDE15)
		{
			unlock_shm();
			return;
		}

		// DNSSEC query handling
		unsigned int reply_flags = flags;
		if(flags & F_NOEXTRA && (query->type == TYPE_DNSKEY || query->type == TYPE_DS))
		{
			if(flags & F_KEYTAG)
			{
				// We were able to validate this query, mark it
				// as SECURE (reply <domain> is {DNSKEY,DS}
				// keytag <X>, algo <Y>, digest <Z>)
				query_set_dnssec(query, DNSSEC_SECURE);
			}
			else if(strstr(arg, "BOGUS") != NULL)
			{
				// BOGUS DS
				query_set_dnssec(query, DNSSEC_BOGUS);
			}
			else
			{
				// If is a negative reply to a DNSSEC query
				// (reply <domain> is no DS), we overwrite flags
				// to store NODATA for this query
				reply_flags = F_NEG;
			}
		}

		// Save reply type and update individual reply counters
		query_set_reply(reply_flags, 0, addr, query, now);

		// Mark query for updating in the database
		query->flags.database.changed = true;
	}
	else if(flags & F_REVERSE || query->type == TYPE_PTR)
	{
		// isExactMatch is not used here as the PTR is special.
		// Example:
		// Question: PTR -x 8.8.8.8
		// will lead to:
		//   domain->domain = 8.8.8.8.in-addr.arpa
		//   name = 8.8.8.8 (derived above from addr)
		//   answer = dns.google
		// Hence, isExactMatch is always false
		// DNS-SD example:
		// Question: PTR _http._tcp.local
		// will lead to:
		//   domain->domain = obs.cr
		//   name = (null)
		//   answer = obs.cr

		// if flags does not contain F_REVERSE, it is not a reverse
		// query, e.g. DNS-SD
		unsigned int pflags = flags;
		if(!(flags & F_REVERSE))
			pflags |= F_RRNAME;

		// Save reply type and update individual reply counters
		query_set_reply(pflags, 0, addr, query, now);

		// Hereby, this query is now fully determined
		query->flags.complete = true;

		// Mark query for updating in the database
		query->flags.database.changed = true;
	}
	else if(flags & F_UPSTREAM && flags & F_RCODE)
	{
		// Non-query reply synthesized locally
		query_set_reply(flags, 0, addr, query, now);

		// Set status of this query
		if(!is_blocked(query->status))
			query_set_status(query, QUERY_CACHE);

		// Hereby, this query is now fully determined
		query->flags.complete = true;

		// Mark query for updating in the database
		query->flags.database.changed = true;
	}
	else if(isExactMatch && !query->flags.complete)
	{
		log_warn("Unknown REPLY");
	}
	else if(config.debug.flags.v.b)
	{
		log_warn("Unknown upstream REPLY, exact: %s, type: %u",
		         isExactMatch ? "true" : "false", query->type);
	}

	if(query && option_bool(OPT_DNSSEC_PROXY))
	{
		// DNSSEC proxy mode is enabled. Interpret AD flag
		// and set DNSSEC status accordingly
		query_set_dnssec(query, adbit ? DNSSEC_SECURE : DNSSEC_INSECURE);
	}

	if(query && option_bool(OPT_DNSSEC_PROXY))
	{
		// DNSSEC proxy mode is enabled. Interpret AD flag
		// and set DNSSEC status accordingly
		query_set_dnssec(query, adbit ? DNSSEC_SECURE : DNSSEC_INSECURE);
	}

	unlock_shm();
}

static enum query_status detect_blocked_IP(const unsigned short flags, const union all_addr *addr)
{
	// Compare returned IP against list of known blocking splash pages

	// First, we check if we want to skip this result even before comparing against the known IPs
	if(flags & F_HOSTS || flags & F_REVERSE)
	{
		// Skip replies which originated locally. Otherwise, we would
		// count gravity.list blocked queries as externally blocked.
		// Also: Do not mark responses of PTR requests as externally blocked.
		const char *cause = (flags & F_HOSTS) ? "origin is HOSTS" : "query is PTR";
		log_debug(DEBUG_QUERIES, "Skipping detection of external blocking IP as %s", cause);

		// Return early, do not compare against known blocking page IP addresses below
		return QUERY_UNKNOWN;
	}

	// If received one of the following IPs as reply, OpenDNS
	// (Cisco Umbrella) blocked this query
	// See https://support.opendns.com/hc/en-us/articles/227986927-What-are-the-Cisco-Umbrella-Block-Page-IP-Addresses
	// for a full list of these IP addresses
	const in_addr_t ipv4Addr = (flags & F_IPV4) ? ntohl(addr->addr4.s_addr) : 0;
	const in_addr_t ipv6Addr = (flags & F_IPV6) ? ntohl(addr->addr6.s6_addr32[3]) : 0;
	// Check for IP block 146.112.61.104 - 146.112.61.110
	if((flags & F_IPV4) && ipv4Addr >= 0x92703d68 && ipv4Addr <= 0x92703d6e)
	{
		if(config.debug.queries.v.b)
		{
			char answer[ADDRSTRLEN]; answer[0] = '\0';
			inet_ntop(AF_INET, addr, answer, ADDRSTRLEN);
			blockingreason = "blocked upstream with known address (IPv4)";
			cacheStatus = QUERY_EXTERNAL_BLOCKED_IP;
			log_debug(DEBUG_QUERIES, "%s -> \"%s\"", blockingreason, answer);
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_IP;
	}
	// Check for IP block ::ffff:146.112.61.104 - ::ffff:146.112.61.110
	else if(flags & F_IPV6 &&
	        addr->addr6.s6_addr32[0] == 0 &&
	        addr->addr6.s6_addr32[1] == 0 &&
	        addr->addr6.s6_addr32[2] == 0xffff0000 &&
	        ipv6Addr >= 0x92703d68 && ipv6Addr <= 0x92703d6e)
	{
		if(config.debug.queries.v.b)
		{
			char answer[ADDRSTRLEN]; answer[0] = '\0';
			inet_ntop(AF_INET6, addr, answer, ADDRSTRLEN);
			blockingreason = "blocked upstream with known address (IPv6)";
			cacheStatus = QUERY_EXTERNAL_BLOCKED_IP;
			log_debug(DEBUG_QUERIES, "%s -> \"%s\"", blockingreason, answer);
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_IP;
	}

	// If upstream replied with 0.0.0.0 or ::,
	// we assume that it filtered the reply as
	// nothing is reachable under these addresses
	else if(flags & F_IPV4 && ipv4Addr == 0)
	{
		if(config.debug.queries.v.b)
		{
			blockingreason = "blocked upstream with 0.0.0.0";
			cacheStatus = QUERY_EXTERNAL_BLOCKED_NULL;
			log_debug(DEBUG_QUERIES, "%s", blockingreason);
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_NULL;
	}
	else if(flags & F_IPV6 &&
	        addr->addr6.s6_addr32[0] == 0 &&
	        addr->addr6.s6_addr32[1] == 0 &&
	        addr->addr6.s6_addr32[2] == 0 &&
	        addr->addr6.s6_addr32[3] == 0)
	{
		if(config.debug.queries.v.b)
		{
			blockingreason = "blocked upstream with ::";
			cacheStatus = QUERY_EXTERNAL_BLOCKED_NULL;
			log_debug(DEBUG_QUERIES, "%s", blockingreason);
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_NULL;
	}

	// Nothing happened here
	return QUERY_UNKNOWN;
}

static void query_blocked(queriesData *query, domainsData *domain, clientsData *client, const enum query_status new_status)
{
	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	// Adjust counters if we recorded a non-blocking status
	if(query->status == QUERY_FORWARDED && query->upstreamID > 0)
	{
		// Get forward pointer
		upstreamsData *upstream = getUpstream(query->upstreamID, true);
		if(upstream != NULL)
			upstream->count--;
	}
	else if(is_blocked(query->status))
	{
		// Already a blocked query, no need to change anything
		return;
	}

	if(is_blocked(new_status))
	{
		// Count as blocked query
		if(domain != NULL)
			domain->blockedcount++;
		if(client != NULL)
			change_clientcount(client, 0, 1, -1, 0);

		query->flags.blocked = true;
	}

	// Update status
	query_set_status(query, new_status);

	// Mark query for updating in the database
	query->flags.database.changed = true;
}

static void FTL_dnssec(const char *arg, const union all_addr *addr, const int id, const char *file, const int line)
{
	// Process DNSSEC result for a domain
	const double now = double_time();

	// Lock shared memory
	lock_shm();

	// Search for corresponding query identified by ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData *query = getQuery(queryID, true);
	if(query == NULL)
	{
		// Memory error, skip this DNSSEC details
		unlock_shm();
		return;
	}

	// Debug logging
	if(config.debug.queries.v.b)
	{
		// Get domain pointer
		const domainsData *domain = getDomain(query->domainID, true);
		if(domain != NULL)
			log_debug(DEBUG_QUERIES, "**** DNSSEC %s is %s (ID %i, %s:%i)", getstr(domain->domainpos), arg, id, file, line);
		if(addr && addr->log.ede != EDE_UNSET) // This function is only called if (flags & F_SECSTAT)
			log_debug(DEBUG_QUERIES, "     EDE: %s (%d)", edestr(addr->log.ede), addr->log.ede);
	}

	// Store EDE
	if(addr && addr->log.ede != EDE_UNSET)
		query->ede = addr->log.ede;

	// Iterate through possible values
	if(strcmp(arg, "SECURE") == 0)
		query_set_dnssec(query, DNSSEC_SECURE);
	else if(strcmp(arg, "INSECURE") == 0)
		query_set_dnssec(query, DNSSEC_INSECURE);
	else if(strcmp(arg, "BOGUS") == 0)
		query_set_dnssec(query, DNSSEC_BOGUS);
	else if(strcmp(arg, "ABANDONED") == 0)
		query_set_dnssec(query, DNSSEC_ABANDONED);
	else if(strcmp(arg, "TRUNCATED") == 0)
		query_set_dnssec(query, DNSSEC_TRUNCATED);
	else
		log_warn("Unknown DNSSEC status \"%s\"", arg);

	// Set reply to NONE (if not already set) as we will not reply to this
	// query when the status is neither SECURE nor INSECURE
	if (query->reply == REPLY_UNKNOWN &&
	    query->dnssec != DNSSEC_SECURE &&
	    query->dnssec != DNSSEC_INSECURE)
	{
		query_set_reply(0, REPLY_NONE, addr, query, now);
	}

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Unlock shared memory
	unlock_shm();
}

static void get_rcode(const unsigned short rcode, const char **rcodestr, enum reply_type *reply)
{
	// Translate dnsmasq's rcode into something we can use
	switch(rcode)
	{
		case SERVFAIL:
			*rcodestr = "SERVFAIL";
			*reply = REPLY_SERVFAIL;
			break;
		case REFUSED:
			*rcodestr = "REFUSED";
			*reply = REPLY_REFUSED;
			break;
		case NOTIMP:
			*rcodestr = "NOT IMPLEMENTED";
			*reply = REPLY_NOTIMP;
			break;
		default:
			*rcodestr = "UNKNOWN";
			*reply = REPLY_OTHER;
			break;
	}
}

static void FTL_upstream_error(const union all_addr *addr, const unsigned int flags, const int id, const char *file, const int line)
{
	// Process local and upstream errors
	// Queries with error are those where the RCODE
	// in the DNS header is neither NOERROR nor NXDOMAIN.

	// Return early if there is nothing we can analyze here (shouldn't happen)
	if(!addr)
		return;

	// Record response time before queuing for the lock
	const double now = double_time();

	// Lock shared memory
	lock_shm();

	// Search for corresponding query identified by ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData *query = getQuery(queryID, true);
	if(query == NULL)
	{
		// Memory error, skip this query
		unlock_shm();
		return;
	}

	// Update upstream server if necessary
	update_upstream(query, id);

	// Translate dnsmasq's rcode into something we can use
	const char *rcodestr = NULL;
	enum reply_type reply = REPLY_UNKNOWN;
	get_rcode(addr->log.rcode, &rcodestr, &reply);

	// Get EDNS data (if available)
	ednsData *edns = getEDNS();

	if(addr->log.ede != EDE_UNSET) // This function is only called if (flags & F_RCODE)
		query->ede = addr->log.ede;

	else if(edns != NULL && edns->ede != EDE_UNSET)
		query->ede = edns->ede;

	// Debug logging
	if(config.debug.queries.v.b)
	{
		// Get domain pointer
		const domainsData *domain = getDomain(query->domainID, true);

		// Get domain name
		const char *domainName = domain != NULL ? getstr(domain->domainpos) : "<cannot access domain struct>";

		if(flags & F_CONFIG)
		{
			// Log local error, typically "nowhere to forward to"
			log_err("**** local error (nowhere to forward to): %s is %s (ID %i, %s:%i)",
			     domainName, rcodestr, id, file, line);
		}
		else if(last_server.sa.sa_family == 0)
		{
			// Log error reply from unknown source
			log_debug(DEBUG_QUERIES, "**** got error reply: %s is %s (ID %i, %s:%i)",
			     domainName, rcodestr, id, file, line);
		}
		else
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			in_port_t port = 0;
			mysockaddr_extract_ip_port(&last_server, ip, &port);
			// Log server which replied to our request
			log_debug(DEBUG_QUERIES, "**** got error reply from %s#%d: %s is %s (ID %i, %s:%i)",
			     ip, port, domainName, rcodestr, id, file, line);
		}

		if(query->reply == REPLY_OTHER)
			log_debug(DEBUG_QUERIES, "     Unknown rcode = %i", addr->log.rcode);

		if(addr->log.ede != EDE_UNSET)
			log_debug(DEBUG_QUERIES, "     EDE: %s (1/%d)", edestr(addr->log.ede), addr->log.ede);

		if(edns != NULL && edns->ede != EDE_UNSET)
			log_debug(DEBUG_QUERIES, "     EDE: %s (2/%d)", edestr(edns->ede), edns->ede);
	}

	// Set query reply
	query_set_reply(0, reply, addr, query, now);

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Reset last_server
	memset(&last_server, 0, sizeof(last_server));

	// Unlock shared memory
	unlock_shm();
}

static void FTL_blocked_upstream_by_header(const enum query_status new_status, const int id, const char *file, const int line)
{
	// Get response time
	const double now = double_time();

	// Lock shared memory
	lock_shm();

	// Search for corresponding query identified by ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData *query = getQuery(queryID, true);
	if(query == NULL)
	{
		// Memory error, skip this query
		unlock_shm();
		return;
	}

	// Get domain pointer
	domainsData *domain = getDomain(query->domainID, true);
	if(domain == NULL)
	{
		// Memory error, skip this query
		unlock_shm();
		return;
	}

	// Possible debugging information
	if(config.debug.queries.v.b)
	{
		// Get domain name (domain cannot be NULL here)
		const char *domainstr = getstr(domain->domainpos);
		log_debug(DEBUG_QUERIES, "**** %s externally blocked by header (ID %i, FTL %i, %s:%i)", domainstr, id, queryID, file, line);
	}

	// Set blocking reason
	blockingreason = new_status == QUERY_EXTERNAL_BLOCKED_NXRA ?
	                 "blocked upstream with NXDOMAIN + no RA" :
	                 "blocked upstream with EDE15";
	cacheStatus = new_status;

	// Store query as externally blocked
	clientsData *client = getClient(query->clientID, true);
	if(client != NULL)
		query_blocked(query, domain, client, new_status);

	// Store reply type as replied with NXDOMAIN
	query_set_reply(F_NEG | F_NXDOMAIN, 0, NULL, query, now);

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Unlock shared memory
	unlock_shm();
}

static void FTL_blocked_upstream_by_addr(const enum query_status new_status, const int id, const char *file, const int line)
{
	// Lock shared memory
	lock_shm();

	// Save status in corresponding query identified by dnsmasq's ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was "pi.hole"
		log_debug(DEBUG_QUERIES, "FTL_check_reply(): Query %i has not been found", id);
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData *query = getQuery(queryID, true);
	if(query == NULL)
	{
		// Memory error, skip this query
		log_debug(DEBUG_QUERIES, "FTL_check_reply(): Memory error (ID %i)", id);
		unlock_shm();
		return;
	}
	clientsData *client = getClient(query->clientID, true);
	domainsData *domain = getDomain(query->domainID, true);
	if(client != NULL && domain != NULL)
		query_blocked(query, domain, client, new_status);

	// Possible debugging information
	if(config.debug.queries.v.b)
	{
		// Get domain name (domain cannot be NULL here)
		const char *domainName = domain ? getstr(domain->domainpos) : "<cannot access domain>";
		log_debug(DEBUG_QUERIES, "**** %s externally blocked by address (ID %i, FTL %i, %s:%i)", domainName, id, queryID, file, line);
	}

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Unlock shared memory
	unlock_shm();
}

int _FTL_check_reply(const unsigned int rcode, const unsigned short flags,
                     const union all_addr *addr,
                     const int id, const char *file, const int line)
{
	// Get EDE data (if available)
	const ednsData *edns = getEDNS();

	// Check if RA and AA bits are unset in DNS header and rcode is NXDOMAIN
	// If the response code (rcode) is NXDOMAIN, we may be seeing a response from
	// an externally blocked query. As they are not always accompany a necessary
	// SOA record, they are not getting added to our cache and, therefore,
	// FTL_reply() is never getting called from within the cache routines.
	// Hence, we have to store the necessary information about the NXDOMAIN
	// reply already here.
	// Alternatively, we also consider EDE15 as a blocking reason.
	if(addr == NULL)
	{
		// RA and AA bits are not set and rcode is NXDOMAIN
		if(!rabit && !aabit && rcode == NXDOMAIN)
		{
			FTL_blocked_upstream_by_header(QUERY_EXTERNAL_BLOCKED_NXRA, id, file, line);

			// Query is blocked
			return 1;
		}

		// EDE 15
		if(edns != NULL && edns->ede == EDE_BLOCKED)
		{
			FTL_blocked_upstream_by_header(QUERY_EXTERNAL_BLOCKED_EDE15, id, file, line);

			// Query is blocked
			return 1;
		}
	}
	// Further checks if this is an IP address
	else
	{
		// Detect if returned IP indicates that this query was blocked
		const enum query_status new_qstatus = detect_blocked_IP(flags, addr);

		// Update status of this query if detected as external blocking
		if(new_qstatus != QUERY_UNKNOWN)
		{
			FTL_blocked_upstream_by_addr(new_qstatus, id, file, line);

			// Query is blocked upstream

			// Return true for any status except known blocking page
			// IP address to short-circut the answer. In the latter case,
			// we want to continue processing the query to get the correct
			// reply downstream to the requesting client.
			return new_qstatus != QUERY_EXTERNAL_BLOCKED_IP;
		}
	}

	return 0;
}

void _FTL_header_analysis(const struct dns_header *header, const struct server *server,
                          const int id, const char *file, const int line)
{
	// Analyze DNS header bits

	// Check if AD bit is set in DNS header
	adbit = header->hb4 & HB4_AD;

	// Check if RA and AA bit is set in DNS header. We do it here as it is it is
	// forced by dnsmasq shortly after calling FTL_header_analysis()
	rabit = header->hb4 & HB4_RA;
	aabit = header->hb3 & HB3_AA;

	// Store server which sent this reply (if applicable)
	if(server)
	{
		memcpy(&last_server, &server->addr, sizeof(last_server));
		if(config.debug.extra.v.b)
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			in_port_t port = 0;
			mysockaddr_extract_ip_port(&last_server, ip, &port);
			log_debug(DEBUG_EXTRA, "Got forward address: %s#%u for ID %i (%s:%i)",
			          ip, port, id, short_path(file), line);
		}
	}
	else
	{
		memset(&last_server, 0, sizeof(last_server));
		log_debug(DEBUG_EXTRA, "Got forward address: NO for ID %i (%s:%i)",
		          id, short_path(file), line);
	}
}

void print_flags(const unsigned int flags)
{
	// Debug function, listing resolver flags in clear text
	// e.g. "Flags: F_FORWARD F_NEG F_IPV6"

	// Only print flags if corresponding debugging flag is set
	if(!(config.debug.flags.v.b))
		return;

	char *flagstr = calloc(sizeof(flagnames) + 1, sizeof(char));
	for (unsigned int i = 0; i < ArraySize(flagnames); i++)
		if (flags & (1u << i))
			strcat(flagstr, flagnames[i]);
	log_debug(DEBUG_FLAGS, "     Flags: %s", flagstr);
	free(flagstr);
}

static void _query_set_reply(const unsigned int flags, const enum reply_type reply,
                             const union all_addr *addr,
                             queriesData *query, const double now,
                             const char *file, const int line)
{
	enum reply_type new_reply = REPLY_UNKNOWN;
	// If reply is set, we use it directly instead of interpreting the flags
	if(reply != 0)
	{
		new_reply = reply;
	}
	// else: Iterate through possible values by analyzing both the flags and the addr bits
	else if(flags & F_NEG ||
	        (flags & F_NOERR && !(flags & (F_IPV4 | F_IPV6))) || // <-- FTL_make_answer() when no A or AAAA is added
	        force_next_DNS_reply == REPLY_NXDOMAIN ||
	        force_next_DNS_reply == REPLY_NODATA)
	{
		if(flags & F_NXDOMAIN || force_next_DNS_reply == REPLY_NXDOMAIN)
			// NXDOMAIN
			new_reply = REPLY_NXDOMAIN;
		else
			// NODATA(-IPv6)
			new_reply = REPLY_NODATA;
	}
	else if(flags & F_CNAME)
		// <CNAME>
		new_reply = REPLY_CNAME;
	else if(flags & F_REVERSE)
		// reserve lookup
		new_reply = REPLY_DOMAIN;
	else if(flags & F_RRNAME)
		// TXT query
		new_reply = REPLY_RRNAME;
	else if((flags & F_RCODE && addr != NULL) || force_next_DNS_reply == REPLY_REFUSED)
	{
		if((addr != NULL && addr->log.rcode == REFUSED)
		   || force_next_DNS_reply == REPLY_REFUSED )
		{
			// REFUSED query
			new_reply = REPLY_REFUSED;
		}
		else if(addr != NULL && addr->log.rcode == SERVFAIL)
		{
			// SERVFAIL query
			new_reply = REPLY_SERVFAIL;
		}
		else if(addr != NULL && addr->log.rcode == NOTIMP)
		{
			// NOTIMP query
			new_reply = REPLY_NOTIMP;
		}
		else
		{
			// Other RCODE
			new_reply = REPLY_OTHER;
		}
	}
	else if(flags & F_KEYTAG && flags & F_NOEXTRA)
	{
		// Since 451bd35ad62c1444b3ef1d204ab606c0098b2fd9, F_KEYTAG is
		// overloaded to discriminate cache records between an arbitrary
		// RR stored entirely in the addr union and one which has a
		// point to block storage
		new_reply = REPLY_DNSSEC;
	}
	else if(force_next_DNS_reply == REPLY_NONE)
	{
		new_reply = REPLY_NONE;
	}
	else if(flags & (F_IPV4 | F_IPV6))
	{
		// IP address
		new_reply = REPLY_IP;
	}
	else
	{
		// Other binary, possibly proprietry, data
		new_reply = REPLY_BLOB;
	}

	if(config.debug.queries.v.b)
	{
		const char *path = short_path(file);
		log_debug(DEBUG_QUERIES, "Set reply to %s (%d) in %s:%d", get_query_reply_str(new_reply), new_reply, path, line);
		if(query->reply != REPLY_UNKNOWN && query->reply != new_reply)
			log_debug(DEBUG_QUERIES, "Reply of query %i was %s now changing to %s", query->id,
			          get_query_reply_str(query->reply), get_query_reply_str(new_reply));
	}

	// Subtract from old reply counter
	counters->reply[query->reply]--;
	log_debug(DEBUG_STATUS, "reply type %u removed (set_reply), ID = %d, new count = %u", query->reply, query->id, counters->reply[query->reply]);
	// Add to new reply counter
	counters->reply[new_reply]++;
	// Store reply type
	query->reply = new_reply;
	log_debug(DEBUG_STATUS, "reply type %u added (set_reply), ID = %d, new count = %u", query->reply, query->id, counters->reply[query->reply]);

	// Save response time
	// Skipped internally if already computed
	set_response_time(query, now);
}

void FTL_fork_and_bind_sockets(struct passwd *ent_pw, bool dnsmasq_start)
{
	// Going into daemon mode involves storing the
	// PID of the generated child process. If FTL
	// is asked to stay in foreground, we just save
	// the PID of the current process in the PID file
	if(daemonmode)
		go_daemon();
	else
		savePID();

	// Initialize query database (pihole-FTL.db)
	db_init();

	// Initialize in-memory databases
	if(!init_memory_database())
		log_crit("Cannot initialize in-memory database.");

	// Flush messages stored in the long-term database
	if(!FTLDBerror())
		flush_message_table();

	// Verify checksum of this binary early on to ensure that the binary is
	// not corrupted and that the binary is not tampered with. We can only
	// do this here as we need the database to be properly initialized
	// in case we need to store the verification result
	verify_FTL(false);

	// Initialize in-memory database starting index
	init_disk_db_idx();

	// Handle real-time signals in this process (and its children)
	// Helper processes are already split from the main instance
	// so they will not listen to real-time signals
	handle_realtime_signals();

	// Initialize thread attributes object with default attribute values
	// Do NOT detach threads as we want to join them during shutdown with a
	// fixed timeout to give them time to clean up and finish their work
	pthread_attr_t attr;
	pthread_attr_init(&attr);

	// Start NTP sync thread
	ntp_start_sync_thread(&attr);

	// Start database thread if database is used
	if(pthread_create( &threads[DB], &attr, DB_thread, NULL ) != 0)
	{
		log_crit("Unable to create database thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until garbage
	// collection needs to be done
	if(pthread_create( &threads[GC], &attr, GC_thread, NULL ) != 0)
	{
		log_crit("Unable to create GC thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until host names needs to
	// be resolved. If configuration does not ask for never resolving hostnames
	// (e.g. on CI builds), the thread is never started)
	if(dnsmasq_start &&
	   resolve_names() &&
	   pthread_create( &threads[DNSclient], &attr, DNSclient_thread, NULL ) != 0)
	{
		log_crit("Unable to create DNS client thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that checks various timers, e.g., for automatic changing
	// blocking mode (enabled/disabled for a given amount of time)
	if(pthread_create( &threads[TIMER], &attr, timer, NULL ) != 0)
	{
		log_crit("Unable to create timer thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start webserver thread
	if(pthread_create( &threads[WEBSERVER], &attr, webserver_thread, NULL ) != 0)
	{
		log_crit("Unable to create webserver thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Chown files if FTL started as user root but a dnsmasq config
	// option states to run as a different user/group (e.g. "nobody")
	if(getuid() == 0)
	{
		// Only print this and change ownership of shmem objects when
		// we're actually dropping root (user/group may be set to root)
		if(ent_pw != NULL && ent_pw->pw_uid != 0)
		{
			log_info("FTL is going to drop from root to user pihole");

			// Change ownership of shared memory objects
			chown_all_shmem(ent_pw);

			// Configured FTL log file
			chown_pihole(config.files.log.ftl.v.s, ent_pw);

			// Configured FTL database file
			chown_pihole(config.files.database.v.s, ent_pw);

			// Check if auxiliary files exist and change ownership
			char *extrafile = calloc(strlen(config.files.database.v.s) + 5, sizeof(char));
			if(extrafile == NULL)
			{
				log_err("Memory allocation failed. Skipping some file ownership checks.");
				return;
			}

			// Check <database>-wal file (write-ahead log)
			strcpy(extrafile, config.files.database.v.s);
			strcat(extrafile, "-wal");
			if(file_exists(extrafile))
				chown_pihole(extrafile, ent_pw);

			// Check <database>-shm file (mmapped shared memory)
			strcpy(extrafile, config.files.database.v.s);
			strcat(extrafile, "-shm");
			if(file_exists(extrafile))
				chown_pihole(extrafile, ent_pw);

			// Free allocated memory
			free(extrafile);
		}
		else
		{
			log_info("FTL is running as root");
		}
	}
	else
	{
		uid_t uid;
		struct passwd *current_user;
		if ((current_user = getpwuid(uid = geteuid())) != NULL)
			log_info("FTL is running as user %s (UID %d)",
			     current_user->pw_name, (int)current_user->pw_uid);
		else
			log_info("Failed to obtain information about FTL user");
	}

	// Initialize FTL HTTP server
	http_init();

	forked = true;
}

static char *get_ptrname(const struct in_addr *addr)
{
	static char *ptrname = NULL;

	// Return cached value if available
	if(ptrname)
		return ptrname;

	// else: Determine name that should be replied to with on Pi-hole PTRs
	switch (config.dns.piholePTR.v.ptr_type)
	{
		default:
		case PTR_MAX:
		case PTR_NONE:
		case PTR_PIHOLE:
			ptrname = (char*)"pi.hole";
			break;

		case PTR_HOSTNAME:
			ptrname = (char*)hostname();
			break;

		case PTR_HOSTNAMEFQDN:
		{
			const char *suffix;
			size_t ptrnamesize = 0;
			// get_domain() will also check conditional domains configured like
			// domain=<domain>[,<address range>[,local]]
			if(addr)
				suffix = get_domain(*addr);
			else
				suffix = daemon->domain_suffix;

			// If local suffix is not available, we try to obtain the domain from
			// the kernel similar to how we do it for the hostname
			if(!suffix)
				suffix = (char*)domainname();

			// If local suffix is not available, we substitute "no_fqdn_available"
			// see the comment about PIHOLE_PTR=HOSTNAMEFQDN in the Pi-hole docs
			// for further details on why this was chosen
			if(!suffix || suffix[0] == '\0')
				suffix = (char*)"no_fqdn_available";

			// Get enough space for domain building
			size_t needspace = strlen(hostname()) + strlen(suffix) + 2;
			if(ptrnamesize < needspace)
			{
				ptrname = realloc(ptrname, needspace);
				ptrnamesize = needspace;
			}

			if(ptrname)
			{
				// Build "<hostname>.<local suffix>" domain
				strcpy(ptrname, hostname());
				strcat(ptrname, ".");
				strcat(ptrname, suffix);
			}
			else
			{
				// Fallback to "<hostname>" on memory error
				ptrname = (char*)hostname();
			}
			break;
		}
	}

	return ptrname;
}

void FTL_forwarding_retried(struct frec *forward, const int newID, const bool dnssec)
{
	// Forwarding to upstream server failed
	const struct server *serv = forward->sentto;
	const int oldID = forward->frec_src.log_id;
	if(oldID == newID)
	{
		log_debug(DEBUG_QUERIES, "%d: Ignoring self-retry", oldID);
		return;
	}

	// Lock shared memory
	lock_shm();

	// Try to obtain destination IP address if available
	char dest[ADDRSTRLEN];
	in_port_t upstreamPort = 53;
	dest[0] = '\0';
	if(serv != NULL)
	{
		if(serv->addr.sa.sa_family == AF_INET)
		{
			inet_ntop(AF_INET, &serv->addr.in.sin_addr, dest, ADDRSTRLEN);
			upstreamPort = ntohs(serv->addr.in.sin_port);
		}
		else
		{
			inet_ntop(AF_INET6, &serv->addr.in6.sin6_addr, dest, ADDRSTRLEN);
			upstreamPort = ntohs(serv->addr.in6.sin6_port);
		}
	}

	// Convert upstream to lower case
	char upstreamIP[INET6_ADDRSTRLEN];
	strncpy(upstreamIP, dest, INET6_ADDRSTRLEN);
	upstreamIP[INET6_ADDRSTRLEN - 1] = '\0';
	strtolower(upstreamIP);

	// Get upstream ID
	const int upstreamID = findUpstreamID(upstreamIP, upstreamPort);

	// Possible debugging information
	log_debug(DEBUG_QUERIES, "**** RETRIED%s query %i as %i to %s#%d",
	          dnssec ? " DNSSEC" : "", oldID, newID,
	          upstreamIP, upstreamPort);

	// Get upstream pointer
	upstreamsData *upstream = getUpstream(upstreamID, true);

	// Update counter
	if(upstream != NULL)
		upstream->failed++;

	// Search for corresponding query identified by ID
	// Retried DNSSEC queries are ignored, we have to flag themselves (newID)
	// Retried normal queries take over, we have to flag the original query (oldID)
	const int queryID = findQueryID(dnssec ? newID : oldID);
	if(queryID >= 0)
	{
		// Get query pointer
		queriesData *query = getQuery(queryID, true);

		// Set retried status
		if(query != NULL)
		{
			if(dnssec)
			{
				// There is no point in retrying the query when
				// we've already got an answer to this query,
				// but we're awaiting keys for DNSSEC
				// validation. We're retrying the DNSSEC query
				// instead
				query_set_status(query, QUERY_RETRIED_DNSSEC);
			}
			else
			{
				// Normal query retry due to answer not arriving
				// soon enough at the requestor
				query_set_status(query, QUERY_RETRIED);
			}

			// Mark query for updating in the database
			query->flags.database.changed = true;
		}
	}

	// Unlock shared memory
	unlock_shm();
	return;
}

// Called when a (forked) TCP worker is terminated by receiving SIGALRM
// We close the dedicated database connection this client had opened
// to avoid dangling database locks
volatile atomic_flag worker_already_terminating = ATOMIC_FLAG_INIT;
void FTL_TCP_worker_terminating(bool finished)
{
	if(get_dnsmasq_debug())
	{
		// Nothing to be done here, forking does not happen in debug mode
		return;
	}

	if(atomic_flag_test_and_set(&worker_already_terminating))
	{
		log_debug(DEBUG_ANY, "TCP worker already terminating!");
		return;
	}

	// Possible debug logging
	if(config.debug.queries.v.b)
	{
		const char *reason = finished ? "client disconnected" : "timeout";
		log_debug(DEBUG_ANY, "TCP worker terminating (%s)", reason);
	}

	if(main_pid() == getpid())
	{
		// If this is not really a fork (e.g. in debug mode), we don't
		// actually close gravity here
		return;
	}

	// First check if we already locked before. This can happen when a fork
	// is running into a timeout while it is still processing something and
	// still holding a lock.
	if(!is_our_lock())
		lock_shm();

	// Close dedicated database connections of this fork
	gravityDB_close();
	unlock_shm();
}

// Called when a (forked) TCP worker is created
// FTL forked to handle TCP connections with dedicated (forked) workers
// SQLite3's mentions that carrying an open database connection across a
// fork() can lead to all kinds of locking problems as SQLite3 was not
// intended to work under such circumstances. Doing so may easily lead
// to ending up with a corrupted database.
void FTL_TCP_worker_created(const int confd)
{
	if(get_dnsmasq_debug())
	{
		// Nothing to be done here, TCP worker forking does not happen
		// in debug mode
		return;
	}

	// Print this if debugging is enabled
	if(config.debug.queries.v.b)
	{
		// Get peer IP address (client)
		char peer_ip[ADDRSTRLEN] = { 0 };
		union mysockaddr peer_sockaddr = {};
		socklen_t peer_len = sizeof(union mysockaddr);
		if (getpeername(confd, (struct sockaddr *)&peer_sockaddr, &peer_len) != -1)
		{
			union all_addr peer_addr = {};
			if (peer_sockaddr.sa.sa_family == AF_INET6)
				peer_addr.addr6 = peer_sockaddr.in6.sin6_addr;
			else
				peer_addr.addr4 = peer_sockaddr.in.sin_addr;
			inet_ntop(peer_sockaddr.sa.sa_family, &peer_addr, peer_ip, ADDRSTRLEN);
		}

		// Get local IP address (interface)
		char local_ip[ADDRSTRLEN] = { 0 };
		union mysockaddr iface_sockaddr = {};
		socklen_t iface_len = sizeof(union mysockaddr);
		if(getsockname(confd, (struct sockaddr *)&iface_sockaddr, &iface_len) != -1)
		{
			union all_addr iface_addr = {};
			if (iface_sockaddr.sa.sa_family == AF_INET6)
				iface_addr.addr6 = iface_sockaddr.in6.sin6_addr;
			else
				iface_addr.addr4 = iface_sockaddr.in.sin_addr;
			inet_ntop(iface_sockaddr.sa.sa_family, &iface_addr, local_ip, ADDRSTRLEN);
		}

		// Print log
		log_debug(DEBUG_ANY, "TCP worker forked for client %s on interface %s with IP %s", peer_ip, next_iface.name, local_ip);
	}

	if(main_pid() == getpid())
	{
		// If this is not really a fork (e.g. in debug mode), we don't
		// actually re-open gravity or close sockets here
		return;
	}

	// Reopen gravity database handle in this fork as the main process's
	// handle isn't valid here
	log_debug(DEBUG_ANY, "Reopening Gravity database for this fork");
	gravityDB_forked();
}

bool FTL_unlink_DHCP_lease(const char *ipaddr, const char **hint)
{
	struct dhcp_lease *lease;
	union all_addr addr;
	const time_t now = dnsmasq_time();

	if(!daemon->dhcp)
	{
		*hint = "DHCP is not enabled";
		return false;
	}

	// Try to extract IP address
	if (inet_pton(AF_INET, ipaddr, &addr.addr4) > 0)
	{
		lease = lease_find_by_addr(addr.addr4);
	}
#ifdef HAVE_DHCP6
	else if (inet_pton(AF_INET6, ipaddr, &addr.addr6) > 0)
	{
		lease = lease6_find_by_plain_addr(&addr.addr6);
	}
#endif
	else
	{
		// Invalid IP address
		*hint = "invalid target address (neither IPv4 nor IPv6)";
		return false;
	}

	// If a lease exists for this IP address, we unlink it and immediately
	// update the lease file to reflect the removal of this lease
	if (lease)
	{
		// Unlink the lease for dnsmasq's database
		lease_prune(lease, now);
		// Update the lease file
		lease_update_file(now);
		// Argument force == 0 ensures the DNS records are only updated
		// when unlinking the lease above actually changed something
		// (variable lease.c:dns_dirty is used here)
		lease_update_dns(0);
	}
	else
	{
		*hint = NULL;
		return false;
	}

	// Return success
	return true;
}

void FTL_query_in_progress(const int id)
{
	// Query (possibly from new source), but the same query may be in
	// progress from another source.

	// Lock shared memory
	lock_shm();

	// Search for corresponding query identified by ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData *query = getQuery(queryID, true);
	if(query == NULL)
	{
		// Memory error, skip this DNSSEC details
		unlock_shm();
		return;
	}

	// Debug logging
	if(config.debug.queries.v.b)
	{
		// Get domain pointer
		const domainsData *domain = getDomain(query->domainID, true);
		if(domain != NULL)
		{
			log_debug(DEBUG_QUERIES, "**** query for %s is already in progress (ID %i)", getstr(domain->domainpos), id);
		}
	}

	// Store status
	query_set_status(query, QUERY_IN_PROGRESS);

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Unlock shared memory
	unlock_shm();
}

void FTL_multiple_replies(const int id, int *firstID)
{
	// We are in the loop that iterates over all aggregated queries for the same
	// type + domain. Every query will receive the reply here so we need to
	// update the original queries to set their status

	// Don't process self-duplicates
	if(*firstID == id)
		return;

	// Skip if the original query was not found in FTL's memory
	if(*firstID == -2)
		return;

	// Lock shared memory
	lock_shm();

	// Search for corresponding query identified by ID
	const int queryID = findQueryID(id);
	if(queryID < 0)
	{
		// This may happen e.g. if the original query was an unhandled query type
		unlock_shm();
		*firstID = -2;
		return;
	}

	if(*firstID == -1)
	{
		// This is not yet a duplicate, we just store the ID
		// of the successful reply here so we can get it quicker
		// during the next loop iterations
		unlock_shm();
		*firstID = queryID;
		return;
	}

	// Get (read-only) pointer of the query that contains all relevant
	// information (all others are mere duplicates and were only added to the
	// list of duplicates rather than havong been forwarded on their own)
	const queriesData *source_query = getQuery(*firstID, true);
	// Get query pointer of duplicated reply
	queriesData *duplicated_query = getQuery(queryID, true);

	if(duplicated_query == NULL || source_query == NULL)
	{
		// Memory error, skip this duplicate
		unlock_shm();
		return;
	}

	// Debug logging
	log_debug(DEBUG_QUERIES, "**** sending reply %d also to %d", *firstID, queryID);

	// Copy relevant information over
	counters->reply[duplicated_query->reply]--;
	log_debug(DEBUG_STATUS, "duplicated_query reply type %u removed, ID = %d, new count = %u", duplicated_query->reply, duplicated_query->id, counters->reply[duplicated_query->reply]);
	duplicated_query->reply = source_query->reply;
	counters->reply[duplicated_query->reply]++;
	log_debug(DEBUG_STATUS, "duplicated_query reply type %u set, ID = %d, new count = %u", duplicated_query->reply, duplicated_query->id, counters->reply[duplicated_query->reply]);

	duplicated_query->dnssec = source_query->dnssec;
	duplicated_query->flags.complete = true;
	duplicated_query->CNAME_domainID = source_query->CNAME_domainID;

	// The original query may have been blocked during CNAME inspection,
	// correct status in this case
	if(source_query->status != QUERY_FORWARDED)
		query_set_status(duplicated_query, source_query->status);

	// Mark query for updating in the database
	duplicated_query->flags.database.changed = true;

	// Unlock shared memory
	unlock_shm();
}

static void _query_set_dnssec(queriesData *query, const enum dnssec_status dnssec, const char *file, const int line)
{
	// Return early if DNSSEC validation is disabled
	if(!option_bool(OPT_DNSSEC_VALID) && !option_bool(OPT_DNSSEC_PROXY))
		return;

	if(config.debug.dnssec.v.b)
	{
		const char *path = short_path(file);
		const char *status = get_query_dnssec_str(dnssec);
		log_debug(DEBUG_DNSSEC, "Setting DNSSEC status to %s in %s:%d", status, path, line);
	}

	// Set DNSSEC status
	query->dnssec = dnssec;
}

// Add dnsmasq log line to internal FIFO buffer (can be queried via the API)
void FTL_dnsmasq_log(const char *payload, const int length)
{
	// Lock SHM
	lock_shm();

	// Add to FIFO buffer
	add_to_fifo_buffer(FIFO_DNSMASQ, payload, NULL, length);

	// Unlock SHM
	unlock_shm();
}

static const char *check_dnsmasq_name(const char *name)
{
	// Special domain name handling
	if(!name)
		// 1. Substitute "(NULL)" if no name is available (should not happen)
		return "(NULL)";
	else if(!name[0])
		// 2. Substitute "." if we are querying the root domain (e.g. DNSKEY)
		return ".";
	// else
	return name;
}

void get_dnsmasq_metrics_obj(cJSON *json)
{
	for (unsigned int i = 0; i < __METRIC_MAX; i++)
		cJSON_AddNumberToObject(json, get_metric_name(i), daemon->metrics[i]);
}

void FTL_connection_error(const char *reason, const union mysockaddr *addr, const char where)
{
	// Backup errno
	const int errnum = errno;

	// Get the error message
	const char *error = strerror(errnum);

	// Set log priority
	int priority = LOG_ERR;

	// Additional information (if available)
	const char *extra = "";
	if(where == 1)
		extra = " while connecting to upstream";
	else if(where == 2)
		extra = " while sending data upstream";
	else if(where == 3)
		extra = " while receiving payload length from upstream";
	else if(where == 4)
		extra = " while receiving payload data from upstream";

	// If this is a TCP connection error and errno == 0, this isn't a
	// connection error but the remote side closed the connection
	if(errnum == 0 && strcmp(reason, "TCP connection failed") == 0)
	{
		error = "Connection prematurely closed by remote server";
		priority = LOG_INFO;
	}

	// Format the address into a string (if available)
	in_port_t port = 0;
	char ip[ADDRSTRLEN + 1] = { 0 };
	if(addr != NULL)
		mysockaddr_extract_ip_port(addr, ip, &port);

	// Get query ID, may be negative if this is a TCP query
	const int id = daemon->log_display_id > 0 ? daemon->log_display_id : -daemon->log_display_id;
	// Log to FTL.log
	log_debug(DEBUG_QUERIES, "Connection error (%s#%u, ID %d): %s (%s)%s", ip, port, id, reason, error, extra);

	// Log to pihole.log
	my_syslog(priority, "%s: %s", reason, error);

	// Add to Pi-hole diagnostics but do not add messages more often than
	// once every five seconds to avoid hammering the database with errors
	// on continuously failing connections
	static time_t last = 0;
	if(time(NULL) - last > 5)
	{
		// Update last time
		last = time(NULL);

		// Build server string
		char *server = NULL;
		if(ip[0] != '\0')
		{
			const size_t len = strlen(ip) + 7;
			server = calloc(len, sizeof(char));
			if(server != NULL)
			{
				snprintf(server, len, "%s#%u", ip, port);
				server[len - 1] = '\0';
			}
		}

		// Extend reason with extra information (if available)
		char *reason_extended = (char *)reason;
		bool allocated = false;
		if(extra[0] != '\0')
		{
			const size_t len = strlen(reason) + strlen(extra) + 3;
			reason_extended = calloc(len, sizeof(char));
			if(reason_extended != NULL)
			{
				snprintf(reason_extended, len, "%s%s", reason, extra);
				reason_extended[len - 1] = '\0';
				allocated = true;
			}
		}

		// Log connection error
		log_connection_error(server, reason_extended, error);

		// Free allocated memory
		if(server != NULL)
			free(server);
		if(allocated)
			free(reason_extended);
	}

	// Restore errno for dnsmaq logging routines
	errno = errnum;
}

/**
 * @brief Retrieves the debug status of dnsmasq.
 *
 * @return true if the debug option is enabled, false otherwise.
 */
bool __attribute__ ((pure)) get_dnsmasq_debug(void)
{
	return option_bool(OPT_DEBUG);
}

static bool enabled = false;
/**
 * @brief Set the dnsmasq debug mode based on the enable flag and process ID.
 *
 * This function enables or disables the dnsmasq debug mode. When enabling,
 * it logs the process ID and name, sets the debug option, and marks the
 * debug mode as enabled. When disabling, it logs the detachment and clears
 * the debug option. If the debug mode is already enabled, it does nothing.
 *
 * @param enable A boolean flag indicating whether to enable or disable debug mode.
 * @param pid The process ID of the process to attach or detach the debugger.
 */
void set_dnsmasq_debug(const bool enable, const pid_t pid)
{
	// Get debugger process' name
	char name[PROC_PATH_SIZ] = "???";
	get_process_name(pid, name);

	// Only enable or disable if the debug mode is not already set
	if(enable && !get_dnsmasq_debug())
	{
		// Enable debug mode
		log_info("Debugger attached (%d: %s), entering dnsmasq debug mode",
		         pid, name);
		option_set(OPT_DEBUG);
		enabled = true;

		return;
	}
	else if(enabled)
	{
		// Disable debug mode
		log_info("Debugger detached, leaving dnsmasq debug mode");
		option_clear(OPT_DEBUG);
	}
}
