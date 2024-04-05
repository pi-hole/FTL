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
// get_edestr()
#include "api/api_helper.h"
// logg_rate_limit_message()
#include "database/message-table.h"
// http_init()
#include "webserver/webserver.h"
// type struct sqlite3_stmt_vec
#include "vector.h"
// check_one_struct()
#include "struct_size.h"
// query_to_database()
#include "database/query-table.h"
// reread_config()
#include "config/config.h"
// FTL_fork_and_bind_sockets()
#include "main.h"

// Private prototypes
static void print_flags(const unsigned int flags);
#define query_set_reply(flags, type, addr, query, response) _query_set_reply(flags, type, addr, query, response, __FILE__, __LINE__)
static void _query_set_reply(const unsigned int flags, const enum reply_type reply, const union all_addr *addr, queriesData* query,
                             const struct timeval response, const char *file, const int line);
#define FTL_check_blocking(queryID, domainID, clientID) _FTL_check_blocking(queryID, domainID, clientID, __FILE__, __LINE__)
static bool _FTL_check_blocking(int queryID, int domainID, int clientID, const char* file, const int line);
static enum query_status detect_blocked_IP(const unsigned short flags, const union all_addr *addr, const queriesData *query, const domainsData *domain);
static void query_blocked(queriesData* query, domainsData* domain, clientsData* client, const enum query_status new_status);
static void FTL_forwarded(const unsigned int flags, const char *name, const union all_addr *addr, unsigned short port, const int id, const char* file, const int line);
static void FTL_reply(const unsigned int flags, const char *name, const union all_addr *addr, const char* arg, const int id, const char* file, const int line);
static void FTL_upstream_error(const union all_addr *addr, const unsigned int flags, const int id, const char* file, const int line);
static void FTL_dnssec(const char *result, const union all_addr *addr, const int id, const char* file, const int line);
static void mysockaddr_extract_ip_port(union mysockaddr *server, char ip[ADDRSTRLEN+1], in_port_t *port);
static void alladdr_extract_ip(union all_addr *addr, const sa_family_t family, char ip[ADDRSTRLEN+1]);
static void check_pihole_PTR(char *domain);
#define query_set_dnssec(query, dnssec) _query_set_dnssec(query, dnssec, __FILE__, __LINE__)
static void _query_set_dnssec(queriesData *query, const enum dnssec_status dnssec, const char *file, const int line);
static char *get_ptrname(struct in_addr *addr);
static const char *check_dnsmasq_name(const char *name);

// Static blocking metadata
static bool adbit = false;
static const char *blockingreason = "";
static enum reply_type force_next_DNS_reply = REPLY_UNKNOWN;
static int last_regex_idx = -1;
static struct ptr_record *pihole_ptr = NULL;
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
} next_iface = {false, false, "", {{ 0 }}, {{ 0 }}};

// Fork-private copy of the server data the most recent reply came from
static union mysockaddr last_server = {{ 0 }};

unsigned char* pihole_privacylevel = &config.misc.privacylevel.v.privacy_level;
const char *flagnames[] = {"F_IMMORTAL ", "F_NAMEP ", "F_REVERSE ", "F_FORWARD ", "F_DHCP ", "F_NEG ", "F_HOSTS ", "F_IPV4 ", "F_IPV6 ", "F_BIGNAME ", "F_NXDOMAIN ", "F_CNAME ", "F_DNSKEY ", "F_CONFIG ", "F_DS ", "F_DNSSECOK ", "F_UPSTREAM ", "F_RRNAME ", "F_SERVER ", "F_QUERY ", "F_NOERR ", "F_AUTH ", "F_DNSSEC ", "F_KEYTAG ", "F_SECSTAT ", "F_NO_RR ", "F_IPSET ", "F_NOEXTRA ", "F_DOMAINSRV", "F_RCODE", "F_RR", "F_STALE" };

void FTL_hook(unsigned int flags, const char *name, union all_addr *addr, char *arg, int id, unsigned short type, const char* file, const int line)
{
	// Extract filename from path
	const char *path = short_path(file);
	const char *types = (flags & F_RR) ? querystr(arg, type) : "?";
	log_debug(DEBUG_FLAGS, "Processing FTL hook from %s:%d (type: %s, name: \"%s\", id: %i)...", path, line, types, name, id);
	print_flags(flags);

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
size_t _FTL_make_answer(struct dns_header *header, char *limit, const size_t len, int *ede, const char *file, const int line)
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
	if(*ede != EDE_UNSET)
		log_debug(DEBUG_QUERIES, "Preparing reply for \"%s\", EDE: %s (%d)", name, edestr(*ede), *ede);
	else
		log_debug(DEBUG_QUERIES, "Preparing reply for \"%s\", EDE: N/A", name);

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

		// Set EDE code to blocked
		*ede = EDE_BLOCKED;
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
	union all_addr redirect_addr4 = {{ 0 }}, redirect_addr6 = {{ 0 }};
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

	// Debug logging
	print_flags(flags);

	// Setup reply header
	setup_reply(header, flags, *ede);

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
		union all_addr addr = {{ 0 }};

		// Overwrite with IP address if requested
		if(redirecting)
			memcpy(&addr, &redirect_addr4, sizeof(addr));
		else if(config.dns.blocking.mode.v.blocking_mode == MODE_IP ||
		        config.dns.blocking.mode.v.blocking_mode == MODE_IP_NODATA_AAAA ||
		        forced_ip)
		{
			if(hostn && config.dns.reply.host.force4.v.b)
				memcpy(&addr, &config.dns.reply.host.v4.v.in_addr, sizeof(addr.addr4));
			else if(!hostn && config.dns.reply.blocking.force4.v.b)
				memcpy(&addr, &config.dns.reply.blocking.v4.v.in_addr, sizeof(addr.addr4));
			else
				memcpy(&addr, &next_iface.addr4, sizeof(addr.addr4));
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
		union all_addr addr = {{ 0 }};

		// Overwrite with IP address if requested
		if(redirecting)
			memcpy(&addr, &redirect_addr6, sizeof(addr));
		else if(config.dns.blocking.mode.v.blocking_mode == MODE_IP ||
		        forced_ip)
		{
			if(hostn && config.dns.reply.host.force6.v.b)
				memcpy(&addr, &config.dns.reply.host.v6.v.in6_addr, sizeof(addr.addr6));
			else if(!hostn && config.dns.reply.blocking.force6.v.b)
				memcpy(&addr, &config.dns.reply.blocking.v6.v.in6_addr, sizeof(addr.addr6));
			else
				memcpy(&addr, &next_iface.addr6, sizeof(addr.addr6));
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
			union all_addr addr = {{ 0 }};
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
                    const unsigned short qtype, const int id,
                    const enum protocol proto,
                    const char* file, const int line)
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
	if(is_pihole_domain(name))
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
	char *domainString = strdup(name);
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
	{
		free(domainString);
		return false;
	}

	// Lock shared memory
	lock_shm();
	const int queryID = counters->queries;

	// Find client IP
	const int clientID = findClientID(clientIP, true, false);

	// Get client pointer
	clientsData* client = getClient(clientID, true);
	if(client == NULL)
	{
		// Encountered memory error, skip query
		// Free allocated memory
		free(domainString);
		// Release thread lock
		unlock_shm();
		return false;
	}

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

		// Free allocated memory
		free(domainString);

		// Do not further process this query, Pi-hole has never seen it
		unlock_shm();
		return true;
	}

	// Log new query if in debug mode
	if(config.debug.queries.v.b)
	{
		const char *types = querystr(arg, qtype);
		log_debug(DEBUG_QUERIES, "**** new %sIPv%d %s query \"%s\" from %s/%s#%d (ID %i, FTL %i, %s:%i)",
		          proto == TCP ? "TCP " : proto == UDP ? "UDP " : "",
		          family == AF_INET ? 4 : 6, types, domainString, interface,
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
		{
			const char *types = querystr(arg, qtype);
			log_debug(DEBUG_QUERIES, "Skipping new query: %s (%i)", types, id);
		}
		free(domainString);
		unlock_shm();
		return false;
	}

	// Go through already knows domains and see if it is one of them
	const int domainID = findDomainID(domainString, true);

	// Save everything
	queriesData* query = getQuery(queryID, false);
	if(query == NULL)
	{
		// Encountered memory error, skip query
		log_err("No memory available, skipping query analysis");
		// Free allocated memory
		free(domainString);
		// Release thread lock
		unlock_shm();
		return false;
	}

	// Fill query object with available data
	query->magic = MAGICBYTE;
	query->timestamp = querytimestamp;
	query->type = querytype;
	counters->querytype[querytype]++;
	log_debug(DEBUG_STATUS, "query type %d set (new query), ID = %d, new count = %d", query->type, id, counters->querytype[query->type]);
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
	log_debug(DEBUG_STATUS, "reply type %d set (new query), ID = %d, new count = %d", query->reply, query->id, counters->reply[query->reply]);
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
	if(client->hwlen < 1)
	{
		client->hwlen = find_mac(addr, client->hwaddr, 1, time(NULL));
		if(config.debug.arp.v.b)
		{
			if(client->hwlen == 6)
				log_debug(DEBUG_ARP, "find_mac(\"%s\") returned hardware address "
				          "%02X:%02X:%02X:%02X:%02X:%02X", clientIP,
				          client->hwaddr[0], client->hwaddr[1], client->hwaddr[2],
				          client->hwaddr[3], client->hwaddr[4], client->hwaddr[5]);
			else
				log_debug(DEBUG_ARP, "find_mac(\"%s\") returned %i bytes of data",
				          clientIP, client->hwlen);
		}
	}

	bool blockDomain = false;
	// Check if this should be blocked only for active queries
	// (skipped for internally generated ones, e.g., DNSSEC)
	if(!internal_query)
		blockDomain = FTL_check_blocking(queryID, domainID, clientID);

	// Free allocated memory
	free(domainString);

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
	// Return early if Pi-hole PTR is not available
	if(pihole_ptr == NULL)
		return;

	// Convert PTR request into numeric form
	union all_addr addr = {{ 0 }};
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
		if((family == AF_INET && flags == F_IPV4 && iface->addr.in.sin_addr.s_addr == addr.addr4.s_addr) ||
		   (family == AF_INET6 && flags == F_IPV6 && IN6_ARE_ADDR_EQUAL(&iface->addr.in6.sin6_addr, &addr.addr6)))
		{
			// The last PTR record in daemon->ptr is reserved for Pi-hole
			free(pihole_ptr->name);
			pihole_ptr->name = strdup(domain);
			if(family == AF_INET)
			{
				// IPv4 supports conditional domains
				struct in_addr addrv4 = { 0 };
				addrv4.s_addr = iface->addr.in.sin_addr.s_addr;
				pihole_ptr->ptr = get_ptrname(&addrv4);
			}
			else
			{
				// IPv6 does not support conditional domains
				pihole_ptr->ptr = get_ptrname(NULL);
			}

			// Debug logging
			log_debug(DEBUG_QUERIES, "Generating PTR response: %s -> %s", pihole_ptr->name, pihole_ptr->ptr);

			return;
		}
	}
}

inline static void set_dnscache_blockingstatus(DNSCacheData * dns_cache, clientsData *client,
                                               enum domain_client_status new_status, const char *domain)
{
	// Memorize blocking status DNS cache for the domain/client combination
	dns_cache->blocking_status = new_status;

	const char *clientip = client ? getstr(client->ippos) : "N/A";
	log_debug(DEBUG_QUERIES, "DNS cache: %s/%s is %s", clientip, domain, blockingreason);
}

static bool check_domain_blocked(const char *domain, const int clientID,
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

		// Mark domain as exactly denied for this client
		set_dnscache_blockingstatus(dns_cache, client, DENYLIST_BLOCKED, domain);

		// We block this domain
		return true;
	}

	// Check domain against antigravity
	int list_id = -1;
	const enum db_result antigravity = in_gravity(domain, client, true, &list_id);
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

		return false;
	}

	// Check domains against gravity domains
	const enum db_result gravity = in_gravity(domain, client, false, &list_id);
	if(gravity == FOUND)
	{
		// Set new status
		*new_status = QUERY_GRAVITY;
		blockingreason = "gravity blocked";

		// Mark domain as gravity blocked for this client
		set_dnscache_blockingstatus(dns_cache, client, GRAVITY_BLOCKED, domain);

		log_debug(DEBUG_QUERIES, "Blocking query due to gravity match (list ID %i)", list_id);

		// Store ID of the matching gravity list
		// see remarks above for the list_id values
		dns_cache->list_id = -1 * (list_id + 2);

		// We block this domain
		return true;
	}

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

		// Mark domain as regex matched for this client
		set_dnscache_blockingstatus(dns_cache, client, REGEX_BLOCKED, domain);

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

	return false;
}

static bool _FTL_check_blocking(int queryID, int domainID, int clientID, const char* file, const int line)
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
	// When this function is called with a different domain than the one
	// already stored in the query, we have to re-lookup the cache ID.
	// This can happen when a CNAME chain is followed and analyzed
	const int cacheID = query->domainID == domainID && query->clientID == clientID ?
	                    query->cacheID :
	                    findCacheID(domainID, clientID, query->type, true);
	DNSCacheData *dns_cache = getDNSCache(cacheID, true);
	if(dns_cache == NULL)
	{
		log_err("No memory available, skipping query analysis");
		return false;
	}

	// Skip the entire chain of tests if we already know the answer for this
	// particular client
	unsigned char blockingStatus = dns_cache->blocking_status;
	char *domainstr = (char*)getstr(domain->domainpos);
	switch(blockingStatus)
	{
		case UNKNOWN_BLOCKED:
			// New domain/client combination.
			// We have to go through all the tests below
			log_debug(DEBUG_QUERIES, "%s is not known", domainstr);

			break;

		case DENYLIST_BLOCKED:
			// Known as exactly denied, we return this result early, skipping
			// all the lengthy tests below
			blockingreason = "exactly denied";
			log_debug(DEBUG_QUERIES, "%s is known as %s", domainstr, blockingreason);

			// Do not block if the entire query is to be permitted
			// as something along the CNAME path hit the whitelist
			if(!query->flags.allowed)
			{
				force_next_DNS_reply = dns_cache->force_reply;
				query_blocked(query, domain, client, QUERY_DENYLIST);
				return true;
			}
			break;

		case GRAVITY_BLOCKED:
			// Known as gravity blocked, we return this result early, skipping
			// all the lengthy tests below
			blockingreason = "gravity blocked";
			log_debug(DEBUG_QUERIES, "%s is known as %s", domainstr, blockingreason);

			// Do not block if the entire query is to be permitted
			// as sometving along the CNAME path hit the whitelist
			if(!query->flags.allowed)
			{
				force_next_DNS_reply = dns_cache->force_reply;
				query_blocked(query, domain, client, QUERY_GRAVITY);
				return true;
			}
			break;

		case REGEX_BLOCKED:
			// Known as regex denied, we return this result early, skipping all
			// the lengthy tests below
			blockingreason = "regex denied";
			log_debug(DEBUG_QUERIES, "%s is known as %s (cache regex ID: %i)",
			          domainstr, blockingreason, dns_cache->list_id);

			// Do not block if the entire query is to be permitted as something
			// along the CNAME path hit the whitelist
			if(!query->flags.allowed)
			{
				force_next_DNS_reply = dns_cache->force_reply;
				last_regex_idx = dns_cache->list_id;
				query_blocked(query, domain, client, QUERY_REGEX);
				return true;
			}
			break;

		case ALLOWED:
			// Known as allowed, we return this result early, skipping all the
			// lengthy tests below
			log_debug(DEBUG_QUERIES, "%s is known as not to be blocked (allowed)", domainstr);

			query->flags.allowed = true;

			return false;
			break;

		case SPECIAL_DOMAIN:
			// Known as a special domain, we return this result early, skipping
			// all the lengthy tests below
			blockingreason = "special domain";
			log_debug(DEBUG_QUERIES, "%s is known as special domain", domainstr);

			force_next_DNS_reply = dns_cache->force_reply;
			query_blocked(query, domain, client, QUERY_SPECIAL_DOMAIN);
			return true;
			break;

		case NOT_BLOCKED:
			// Known as not blocked, we return this result early, skipping all
			// the lengthy tests below
			log_debug(DEBUG_QUERIES, "%s is known as not to be blocked", domainstr);

			return false;
			break;
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
	domainstr = strdup(domainstr);
	const char *blockedDomain = domainstr;

	// Check exact whitelist for match
	query->flags.allowed = in_allowlist(domainstr, dns_cache, client) == FOUND;

	// If not found: Check regex whitelist for match
	if(!query->flags.allowed)
		query->flags.allowed = in_regex(domainstr, dns_cache, client->id, REGEX_ALLOW);

	// Check if this is a special domain
	if(!query->flags.allowed && special_domain(query, domainstr))
	{
		// Set DNS cache properties
		dns_cache->blocking_status = SPECIAL_DOMAIN;
		dns_cache->force_reply = force_next_DNS_reply;

		// Adjust counters
		query_blocked(query, domain, client, QUERY_SPECIAL_DOMAIN);

		// Debug output
		log_debug(DEBUG_QUERIES, "Special domain: %s is %s", domainstr, blockingreason);

		return true;
	}

	// Check blacklist (exact + regex) and gravity for queried domain
	unsigned char new_status = QUERY_UNKNOWN;
	bool db_okay = true;
	bool blockDomain = check_domain_blocked(domainstr, clientID, client, query, dns_cache, &new_status, &db_okay);

	// Check blacklist (exact + regex) and gravity for _esni.domain if enabled
	// (defaulting to true)
	if(config.dns.blockESNI.v.b &&
	   !query->flags.allowed && blockDomain == NOT_FOUND &&
	    strlen(domainstr) > 6 && strncasecmp(domainstr, "_esni.", 6u) == 0)
	{
		blockDomain = check_domain_blocked(domainstr + 6u, clientID, client, query, dns_cache, &new_status, &db_okay);

		if(blockDomain)
		{
			// Truncate "_esni." from queried domain if the parenting domain was
			// the reason for blocking this query
			blockedDomain = domainstr + 6u;
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
			          domainstr, blockedDomain, blockingreason, dns_cache->list_id);
			if(force_next_DNS_reply != 0)
				log_debug(DEBUG_QUERIES, "Forcing next reply to %s", get_query_reply_str(force_next_DNS_reply));
		}
	}
	else if(db_okay)
	{
		// Explicitly mark as not blocked to skip the entire gravity/blacklist
		// chain when the same client asks for the same domain in the future.
		// Store domain as allowed if this is the case
		dns_cache->blocking_status = query->flags.allowed ? ALLOWED : NOT_BLOCKED;

		// Debug output
		// client is guaranteed to be non-NULL above
		log_debug(DEBUG_QUERIES, "DNS cache: %s/%s is %s (domainlist ID: %i)", getstr(client->ippos),
		          domainstr, query->flags.allowed ? "allowed" : "not blocked", dns_cache->list_id);
	}

	free(domainstr);
	return blockDomain;
}


bool _FTL_CNAME(const char *dst, const char *src, const int id, const char* file, const int line)
{
	log_debug(DEBUG_QUERIES, "FTL_CNAME called with: src = %s, dst = %s, id = %d", src, dst, id);

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
	queriesData* query = getQuery(queryID, true);
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
	char *child_domain = strdup(dst);
	// Convert to lowercase for matching
	strtolower(child_domain);
	const int child_domainID = findDomainID(child_domain, false);

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
		domainsData* parent_domain = getDomain(parent_domainID, true);
		if(parent_domain == NULL)
		{
			// Memory error, return
			free(child_domain);
			unlock_shm();
			return false;
		}
		parent_domain->blockedcount++;

		// Store query response as CNAME type
		struct timeval response;
		gettimeofday(&response, 0);
		query_set_reply(F_CNAME, 0, NULL, query, response);

		// Store domain that was the reason for blocking the entire chain
		query->CNAME_domainID = child_domainID;

		// Change blocking reason into CNAME-caused blocking
		if(query->status == QUERY_GRAVITY)
		{
			query_set_status(query, QUERY_GRAVITY_CNAME);
		}
		else if(query->status == QUERY_REGEX)
		{
			// Get parent and child DNS cache entries
			const int parent_cacheID = query->cacheID;
			const int child_cacheID = findCacheID(child_domainID, clientID, query->type, false);

			// Get cache pointers
			DNSCacheData *parent_cache = getDNSCache(parent_cacheID, true);
			DNSCacheData *child_cache = getDNSCache(child_cacheID, true);

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
	free(child_domain);
	unlock_shm();
	return block;
}

static void FTL_forwarded(const unsigned int flags, const char *name, const union all_addr *addr,
                          unsigned short port, const int id, const char* file, const int line)
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
	char *upstreamIP = strdup(dest);
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
		free(upstreamIP);
		unlock_shm();
		return;
	}

	// Get query pointer
	queriesData* query = getQuery(queryID, true);
	if(query == NULL)
	{
		free(upstreamIP);
		unlock_shm();
		return;
	}

	// Get ID of upstream destination, create new upstream record
	// if not found in current data structure
	const int upstreamID = findUpstreamID(upstreamIP, upstreamPort);
	query->upstreamID = upstreamID;

	upstreamsData *upstream = getUpstream(upstreamID, true);
	if(upstream != NULL)
		upstream->count++;

	// Proceed only if
	// - current query has not been marked as replied to so far
	//   (it could be that answers from multiple forward
	//    destinations are coming in for the same query)
	// - the query was formally known as cached but had to be forwarded
	//   (this is a special case further described below)
	if(query->flags.complete && query->status != QUERY_CACHE)
	{
		free(upstreamIP);
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

	// Release allocated memory
	free(upstreamIP);

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
		log_info("Received SIGHUP, flushing cache and re-reading config");

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

static void mysockaddr_extract_ip_port(union mysockaddr *server, char ip[ADDRSTRLEN+1], in_port_t *port)
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
		if(config.debug.queries.v.b)
		{
			upstreamsData *upstream = getUpstream(query->upstreamID, true);
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
                      const char *arg, const int id, const char* file, const int line)
{
	const double now = double_time();
	// If domain is "pi.hole", we skip this query
	// We compare case-insensitive here
	// Hint: name can be NULL, e.g. for NODATA/NXDOMAIN replies
	if(name != NULL && strcasecmp(name, "pi.hole") == 0)
	{
		return;
	}

	// Get response time before lock because we want to measure upstream not
	// the lock. The latter may artificially add some extra nanoseconds when
	// the Pi-hole is currently busy
	struct timeval response;
	gettimeofday(&response, 0);

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

	// Check if this reply came from our local cache
	bool cached = false;
	if(!(flags & F_UPSTREAM))
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
		if(addr)
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

		if(cached || last_server.sa.sa_family == 0)
			// Log cache or upstream reply from unknown source
			log_debug(DEBUG_QUERIES, "**** got %s%s reply: %s is %s (ID %i, %s:%i)",
			          stale ? "stale ": "", cached ? "cache" : "upstream",
			          dispname, answer, id, file, line);
		else
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			in_port_t port = 0;
			mysockaddr_extract_ip_port(&last_server, ip, &port);
			// Log server which replied to our request
			log_debug(DEBUG_QUERIES, "**** got %s%s reply from %s#%d: %s is %s (ID %i, %s:%i)",
			          stale ? "stale ": "", cached ? "cache" : "upstream",
			          ip, port, dispname, answer, id, file, line);
		}
	}

	// Get and check query pointer
	queriesData* query = getQuery(queryID, true);
	if(query == NULL)
	{
		// Nothing to be done here
		unlock_shm();
		return;
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
	domainsData* domain = getDomain(domainID, true);
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

		// Detect if returned IP indicates that this query was blocked
		const enum query_status new_status = detect_blocked_IP(flags, addr, query, domain);

		// Update status of this query if detected as external blocking
		if(new_status != query->status)
		{
			clientsData *client = getClient(query->clientID, true);
			if(client != NULL)
				query_blocked(query, domain, client, new_status);
		}

		// Save reply type and update individual reply counters
		query_set_reply(flags, 0, addr, query, response);

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
		query_set_reply(flags, 0, addr, query, response);

		// Hereby, this query is now fully determined
		query->flags.complete = true;

		// Mark query for updating in the database
		query->flags.database.changed = true;
	}
	else if((flags & (F_FORWARD | F_UPSTREAM)) && isExactMatch)
	{
		upstreamsData *upstream = getUpstream(query->upstreamID, true);
		upstream->responses++;

		// Re-compute upstream average response time and uncertainty
		upstream->rtime += query->response;
		const double mean = upstream->rtime / upstream->responses;
		upstream->rtuncertainty += (mean - query->response)*(mean - query->response);

		// Only proceed if query is not already known
		// to have been blocked by Quad9
		if(query->status == QUERY_EXTERNAL_BLOCKED_IP ||
		   query->status == QUERY_EXTERNAL_BLOCKED_NULL ||
		   query->status == QUERY_EXTERNAL_BLOCKED_NXRA)
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
		query_set_reply(reply_flags, 0, addr, query, response);

		// Further checks if this is an IP address
		if(addr)
		{
			// Detect if returned IP indicates that this query was blocked
			const enum query_status new_status = detect_blocked_IP(flags, addr, query, domain);

			// Update status of this query if detected as external blocking
			if(new_status != query->status)
			{
				clientsData *client = getClient(query->clientID, true);
				if(client != NULL)
					query_blocked(query, domain, client, new_status);
			}
		}

		// Mark query for updating in the database
		query->flags.database.changed = true;
	}
	else if(flags & F_REVERSE)
	{
		// isExactMatch is not used here as the PTR is special.
		// Example:
		// Question: PTR 8.8.8.8
		// will lead to:
		//   domain->domain = 8.8.8.8.in-addr.arpa
		// and will return
		//   name = google-public-dns-a.google.com
		// Hence, isExactMatch is always false

		// Save reply type and update individual reply counters
		query_set_reply(flags, 0, addr, query, response);

		// Mark query for updating in the database
		query->flags.database.changed = true;
	}
	else if(isExactMatch && !query->flags.complete)
	{
		log_warn("Unknown REPLY");
	}
	else if(config.debug.flags.v.b)
	{
		log_warn("Unknown upstream REPLY");
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

static enum query_status detect_blocked_IP(const unsigned short flags, const union all_addr *addr, const queriesData *query, const domainsData *domain)
{
	// Compare returned IP against list of known blocking splash pages

	if (!addr)
	{
		return query->status;
	}

	// First, we check if we want to skip this result even before comparing against the known IPs
	if(flags & F_HOSTS || flags & F_REVERSE)
	{
		// Skip replies which originated locally. Otherwise, we would
		// count gravity.list blocked queries as externally blocked.
		// Also: Do not mark responses of PTR requests as externally blocked.
		const char *cause = (flags & F_HOSTS) ? "origin is HOSTS" : "query is PTR";
		log_debug(DEBUG_QUERIES, "Skipping detection of external blocking IP for ID %i as %s", query->id, cause);

		// Return early, do not compare against known blocking page IP addresses below
		return query->status;
	}

	// If received one of the following IPs as reply, OpenDNS
	// (Cisco Umbrella) blocked this query
	// See https://support.opendns.com/hc/en-us/articles/227986927-What-are-the-Cisco-Umbrella-Block-Page-IP-Addresses-
	// for a full list of these IP addresses
	in_addr_t ipv4Addr = ntohl(addr->addr4.s_addr);
	in_addr_t ipv6Addr = ntohl(addr->addr6.s6_addr32[3]);
	// Check for IP block 146.112.61.104 - 146.112.61.110
	if((flags & F_IPV4) && ipv4Addr >= 0x92703d68 && ipv4Addr <= 0x92703d6e)
	{
		if(config.debug.queries.v.b)
		{
			char answer[ADDRSTRLEN]; answer[0] = '\0';
			inet_ntop(AF_INET, addr, answer, ADDRSTRLEN);
			log_debug(DEBUG_QUERIES, "Upstream responded with known blocking page (IPv4), ID %i:\n\t\"%s\" -> \"%s\"",
			          query->id, getstr(domain->domainpos), answer);
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_IP;
	}
	// Check for IP block :ffff:146.112.61.104 - :ffff:146.112.61.110
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
			log_debug(DEBUG_QUERIES, "Upstream responded with known blocking page (IPv6), ID %i:\n\t\"%s\" -> \"%s\"",
			          query->id, getstr(domain->domainpos), answer);
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
			log_debug(DEBUG_QUERIES, "Upstream responded with 0.0.0.0, ID %i:\n\t\"%s\" -> \"0.0.0.0\"",
			          query->id, getstr(domain->domainpos));
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
			log_debug(DEBUG_QUERIES, "Upstream responded with ::, ID %i:\n\t\"%s\" -> \"::\"",
			          query->id, getstr(domain->domainpos));
		}

		// Update status
		return QUERY_EXTERNAL_BLOCKED_NULL;
	}

	// Nothing happened here
	return query->status;
}

static void query_blocked(queriesData* query, domainsData* domain, clientsData* client, const enum query_status new_status)
{
	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	// Adjust counters if we recorded a non-blocking status
	if(query->status == QUERY_FORWARDED)
	{
		// Get forward pointer
		upstreamsData* upstream = getUpstream(query->upstreamID, true);
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

static void FTL_dnssec(const char *arg, const union all_addr *addr, const int id, const char* file, const int line)
{
	// Process DNSSEC result for a domain

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
	queriesData* query = getQuery(queryID, true);
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
		const domainsData* domain = getDomain(query->domainID, true);
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
		struct timeval response;
		gettimeofday(&response, 0);
		query_set_reply(0, REPLY_NONE, addr, query, response);
	}

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Unlock shared memory
	unlock_shm();
}

static void FTL_upstream_error(const union all_addr *addr, const unsigned int flags, const int id, const char* file, const int line)
{
	// Process local and upstream errors
	// Queries with error are those where the RCODE
	// in the DNS header is neither NOERROR nor NXDOMAIN.

	// Return early if there is nothing we can analyze here (shouldn't happen)
	if(!addr)
		return;

	// Record response time before queuing for the lock
	struct timeval response;
	gettimeofday(&response, 0);

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
	queriesData* query = getQuery(queryID, true);
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
	enum reply_type reply;
	switch(addr->log.rcode)
	{
		case SERVFAIL:
			rcodestr = "SERVFAIL";
			reply = REPLY_SERVFAIL;
			break;
		case REFUSED:
			rcodestr = "REFUSED";
			reply = REPLY_REFUSED;
			break;
		case NOTIMP:
			rcodestr = "NOT IMPLEMENTED";
			reply = REPLY_NOTIMP;
			break;
		default:
			rcodestr = "UNKNOWN";
			reply = REPLY_OTHER;
			break;
	}

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
		const domainsData* domain = getDomain(query->domainID, true);

		// Get domain name
		const char *domainname;
		if(domain != NULL)
			domainname = getstr(domain->domainpos);
		else
			domainname = "<cannot access domain struct>";

		if(flags & F_CONFIG)
		{
			// Log local error, typically "nowhere to forward to"
			log_err("**** local error (nowhere to forward to): %s is %s (ID %i, %s:%i)",
			     domainname, rcodestr, id, file, line);
		}
		else if(last_server.sa.sa_family == 0)
		{
			// Log error reply from unknown source
			log_debug(DEBUG_QUERIES, "**** got error reply: %s is %s (ID %i, %s:%i)",
			     domainname, rcodestr, id, file, line);
		}
		else
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			in_port_t port = 0;
			mysockaddr_extract_ip_port(&last_server, ip, &port);
			// Log server which replied to our request
			log_debug(DEBUG_QUERIES, "**** got error reply from %s#%d: %s is %s (ID %i, %s:%i)",
			     ip, port, domainname, rcodestr, id, file, line);
		}

		if(query->reply == REPLY_OTHER)
			log_debug(DEBUG_QUERIES, "     Unknown rcode = %i", addr->log.rcode);

		if(addr->log.ede != EDE_UNSET)
			log_debug(DEBUG_QUERIES, "     EDE: %s (1/%d)", edestr(addr->log.ede), addr->log.ede);

		if(edns != NULL && edns->ede != EDE_UNSET)
			log_debug(DEBUG_QUERIES, "     EDE: %s (2/%d)", edestr(edns->ede), edns->ede);
	}

	// Set query reply
	query_set_reply(0, reply, addr, query, response);

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Reset last_server
	memset(&last_server, 0, sizeof(last_server));

	// Unlock shared memory
	unlock_shm();
}

static void FTL_mark_externally_blocked(const int id, const char* file, const int line)
{
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
	queriesData* query = getQuery(queryID, true);
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
		const char *domainname = getstr(domain->domainpos);
		log_debug(DEBUG_QUERIES, "**** %s externally blocked (ID %i, FTL %i, %s:%i)", domainname, id, queryID, file, line);
	}

	// Get response time
	struct timeval response;
	gettimeofday(&response, 0);

	// Store query as externally blocked
	clientsData *client = getClient(query->clientID, true);
	if(client != NULL)
		query_blocked(query, domain, client, QUERY_EXTERNAL_BLOCKED_NXRA);

	// Store reply type as replied with NXDOMAIN
	query_set_reply(F_NEG | F_NXDOMAIN, 0, NULL, query, response);

	// Mark query for updating in the database
	query->flags.database.changed = true;

	// Unlock shared memory
	unlock_shm();
}

void _FTL_header_analysis(const unsigned char header4, const unsigned int rcode, const struct server *server,
                          const int id, const char* file, const int line)
{
	// Analyze DNS header bits

	// Check if RA bit is unset in DNS header and rcode is NXDOMAIN
	// If the response code (rcode) is NXDOMAIN, we may be seeing a response from
	// an externally blocked query. As they are not always accompany a necessary
	// SOA record, they are not getting added to our cache and, therefore,
	// FTL_reply() is never getting called from within the cache routines.
	// Hence, we have to store the necessary information about the NXDOMAIN
	// reply already here.
	if(!(header4 & 0x80) && rcode == NXDOMAIN)
		// RA bit is not set and rcode is NXDOMAIN
		FTL_mark_externally_blocked(id, file, line);

	// Check if AD bit is set in DNS header
	adbit = header4 & HB4_AD;

	// Store server which sent this reply
	if(server)
	{
		memcpy(&last_server, &server->addr, sizeof(last_server));
		if(config.debug.extra.v.b)
		{
			char ip[ADDRSTRLEN+1] = { 0 };
			in_port_t port = 0;
			mysockaddr_extract_ip_port(&last_server, ip, &port);
			log_debug(DEBUG_EXTRA, "Got forward address: %s#%u (%s:%i)", ip, port, short_path(file), line);
		}
	}
	else
	{
		memset(&last_server, 0, sizeof(last_server));
		log_debug(DEBUG_EXTRA, "Got forward address: NO");
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
                             queriesData *query, const struct timeval response,
                             const char *file, const int line)
{
	enum reply_type new_reply = REPLY_UNKNOWN;
	const double now = double_time();
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
	log_debug(DEBUG_STATUS, "reply type %d removed (set_reply), ID = %d, new count = %d", query->reply, query->id, counters->reply[query->reply]);
	// Add to new reply counter
	counters->reply[new_reply]++;
	// Store reply type
	query->reply = new_reply;
	log_debug(DEBUG_STATUS, "reply type %d added (set_reply), ID = %d, new count = %d", query->reply, query->id, counters->reply[query->reply]);

	// Save response time
	// Skipped internally if already computed
	set_response_time(query, now);
}

static void init_pihole_PTR(void)
{
	char *ptrname = NULL;
	// Determine name that should be replied to with on Pi-hole PTRs
	switch (config.dns.piholePTR.v.ptr_type)
	{
		default:
		case PTR_NONE:
		case PTR_PIHOLE:
			ptrname = (char*)"pi.hole";
			break;

		case PTR_HOSTNAME:
			ptrname = (char*)hostname();
			break;

		case PTR_HOSTNAMEFQDN:
		{
			char *suffix = daemon->domain_suffix;
			// If local suffix is not available, we substitute "no_fqdn_available"
			// see the comment about PIHOLE_PTR=HOSTNAMEFQDN in the Pi-hole docs
			// for further details on why this was chosen
			if(!suffix)
				suffix = (char*)"no_fqdn_available";
			ptrname = calloc(strlen(hostname()) + strlen(suffix) + 2, sizeof(char));
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
		}
			break;
	}

	// Obtain PTR record used for Pi-hole PTR injection (if enabled)
	if(config.dns.piholePTR.v.ptr_type != PTR_NONE)
	{
		// Add PTR record for pi.hole, the address will be injected later
		pihole_ptr = calloc(1, sizeof(struct ptr_record));
		pihole_ptr->name = strdup("x.x.x.x.in-addr.arpa");
		pihole_ptr->ptr = (char*)"";
		pihole_ptr->next = NULL;
		// Add our PTR record to the end of the linked list
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
			// Ours is the only record for daemon->ptr
			daemon->ptr = pihole_ptr;
		}
	}
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
		savepid();

	// Initialize query database (pihole-FTL.db)
	db_init();

	// Initialize in-memory databases
	if(!init_memory_database())
		log_crit("Cannot initialize in-memory database.");

	// Flush messages stored in the long-term database
	flush_message_table();

	// Try to import queries from long-term database if available
	if(config.database.DBimport.v.b)
	{
		import_queries_from_disk();
		DB_read_queries();
	}

	// Initialize in-memory database starting index
	update_disk_db_idx();

	// Log some information about the imported queries (if any)
	log_counter_info();

	// Handle real-time signals in this process (and its children)
	// Helper processes are already split from the main instance
	// so they will not listen to real-time signals
	handle_realtime_signals();

	// We will use the attributes object later to start all threads in
	// detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);

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

	// Chown files if FTL started as user root but a dnsmasq config
	// option states to run as a different user/group (e.g. "nobody")
	if(getuid() == 0)
	{
		// Only print this and change ownership of shmem objects when
		// we're actually dropping root (user/group my be set to root)
		if(ent_pw != NULL && ent_pw->pw_uid != 0)
		{
			log_info("FTL is going to drop from root to user %s (UID %u)",
			     ent_pw->pw_name, ent_pw->pw_uid);
			if(chown(config.files.log.ftl.v.s, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
				log_warn("Setting ownership (%u:%u) of %s failed: %s (%i)",
				ent_pw->pw_uid, ent_pw->pw_gid, config.files.log.ftl.v.s, strerror(errno), errno);
			if(chown(config.files.database.v.s, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
				log_warn("Setting ownership (%u:%u) of %s failed: %s (%i)",
				ent_pw->pw_uid, ent_pw->pw_gid, config.files.database.v.s, strerror(errno), errno);
			chown_all_shmem(ent_pw);
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

	// Initialize Pi-hole PTR pointer
	init_pihole_PTR();
}

static char *get_ptrname(struct in_addr *addr)
{
	static char *ptrname = NULL;
	// Determine name that should be replied to with on Pi-hole PTRs
	switch (config.dns.piholePTR.v.ptr_type)
	{
		default:
		case PTR_NONE:
		case PTR_PIHOLE:
			ptrname = (char*)"pi.hole";
			break;

		case PTR_HOSTNAME:
			ptrname = (char*)hostname();
			break;

		case PTR_HOSTNAMEFQDN:
		{
			char *suffix;
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

void FTL_forwarding_retried(const struct server *serv, const int oldID, const int newID, const bool dnssec)
{
	// Forwarding to upstream server failed

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
	char *upstreamIP = strdup(dest);
	strtolower(upstreamIP);

	// Get upstream ID
	const int upstreamID = findUpstreamID(upstreamIP, upstreamPort);

	// Possible debugging information
	log_debug(DEBUG_QUERIES, "**** RETRIED%s query %i as %i to %s#%d",
	          dnssec ? " DNSSEC" : "", oldID, newID,
	          upstreamIP, upstreamPort);

	// Get upstream pointer
	upstreamsData* upstream = getUpstream(upstreamID, true);

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
		queriesData* query = getQuery(queryID, true);

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

	// Clean up and unlock shared memory
	free(upstreamIP);
	unlock_shm();
	return;
}

unsigned int FTL_extract_question_flags(struct dns_header *header, const size_t qlen)
{
	// Create working pointer
	unsigned char *p = (unsigned char *)(header+1);
	uint16_t qtype, qclass;

	// Go through the questions
	for (uint16_t i = ntohs(header->qdcount); i != 0; i--)
	{
		// Prime dnsmasq flags
		int flags = RCODE(header) == NXDOMAIN ? F_NXDOMAIN : 0;

		// Extract name from this question
		char name[MAXDNAME];
		if (!extract_name(header, qlen, &p, name, 1, 4))
			break; // bad packet, go to fallback solution

		// Extract query type
		GETSHORT(qtype, p);
		GETSHORT(qclass, p);

		// Only further analyze IN questions here (not CHAOS, etc.)
		if (qclass != C_IN)
			continue;

		// Very simple decision: If the question is AAAA, the reply
		// should be IPv6. We use IPv4 in all other cases
		if(qtype == T_AAAA)
			flags |= F_IPV6;
		else
			flags |= F_IPV4;

		// Debug logging if enabled
		if(config.debug.queries.v.b)
		{
			char *qtype_str = querystr(NULL, qtype);
			log_debug(DEBUG_QUERIES, "CNAME header: Question was <IN> %s %s", qtype_str, name);
		}

		return flags;
	}

	// Fall back to IPv4 (type A) when for the unlikely event that we cannot
	// find any questions in this header
	log_debug(DEBUG_QUERIES, "CNAME header: No valid IN question found in header");

	return F_IPV4;
}

// Called when a (forked) TCP worker is terminated by receiving SIGALRM
// We close the dedicated database connection this client had opened
// to avoid dangling database locks
volatile atomic_flag worker_already_terminating = ATOMIC_FLAG_INIT;
void FTL_TCP_worker_terminating(bool finished)
{
	if(dnsmasq_debug)
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
	if(dnsmasq_debug)
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
		union mysockaddr peer_sockaddr = {{ 0 }};
		socklen_t peer_len = sizeof(union mysockaddr);
		if (getpeername(confd, (struct sockaddr *)&peer_sockaddr, &peer_len) != -1)
		{
			union all_addr peer_addr = {{ 0 }};
			if (peer_sockaddr.sa.sa_family == AF_INET6)
				peer_addr.addr6 = peer_sockaddr.in6.sin6_addr;
			else
				peer_addr.addr4 = peer_sockaddr.in.sin_addr;
			inet_ntop(peer_sockaddr.sa.sa_family, &peer_addr, peer_ip, ADDRSTRLEN);
		}

		// Get local IP address (interface)
		char local_ip[ADDRSTRLEN] = { 0 };
		union mysockaddr iface_sockaddr = {{ 0 }};
		socklen_t iface_len = sizeof(union mysockaddr);
		if(getsockname(confd, (struct sockaddr *)&iface_sockaddr, &iface_len) != -1)
		{
			union all_addr iface_addr = {{ 0 }};
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
		lease = lease6_find_by_addr(&addr.addr6, 128, 0);
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
	queriesData* query = getQuery(queryID, true);
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
		const domainsData* domain = getDomain(query->domainID, true);
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
	const queriesData* source_query = getQuery(*firstID, true);
	// Get query pointer of duplicated reply
	queriesData* duplicated_query = getQuery(queryID, true);

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
	log_debug(DEBUG_STATUS, "duplicated_query reply type %d removed, ID = %d, new count = %d", duplicated_query->reply, duplicated_query->id, counters->reply[duplicated_query->reply]);
	duplicated_query->reply = source_query->reply;
	counters->reply[duplicated_query->reply]++;
	log_debug(DEBUG_STATUS, "duplicated_query reply type %d set, ID = %d, new count = %d", duplicated_query->reply, duplicated_query->id, counters->reply[duplicated_query->reply]);

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

const char *get_edestr(const int ede)
{
	return edestr(ede);
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

/* Changes */
bool FTL_model_query(char* domain){
	// Sending domain name to localhost:5336 to check domain credibility
	// If the domain is credible, return false, else return true

	// Create a socket
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		printf("Error creating socket\n");
		return false;
	}
	// Sending domain name to localhost:5336
	struct sockaddr_in serv_addr;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(5336);

	struct in_addr server_ip;
	if (inet_pton(AF_INET, "127.0.0.1", &server_ip) <= 0)
	{
		printf("Invalid server IP address\n");
		return false;
	}

	serv_addr.sin_addr = server_ip;

	// Connect to the server
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		printf("Error connecting to the server\n");
		return true;
	}

	// Send the domain name to the server
	if (send(sockfd, domain, strlen(domain), 0) < 0)
	{
		printf("Error sending domain name\n");
		return false;
	}
	else
	{
		// Assuming sockfd is the socket file descriptor
		char buffer[2]; // Buffer to store the received data

		// Receive data from the server
		int bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
		if (bytes_received < 0)
		{
			printf("Error receiving data\n");
			return false;
		}

		buffer[bytes_received] = '\0'; // Null-terminate the received data

		// Convert the received data to a boolean
		bool received_bool = (buffer[0] == '1') ? true : false;
		close(sockfd);
		return received_bool;
	}

	// Close the socket
	close(sockfd);
	return true;
}