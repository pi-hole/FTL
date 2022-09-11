/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "api.h"
#include "../enums.h"
// getstr()
#include "../shmem.h"
// read_setupVarsconf()
#include "../setupVars.h"
// ssend()
#include "socket.h"
// get_FTL_db_filesize()
#include "../files.h"
// logg()
#include "../log.h"
#include "request.h"
// struct config
#include "../config.h"
// get_sqlite3_version()
#include "../database/common.h"
// get_number_of_queries_in_DB()
#include "../database/query-table.h"
// in_auditlist()
#include "../database/gravity-db.h"
// struct overTime
#include "../overTime.h"
// Version information
#include "../version.h"
// enum REGEX
#include "../regex_r.h"
// get_aliasclient_list()
#include "../database/aliasclients.h"
// get_edestr()
#include "api_helper.h"
// RTF_UP, RTF_GATEWAY
#include <linux/route.h>

// defined in src/dnsmasq/cache.c
extern char *querystr(char *desc, unsigned short type);

#define min(a,b) ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

/* qsort comparison function (count field), sort ASC */
static int __attribute__((pure)) cmpasc(const void *a, const void *b)
{
	const int *elem1 = (int*)a;
	const int *elem2 = (int*)b;

	if (elem1[1] < elem2[1])
		return -1;
	else if (elem1[1] > elem2[1])
		return 1;
	else
		return 0;
}

// qsort subroutine, sort DESC
static int __attribute__((pure)) cmpdesc(const void *a, const void *b)
{
	const int *elem1 = (int*)a;
	const int *elem2 = (int*)b;

	if (elem1[1] > elem2[1])
		return -1;
	else if (elem1[1] < elem2[1])
		return 1;
	else
		return 0;
}

void getStats(const int sock, const bool istelnet)
{
	const int blocked = blocked_queries();
	const int total = counters->queries;
	float percentage = 0.0f;

	// Avoid 1/0 condition
	if(total > 0)
		percentage = 1e2f*blocked/total;

	// Send domains being blocked
	if(istelnet) {
		ssend(sock, "domains_being_blocked %i\n", counters->gravity);
	}
	else
		pack_int32(sock, counters->gravity);

	// unique_clients: count only clients that have been active within the most recent 24 hours
	int activeclients = 0;
	for(int clientID=0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);
		if(client == NULL)
			continue;

		if(client->count > 0)
			activeclients++;
	}

	if(istelnet) {
		ssend(sock, "dns_queries_today %i\nads_blocked_today %i\nads_percentage_today %f\n",
		      total, blocked, percentage);
		ssend(sock, "unique_domains %i\nqueries_forwarded %i\nqueries_cached %i\n",
		      counters->domains, forwarded_queries(), cached_queries());
		ssend(sock, "clients_ever_seen %i\n", counters->clients);
		ssend(sock, "unique_clients %i\n", activeclients);

		// Sum up all query types (A, AAAA, ANY, SRV, SOA, ...)
		int sumalltypes = 0;
		for(int queryType=0; queryType < TYPE_MAX-1; queryType++)
		{
			sumalltypes += counters->querytype[queryType];
		}
		ssend(sock, "dns_queries_all_types %i\n", sumalltypes);

		// Send individual reply type counters
		int sumallreplies = 0;
		for(enum reply_type reply = REPLY_UNKNOWN; reply < QUERY_REPLY_MAX; reply++)
		{
			ssend(sock, "reply_%s %i\n", get_query_reply_str(reply), counters->reply[reply]);
			sumallreplies += counters->reply[reply];
		}
		ssend(sock, "dns_queries_all_replies %i\n", sumallreplies);
		ssend(sock, "privacy_level %i\n", config.privacylevel);
	}
	else
	{
		pack_int32(sock, total);
		pack_int32(sock, blocked);
		pack_float(sock, percentage);
		pack_int32(sock, counters->domains);
		pack_int32(sock, forwarded_queries());
		pack_int32(sock, cached_queries());
		pack_int32(sock, counters->clients);
		pack_int32(sock, activeclients);
	}

	// Send status
	if(istelnet) {
		ssend(sock, "status %s\n", blockingstatus ? "enabled" : "disabled");
	}
	else
		pack_uint8(sock, blockingstatus);
}

void getOverTime(const int sock, const bool istelnet)
{
	if(istelnet)
	{
		for(int slot = 0; slot < OVERTIME_SLOTS; slot++)
		{
			ssend(sock,"%lli %i %i\n",
			      (long long)overTime[slot].timestamp,
			      overTime[slot].total,
			      overTime[slot].blocked);
		}
	}
	else
	{
		// We can use the map16 type because there should only be about 288 time slots (TIMEFRAME set to "yesterday")
		// and map16 can hold up to (2^16)-1 = 65535 pairs

		// Send domains over time
		pack_map16_start(sock, (uint16_t) OVERTIME_SLOTS);
		for(int slot = 0; slot < OVERTIME_SLOTS; slot++) {
			pack_int32(sock, (int32_t)overTime[slot].timestamp);
			pack_int32(sock, overTime[slot].total);
		}

		// Send ads over time
		pack_map16_start(sock, (uint16_t) OVERTIME_SLOTS);
		for(int slot = 0; slot < OVERTIME_SLOTS; slot++) {
			pack_int32(sock, (int32_t)overTime[slot].timestamp);
			pack_int32(sock, overTime[slot].blocked);
		}
	}
}

void getTopDomains(const char *client_message, const int sock, const bool istelnet)
{
	int temparray[counters->domains][2], count=10, num;
	bool audit = false, asc = false;

	const bool blocked = command(client_message, ">top-ads");

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS) {
		// Always send the total number of domains, but pretend it's 0
		if(!istelnet)
			pack_int32(sock, 0);

		return;
	}

	// Match both top-domains and top-ads
	// example: >top-domains (15)
	if(sscanf(client_message, "%*[^(](%i)", &num) > 0) {
		// User wants a different number of requests
		count = num;
	}

	// Apply Audit Log filtering?
	// example: >top-domains for audit
	if(command(client_message, " for audit"))
		audit = true;

	// Sort in ascending order?
	// example: >top-domains asc
	if(command(client_message, " asc"))
		asc = true;

	for(int domainID=0; domainID < counters->domains; domainID++)
	{
		// Get domain pointer
		const domainsData* domain = getDomain(domainID, true);
		if(domain == NULL)
			continue;

		temparray[domainID][0] = domainID;
		if(blocked)
			temparray[domainID][1] = domain->blockedcount;
		else
			// Count only permitted queries
			temparray[domainID][1] = (domain->count - domain->blockedcount);
	}

	// Sort temporary array
	if(asc)
		qsort(temparray, counters->domains, sizeof(int[2]), cmpasc);
	else
		qsort(temparray, counters->domains, sizeof(int[2]), cmpdesc);


	// Get filter
	const char* filter = read_setupVarsconf("API_QUERY_LOG_SHOW");
	bool showpermitted = true, showblocked = true;
	if(filter != NULL)
	{
		if((strcmp(filter, "permittedonly")) == 0)
			showblocked = false;
		else if((strcmp(filter, "blockedonly")) == 0)
			showpermitted = false;
		else if((strcmp(filter, "nothing")) == 0)
		{
			showpermitted = false;
			showblocked = false;
		}
	}
	clearSetupVarsArray();

	// Get domains which the user doesn't want to see
	char * excludedomains = NULL;
	if(!audit)
	{
		excludedomains = read_setupVarsconf("API_EXCLUDE_DOMAINS");
		if(excludedomains != NULL)
		{
			getSetupVarsArray(excludedomains);
		}
	}

	if(!istelnet)
	{
		// Send the data required to get the percentage each domain has been blocked / queried
		if(blocked)
			pack_int32(sock, blocked_queries());
		else
			pack_int32(sock, counters->queries);
	}

	int n = 0;
	for(int i=0; i < counters->domains; i++)
	{
		// Get sorted index
		const int domainID = temparray[i][0];
		// Get domain pointer
		const domainsData* domain = getDomain(domainID, true);
		if(domain == NULL)
			continue;

		// Skip this domain if there is a filter on it
		if(excludedomains != NULL && insetupVarsArray(getstr(domain->domainpos)))
			continue;

		// Skip this domain if already audited
		if(audit && in_auditlist(getstr(domain->domainpos)) > 0)
		{
			if(config.debug & DEBUG_API)
				logg("API: %s has been audited.", getstr(domain->domainpos));
			continue;
		}

		// Hidden domain, probably due to privacy level. Skip this in the top lists
		if(strcmp(getstr(domain->domainpos), HIDDEN_DOMAIN) == 0)
			continue;

		if(blocked && showblocked && domain->blockedcount > 0)
		{
			if(istelnet)
				ssend(sock, "%i %i %s\n", n, domain->blockedcount, getstr(domain->domainpos));
			else {
				if(!pack_str32(sock, getstr(domain->domainpos)))
					return;

				pack_int32(sock, domain->blockedcount);
			}
			n++;
		}
		else if(!blocked && showpermitted && (domain->count - domain->blockedcount) > 0)
		{
			if(istelnet)
				ssend(sock,"%i %i %s\n",n,(domain->count - domain->blockedcount),getstr(domain->domainpos));
			else
			{
				if(!pack_str32(sock, getstr(domain->domainpos)))
					return;

				pack_int32(sock, domain->count - domain->blockedcount);
			}
			n++;
		}

		// Only count entries that are actually sent and return when we have send enough data
		if(n == count)
			break;
	}

	if(excludedomains != NULL)
		clearSetupVarsArray();
}

void getTopClients(const char *client_message, const int sock, const bool istelnet)
{
	int temparray[counters->clients][2], count=10, num;

	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS) {
		// Always send the total number of clients, but pretend it's 0
		if(!istelnet)
			pack_int32(sock, 0);

		return;
	}

	// Match both top-domains and top-ads
	// example: >top-clients (15)
	if(sscanf(client_message, "%*[^(](%i)", &num) > 0) {
		// User wants a different number of requests
		count = num;
	}

	// Show also clients which have not been active recently?
	// This option can be combined with existing options,
	// i.e. both >top-clients withzero" and ">top-clients withzero (123)" are valid
	bool includezeroclients = false;
	if(command(client_message, " withzero"))
		includezeroclients = true;

	// Show number of blocked queries instead of total number?
	// This option can be combined with existing options,
	// i.e. ">top-clients withzero blocked (123)" would be valid
	bool blockedonly = false;
	if(command(client_message, " blocked"))
		blockedonly = true;

	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		const clientsData* client = getClient(clientID, true);
		// Skip invalid clients and also those managed by alias clients
		if(client == NULL || (!client->flags.aliasclient && client->aliasclient_id >= 0))
		{
			temparray[clientID][0] = -1;
			continue;
		}
		temparray[clientID][0] = clientID;
		// Use either blocked or total count based on request string
		temparray[clientID][1] = blockedonly ? client->blockedcount : client->count;
	}

	// Sort in ascending order?
	// example: >top-clients asc
	bool asc = false;
	if(command(client_message, " asc"))
		asc = true;

	// Sort temporary array
	if(asc)
		qsort(temparray, counters->clients, sizeof(int[2]), cmpasc);
	else
		qsort(temparray, counters->clients, sizeof(int[2]), cmpdesc);

	// Get clients which the user doesn't want to see
	const char* excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);
	}

	if(!istelnet)
	{
		// Send the total queries so they can make percentages from this data
		pack_int32(sock, counters->queries);
	}

	int n = 0;
	for(int i=0; i < counters->clients; i++)
	{
		// Get sorted indices and counter values (may be either total or blocked count)
		const int clientID = temparray[i][0];
		const int ccount = temparray[i][1];

		// clientID -1 means this client is to be skipped (managed by a alias-client)
		if(clientID < 0)
			continue;

		// Get client pointer
		const clientsData* client = getClient(clientID, true);

		// Skip invalid clients
		if(client == NULL)
			continue;

		// Skip this client if there is a filter on it
		if(excludeclients != NULL &&
			(insetupVarsArray(getstr(client->ippos)) || insetupVarsArray(getstr(client->namepos))))
			continue;

		// Hidden client, probably due to privacy level. Skip this in the top lists
		if(strcmp(getstr(client->ippos), HIDDEN_CLIENT) == 0)
			continue;

		// Get client IP and name
		const char *client_ip = getstr(client->ippos);
		const char *client_name = getstr(client->namepos);

		// Return this client if either
		// - "withzero" option is set, and/or
		// - the client made at least one query within the most recent 24 hours
		if(includezeroclients || ccount > 0)
		{
			if(istelnet)
				ssend(sock,"%i %i %s %s\n", n, ccount, client_ip, client_name);
			else
			{
				if(!pack_str32(sock, "") || !pack_str32(sock, client_ip))
					return;

				pack_int32(sock, ccount);
			}
			n++;
		}

		if(n == count)
			break;
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();
}


void getUpstreamDestinations(const char *client_message, const int sock, const bool istelnet)
{
	bool sort = true;
	int temparray[counters->upstreams][2], sumforwarded = 0;

	if(command(client_message, "unsorted"))
		sort = false;

	for(int upstreamID = 0; upstreamID < counters->upstreams; upstreamID++)
	{
		// Get upstream pointer
		const upstreamsData* upstream = getUpstream(upstreamID, true);
		if(upstream == NULL)
			continue;

		temparray[upstreamID][0] = upstreamID;

		int count = 0;
		for(unsigned i = 0; i < (sizeof(upstream->overTime)/sizeof(*upstream->overTime)); i++)
			count += upstream->overTime[i];
		temparray[upstreamID][1] = count;
		sumforwarded += count;
	}

	if(sort)
	{
		// Sort temporary array in descending order
		qsort(temparray, counters->upstreams, sizeof(int[2]), cmpdesc);
	}

	const int cached = cached_queries();
	const int blocked = blocked_queries();
	const int others = counters->queries - counters->status[QUERY_FORWARDED] - cached - blocked;
	// The total number of DNS packets can be different than the total
	// number of queries as FTL is periodically sending queries to multiple
	// DNS upstream servers to probe which one is the fastest
	const int totalqueries = sumforwarded + blocked + cached + others;

	// Loop over available forward destinations
	for(int i = -3; i < min(counters->upstreams, 8); i++)
	{
		float percentage = 0.0f;
		const char *ip, *name;
		in_port_t upstream_port = 0;

		if(i == -3)
		{
			// Blocked queries (local lists)
			ip = "blocked";
			name = ip;

			if(totalqueries > 0)
				// What's the percentage of blocked queries on the total amount of queries?
				percentage = 1e2f * blocked / totalqueries;
		}
		else if(i == -2)
		{
			// Local cache
			ip = "cached";
			name = ip;

			if(totalqueries > 0)
				// What's the percentage of cached queries on the total amount of queries?
				percentage = 1e2f * cached / totalqueries;
		}
		else if(i == -1)
		{
			// Others
			ip = "other";
			name = ip;

			if(totalqueries > 0)
				// What's the percentage of cached queries on the total amount of queries?
				percentage = 1e2f * others / totalqueries;
		}
		else
		{
			// Regular upstream destination
			const int upstreamID = temparray[i][0];
			const int count = temparray[i][1];

			// Get upstream pointer
			const upstreamsData* upstream = getUpstream(upstreamID, true);
			if(upstream == NULL)
				continue;

			// Get IP and host name of upstream destination if available
			ip = getstr(upstream->ippos);
			if(upstream->namepos != 0)
				name = getstr(upstream->namepos);
			else
				name = getstr(upstream->ippos);
			upstream_port = upstream->port;

			// Get percentage
			if(totalqueries > 0)
				percentage = 1e2f * count / totalqueries;
		}

		// Send data:
		// - always if i < 0 (special upstreams: blocked and cached)
		// - only if percentage > 0.0 for all others (i > 0)
		if(percentage > 0.0f || i < 0)
		{
			if(istelnet)
				if(upstream_port != 0)
					ssend(sock, "%i %.2f %s#%u %s#%u\n", i, percentage,
					      ip, upstream_port, name, upstream_port);
				else
					ssend(sock, "%i %.2f %s %s\n", i, percentage, ip, name);
			else
			{
				if(!pack_str32(sock, name) || !pack_str32(sock, ip))
					return;

				pack_float(sock, percentage);
			}
		}
	}
}

void getQueryTypes(const int sock, const bool istelnet)
{
	int total = 0;
	for(enum query_types type = TYPE_A; type < TYPE_MAX; type++)
	{
		total += counters->querytype[type - 1];
	}

	float percentage[TYPE_MAX] = { 0.0 };

	// Prevent floating point exceptions by checking if the divisor is != 0
	if(total > 0)
	{
		for(enum query_types type = TYPE_A; type < TYPE_MAX; type++)
		{
			percentage[type] = 1e2f*counters->querytype[type - 1]/total;
		}
	}

	if(istelnet) {
		ssend(sock, "A (IPv4): %.2f\nAAAA (IPv6): %.2f\nANY: %.2f\nSRV: %.2f\n"
		             "SOA: %.2f\nPTR: %.2f\nTXT: %.2f\nNAPTR: %.2f\n"
		             "MX: %.2f\nDS: %.2f\nRRSIG: %.2f\nDNSKEY: %.2f\n"
		             "NS: %.2f\n" "OTHER: %.2f\n\nSVCB: %.2f\nHTTPS: %.2f\n",
		      percentage[TYPE_A], percentage[TYPE_AAAA], percentage[TYPE_ANY], percentage[TYPE_SRV],
		      percentage[TYPE_SOA], percentage[TYPE_PTR], percentage[TYPE_TXT], percentage[TYPE_NAPTR],
		      percentage[TYPE_MX], percentage[TYPE_DS], percentage[TYPE_RRSIG], percentage[TYPE_DNSKEY],
		      percentage[TYPE_NS], percentage[TYPE_OTHER], percentage[TYPE_SVCB], percentage[TYPE_HTTPS]);
	}
	else {
		pack_str32(sock, "A (IPv4)");
		pack_float(sock, percentage[TYPE_A]);
		pack_str32(sock, "AAAA (IPv6)");
		pack_float(sock, percentage[TYPE_AAAA]);
		pack_str32(sock, "ANY");
		pack_float(sock, percentage[TYPE_ANY]);
		pack_str32(sock, "SRV");
		pack_float(sock, percentage[TYPE_SRV]);
		pack_str32(sock, "SOA");
		pack_float(sock, percentage[TYPE_SOA]);
		pack_str32(sock, "PTR");
		pack_float(sock, percentage[TYPE_PTR]);
		pack_str32(sock, "TXT");
		pack_float(sock, percentage[TYPE_TXT]);
		pack_str32(sock, "NAPTR");
		pack_float(sock, percentage[TYPE_NAPTR]);
		pack_str32(sock, "MX");
		pack_float(sock, percentage[TYPE_MX]);
		pack_str32(sock, "DS");
		pack_float(sock, percentage[TYPE_DS]);
		pack_str32(sock, "RRSIG");
		pack_float(sock, percentage[TYPE_RRSIG]);
		pack_str32(sock, "DNSKEY");
		pack_float(sock, percentage[TYPE_DNSKEY]);
		pack_str32(sock, "NS");
		pack_float(sock, percentage[TYPE_NS]);
		pack_str32(sock, "OTHER");
		pack_float(sock, percentage[TYPE_OTHER]);
		pack_str32(sock, "SVCB");
		pack_float(sock, percentage[TYPE_SVCB]);
		pack_str32(sock, "HTTPS");
		pack_float(sock, percentage[TYPE_HTTPS]);
	}
}

void getAllQueries(const char *client_message, const int sock, const bool istelnet)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_MAXIMUM)
		return;

	// Do we want a more specific version of this command (domain/client/time interval filtered)?
	int from = 0, until = 0;

	bool showpermitted = true, showblocked = true;

	char *domainname = NULL;
	bool filterdomainname = false;
	int domainid = -1;

	char *clientname = NULL;
	bool filterclientname = false;
	int clientid = -1;
	int *clientid_list = NULL;

	unsigned char querytype = 0;

	char *forwarddest = NULL;
	bool filterforwarddest = false;
	int forwarddestid = 0;

	// Time filtering?
	if(command(client_message, ">getallqueries-time")) {
		sscanf(client_message, ">getallqueries-time %i %i",&from, &until);
	}

	// Query type filtering?
	if(command(client_message, ">getallqueries-qtype")) {
		// Get query type we want to see only
		unsigned int qtype = 0;
		sscanf(client_message, ">getallqueries-qtype %u", &qtype);
		if(qtype < TYPE_A || qtype >= TYPE_MAX)
		{
			// Invalid query type requested
			return;
		}
		querytype = qtype;
	}

	// Forward destination filtering?
	if(command(client_message, ">getallqueries-forward")) {
		// Get forward destination name we want to see only (limit length to 255 chars)
		forwarddest = calloc(256, sizeof(char));
		if(forwarddest == NULL)
			return;

		sscanf(client_message, ">getallqueries-forward %255s", forwarddest);
		filterforwarddest = true;

		if(strcmp(forwarddest, "blocked") == 0)
			forwarddestid = -3;
		else if(strcmp(forwarddest, "cached") == 0)
			forwarddestid = -2;
		else if(strcmp(forwarddest, "other") == 0)
			forwarddestid = -1;
		else
		{
			// Extract address/name and port
			char serv_addr[INET6_ADDRSTRLEN] = { 0 };
			unsigned int serv_port = 53;
			// We limit the number of bytes written into the serv_addr buffer
			// to prevent buffer overflows. If there is no port available in
			// the database, we skip extracting them and use the default port
			sscanf(forwarddest, "%"xstr(INET6_ADDRSTRLEN)"[^#]#%u", serv_addr, &serv_port);
			serv_addr[INET6_ADDRSTRLEN-1] = '\0';

			// Iterate through all known forward destinations
			forwarddestid = -3;
			for(int i = 0; i < counters->upstreams; i++)
			{
				// Get forward pointer
				const upstreamsData* forward = getUpstream(i, true);
				if(forward == NULL)
					continue;

				// Try to match the requested string against their IP addresses and
				// (if available) their host names
				if((strcmp(getstr(forward->ippos), serv_addr) == 0 ||
				   (forward->namepos != 0 &&
				    strcasecmp(getstr(forward->namepos), serv_addr) == 0)) && forward->port == serv_port)
				{
					forwarddestid = i;
					break;
				}
			}
			if(forwarddestid < 0)
			{
				// Requested forward destination has not been found, we directly
				// exit here as there is no data to be returned
				free(forwarddest);
				return;
			}
		}
	}

	// Domain filtering?
	if(command(client_message, ">getallqueries-domain")) {
		// Get domain name we want to see only (limit length to 255 chars)
		domainname = calloc(256, sizeof(char));
		if(domainname == NULL)
		{
			if(forwarddest) free(forwarddest);
			return;
		}

		sscanf(client_message, ">getallqueries-domain %255s", domainname);
		filterdomainname = true;
		// Iterate through all known domains
		for(int domainID = 0; domainID < counters->domains; domainID++)
		{
			// Get domain pointer
			const domainsData* domain = getDomain(domainID, true);
			if(domain == NULL)
				continue;

			// Try to match the requested string
			if(strcmp(getstr(domain->domainpos), domainname) == 0)
			{
				domainid = domainID;
				break;
			}
		}
		if(domainid < 0)
		{
			// Requested domain has not been found, we directly
			// exit here as there is no data to be returned
			free(domainname);
			if(forwarddest) free(forwarddest);
			return;
		}
	}

	// Client filtering?
	if(command(client_message, ">getallqueries-client")) {
		// Get client name we want to see only (limit length to 255 chars)
		clientname = calloc(256, sizeof(char));
		if(clientname == NULL)
		{
			if(forwarddest) free(forwarddest);
			if(domainname) free(domainname);
			return;
		}

		if(command(client_message, ">getallqueries-client-blocked"))
		{
			showpermitted = false;
			sscanf(client_message, ">getallqueries-client-blocked %255s", clientname);
		}
		else
		{
			sscanf(client_message, ">getallqueries-client %255s", clientname);
		}
		filterclientname = true;

		// Iterate through all known clients
		for(int i = 0; i < counters->clients; i++)
		{
			// Get client pointer
			const clientsData* client = getClient(i, true);
			// Skip invalid clients and also those managed by alias clients
			if(client == NULL || client->aliasclient_id >= 0)
				continue;

			// Try to match the requested string
			if(strcmp(getstr(client->ippos), clientname) == 0 ||
			   (client->namepos != 0 &&
			    strcasecmp(getstr(client->namepos), clientname) == 0))
			{
				clientid = i;

				// Is this a alias-client?
				if(client->flags.aliasclient)
					clientid_list = get_aliasclient_list(i);

				break;
			}
		}
		if(clientid == -1)
		{
			// Requested client has not been found, we directly
			// exit here as there is no data to be returned
			free(clientname);
			if(forwarddest) free(forwarddest);
			if(domainname) free(domainname);
			return;
		}

	}

	int ibeg = 0, num;
	// Test for integer that specifies number of entries to be shown
	if(sscanf(client_message, "%*[^(](%i)", &num) > 0)
	{
		// User wants a different number of requests
		// Don't allow a start index that is smaller than zero
		ibeg = counters->queries-num;
		if(ibeg < 0)
			ibeg = 0;
	}

	// Get potentially existing filtering flags
	char * filter = read_setupVarsconf("API_QUERY_LOG_SHOW");
	if(filter != NULL)
	{
		if((strcmp(filter, "permittedonly")) == 0)
			showblocked = false;
		else if((strcmp(filter, "blockedonly")) == 0)
			showpermitted = false;
		else if((strcmp(filter, "nothing")) == 0)
		{
			showpermitted = false;
			showblocked = false;
		}
	}
	clearSetupVarsArray();

	for(int queryID = ibeg; queryID < counters->queries; queryID++)
	{
		const queriesData* query = getQuery(queryID, true);
		// Check if this query has been create while in maximum privacy mode
		if(query == NULL || query->privacylevel >= PRIVACY_MAXIMUM)
			continue;

		// Verify query type
		if(query->type >= TYPE_MAX)
			continue;
		// Get query type
		const char *qtype = querytypes[query->type];
		char othertype[12] = { 0 }; // Maximum is "TYPE65535" = 10 bytes
		if(query->type == TYPE_OTHER)
		{
			// Check the dnsmasq RR types table for a matching record
			qtype = querystr((char*)"", query->qtype);

			// If not known (querystr() returned "type=1234"), we replace this
			if(!qtype || strstr(qtype, "type=") != NULL)
			{
				// Format custom type into buffer
				sprintf(othertype, "TYPE%u", query->qtype);
				// Replace qtype pointer
				qtype = othertype;
			}
		}

		// Hide UNKNOWN queries when not requesting both query status types
		if(query->status == QUERY_UNKNOWN && !(showpermitted && showblocked))
			continue;

		// Skip blocked queries when asked to
		if(query->flags.blocked && !showblocked)
			continue;

		// Skip permitted queries when asked to
		if(!query->flags.blocked && !showpermitted)
			continue;

		// Skip those entries which so not meet the requested timeframe
		if((from > query->timestamp && from != 0) || (query->timestamp > until && until != 0))
			continue;

		// Skip if domain is not identical with what the user wants to see
		if(filterdomainname)
		{
			// Check direct match
			if(query->domainID == domainid)
			{
				// Get this query
			}
			// If the domain of this query did not match, the CNAME
			// domain may still match - we have to check it in
			// addition if this query is of CNAME blocked type
			else if(query->CNAME_domainID == domainid)
			{
				// Get this query
			}
			else
			{
				// Skip this query
				continue;
			}
		}

		// Skip if client name and IP are not identical with what the user wants to see
		if(filterclientname)
		{
			// Normal clients
			if(clientid_list == NULL && query->clientID != clientid)
				continue;
			// Alias-clients (we have to check for all clients managed by this alias-client)
			else if(clientid_list != NULL)
			{
				bool found = false;
				for(int i = 0; i < clientid_list[0]; i++)
					if(query->clientID == clientid_list[i + 1])
						found = true;
				if(!found)
					continue;
			}
		}

		// Skip if query type is not identical with what the user wants to see
		if(querytype != 0 && querytype != query->type)
			continue;

		if(filterforwarddest)
		{
			// Skip if not from the virtual blocking "upstream" server
			if(forwarddestid == -3 && !query->flags.blocked)
				continue;
			// Does the user want to see queries answered from local cache?
			else if(forwarddestid == -2 && query->status != QUERY_CACHE)
				continue;
			// Does the user want to see queries from the "other" category
			else if(forwarddestid == -1 && query->status != QUERY_IN_PROGRESS)
				continue;
			// Does the user want to see queries answered by an upstream server?
			else if(forwarddestid >= 0 && forwarddestid != query->upstreamID)
				continue;
		}

		// Ask subroutine for domain. It may return "hidden" depending on
		// the privacy settings at the time the query was made
		const char *domain = getDomainString(query);

		// Similarly for the client
		const char *clientIPName = NULL;
		// Get client pointer
		const clientsData* client = getClient(query->clientID, true);
		if(domain == NULL || client == NULL)
			continue;

		if(strlen(getstr(client->namepos)) > 0)
			clientIPName = getClientNameString(query);
		else
			clientIPName = getClientIPString(query);

		unsigned long delay = query->flags.response_calculated ? query->response : 0UL;

		// Get domain blocked during deep CNAME inspection, if applicable
		const char *CNAME_domain = "N/A";
		if(query->CNAME_domainID > -1)
		{
			CNAME_domain = getCNAMEDomainString(query);
		}

		// Get domainlist table ID, if applicable and permitted by privacy settings
		int domainlist_id = -1;
		if (config.privacylevel < PRIVACY_HIDE_DOMAINS)
		{
			unsigned int cacheID = findCacheID(query->domainID, query->clientID, query->type, false);
			DNSCacheData *dns_cache = getDNSCache(cacheID, true);
			if(dns_cache != NULL)
				domainlist_id = dns_cache->domainlist_id;
		}

		// Get IP of upstream destination, if applicable
		in_port_t upstream_port = 0;
		const char *upstream_name = "N/A";
		if(query->upstreamID > -1)
		{
			const upstreamsData *upstream = getUpstream(query->upstreamID, true);
			if(upstream != NULL)
			{
				if(upstream->namepos != 0)
					// Get upstream destination name if possible
					upstream_name = getstr(upstream->namepos);
				else
					// If we have no name, get the IP address
					upstream_name = getstr(upstream->ippos);

				upstream_port = upstream->port;
			}
		}

		// Get reply type
		// If this is a partially cached CNAME (parts needed to be
		// forwarded) but we never receive replies, we have to set the
		// reply back to unknown instead of handing out "CNAME"
		// See https://discourse.pi-hole.net/t/garbage-response-times-for-many-almost-half-at-times-cname-answers/50291/17
		enum reply_type reply = query->flags.response_calculated ? query->reply : REPLY_UNKNOWN;

		// Overwrite reply and reply time if they don't make sense for this query
		// See same Discourse discussion as immediately above
		if(query->status == QUERY_RETRIED || query->status == QUERY_IN_PROGRESS)
		{
			reply = REPLY_UNKNOWN;
			delay = 0UL;
		}

		if(istelnet)
		{
			ssend(sock,"%lli %s %s %s %i %i %i %lu %s %i %s#%u \"%s\"",
				(long long)query->timestamp,
				qtype,
				domain,
				clientIPName,
				query->status,
				query->dnssec,
				reply,
				delay,
				CNAME_domain,
				domainlist_id,
				upstream_name,
				upstream_port,
				query->ede == -1 ? "" : get_edestr(query->ede));

			if(config.debug & DEBUG_API)
				ssend(sock, " \"%i\"", queryID);
			ssend(sock, "\n");
		}
		else
		{
			pack_int32(sock, (int32_t)query->timestamp);

			// Use a fixstr because the length of qtype is always 4 (max is 31 for fixstr)
			if(!pack_fixstr(sock, qtype))
				break;

			// Use str32 for domain and client because we have no idea how long they will be (max is 4294967295 for str32)
			if(!pack_str32(sock, domain) || !pack_str32(sock, clientIPName))
				break;

			pack_uint8(sock, query->status);
			pack_uint8(sock, query->dnssec);
		}
	}

	// Free allocated memory
	if(filterclientname)
		free(clientname);

	if(filterdomainname)
		free(domainname);

	if(filterforwarddest)
		free(forwarddest);

	if(clientid_list != NULL)
		free(clientid_list);
}

void getRecentBlocked(const char *client_message, const int sock, const bool istelnet)
{
	int num=1;

	// Test for integer that specifies number of entries to be shown
	if(sscanf(client_message, "%*[^(](%i)", &num) > 0) {
		// User wants a different number of requests
		if(num >= counters->queries)
			num = 0;
	}

	// Find most recently blocked query
	int found = 0;
	for(int queryID = counters->queries - 1; queryID > 0 ; queryID--)
	{
		const queriesData* query = getQuery(queryID, true);
		if(query == NULL)
			continue;

		if(query->flags.blocked)
		{
			// Ask subroutine for domain. It may return "hidden" depending on
			// the privacy settings at the time the query was made
			const char *domain = getDomainString(query);
			if(domain == NULL)
				continue;

			if(istelnet)
				ssend(sock,"%s\n", domain);
			else if(!pack_str32(sock, domain))
				return;

			// Only count when sent successfully
			found++;
		}

		if(found >= num)
			break;
	}
}

void getClientID(const int sock, const bool istelnet)
{
	if(istelnet)
		ssend(sock,"%i\n", sock);
	else
		pack_int32(sock, sock);
}

void getVersion(const int sock, const bool istelnet)
{
	const char *commit = GIT_HASH;
	const char *tag = GIT_TAG;
	const char *version = get_FTL_version();

	// Extract first 7 characters of the hash
	char hash[8] = { 0 };
	memcpy(hash, commit, min((size_t)7, strlen(commit)));

	if(strlen(tag) > 1) {
		if(istelnet)
			ssend(sock, "version %s\ntag %s\nbranch %s\nhash %s\ndate %s\n", version, tag, GIT_BRANCH, hash, GIT_DATE);
		else {
			if(!pack_str32(sock, version) ||
					!pack_str32(sock, (char *) tag) ||
					!pack_str32(sock, GIT_BRANCH) ||
					!pack_str32(sock, hash) ||
					!pack_str32(sock, GIT_DATE))
				return;
		}
	}
	else {
		if(istelnet)
			ssend(sock, "version vDev-%s\ntag %s\nbranch %s\nhash %s\ndate %s\n", hash, tag, GIT_BRANCH, hash, GIT_DATE);
		else {
			char *hashVersion = calloc(6 + strlen(hash), sizeof(char));
			if(hashVersion == NULL) return;
			sprintf(hashVersion, "vDev-%s", hash);

			if(!pack_str32(sock, hashVersion) ||
					!pack_str32(sock, (char *) tag) ||
					!pack_str32(sock, GIT_BRANCH) ||
					!pack_str32(sock, hash) ||
					!pack_str32(sock, GIT_DATE))
				return;

			free(hashVersion);
		}
	}
}

void getDBstats(const int sock, const bool istelnet)
{
	// Get file details
	unsigned long long int filesize = get_FTL_db_filesize();

	char prefix[2] = { 0 };
	double formatted = 0.0;
	format_memory_size(prefix, filesize, &formatted);

	if(istelnet)
		ssend(sock, "queries in database: %i\ndatabase filesize: %.2f %sB\nSQLite version: %s\n",
		             get_number_of_queries_in_DB(NULL), formatted, prefix, get_sqlite3_version());
	else {
		pack_int32(sock, get_number_of_queries_in_DB(NULL));
		pack_int64(sock, filesize);

		if(!pack_str32(sock, (char *) get_sqlite3_version()))
			return;
	}
}

void getClientsOverTime(const int sock, const bool istelnet)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
		return;

	// Get clients which the user doesn't want to see
	char * excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	// Array of clients to be skipped in the output
	// if skipclient[i] == true then this client should be hidden from
	// returned data. We initialize it with false
	bool skipclient[counters->clients];
	memset(skipclient, false, counters->clients*sizeof(bool));

	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);

		for(int clientID=0; clientID < counters->clients; clientID++)
		{
			// Get client pointer
			const clientsData* client = getClient(clientID, true);
			// Skip invalid clients
			if(client == NULL)
				continue;

			// Check if this client should be skipped
			if(insetupVarsArray(getstr(client->ippos)) ||
			   insetupVarsArray(getstr(client->namepos)) ||
			   (!client->flags.aliasclient && client->aliasclient_id > -1))
				skipclient[clientID] = true;
		}
	}

	// Main return loop
	for(int slot = 0; slot < OVERTIME_SLOTS; slot++)
	{
		if(istelnet)
			ssend(sock, "%lli", (long long)overTime[slot].timestamp);
		else
			pack_int32(sock, (int32_t)overTime[slot].timestamp);

		// Loop over forward destinations to generate output to be sent to the client
		for(int clientID = 0; clientID < counters->clients; clientID++)
		{
			if(skipclient[clientID])
				continue;

			// Get client pointer
			const clientsData* client = getClient(clientID, true);
			// Skip invalid clients and also those managed by alias clients
			if(client == NULL || client->aliasclient_id >= 0)
				continue;
			// Also skip clients with no active counts at all (may be old IPv6 addresses)
			if(client->count == 0)
				continue;
			const int thisclient = client->overTime[slot];

			if(istelnet)
				ssend(sock, " %i", thisclient);
			else
				pack_int32(sock, thisclient);
		}

		if(istelnet)
			ssend(sock, "\n");
		else
			pack_int32(sock, -1);
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();
}

void getClientNames(const int sock, const bool istelnet)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS_CLIENTS)
		return;

	// Get clients which the user doesn't want to see
	char * excludeclients = read_setupVarsconf("API_EXCLUDE_CLIENTS");
	// Array of clients to be skipped in the output
	// if skipclient[i] == true then this client should be hidden from
	// returned data. We initialize it with false
	bool skipclient[counters->clients];
	memset(skipclient, false, counters->clients*sizeof(bool));

	if(excludeclients != NULL)
	{
		getSetupVarsArray(excludeclients);

		for(int clientID=0; clientID < counters->clients; clientID++)
		{
			// Get client pointer
			const clientsData* client = getClient(clientID, true);
			// Skip invalid clients
			if(client == NULL)
				continue;

			// Check if this client should be skipped
			if(insetupVarsArray(getstr(client->ippos)) ||
			   insetupVarsArray(getstr(client->namepos)) ||
			   (!client->flags.aliasclient && client->aliasclient_id > -1))
				skipclient[clientID] = true;
		}
	}

	// Loop over clients to generate output to be sent to the client
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		if(skipclient[clientID])
			continue;

		// Get client pointer
		const clientsData* client = getClient(clientID, true);
		// Skip invalid clients and also those managed by alias clients
		if(client == NULL || client->aliasclient_id >= 0)
			continue;
		// Skip clients with no active counts at all (may be old IPv6 addresses)
		if(client->count == 0)
			continue;

		const char *client_ip = getstr(client->ippos);
		const char *client_name = getstr(client->namepos);

		if(istelnet)
			ssend(sock, "%s %s\n", client_name, client_ip);
		else {
			pack_str32(sock, client_name);
			pack_str32(sock, client_ip);
		}
	}

	if(excludeclients != NULL)
		clearSetupVarsArray();
}

void getUnknownQueries(const int sock, const bool istelnet)
{
	// Exit before processing any data if requested via config setting
	get_privacy_level(NULL);
	if(config.privacylevel >= PRIVACY_HIDE_DOMAINS)
		return;

	for(int queryID = 0; queryID < counters->queries; queryID++)
	{
		const queriesData* query = getQuery(queryID, true);

		if(query == NULL ||
		  (query->status != QUERY_UNKNOWN && query->flags.complete))
			continue;

		char type[5];
		if(query->type == TYPE_A)
		{
			strcpy(type,"IPv4");
		}
		else
		{
			strcpy(type,"IPv6");
		}

		// Get domain pointer
		const domainsData* domain = getDomain(query->domainID, true);
		// Get client pointer
		const clientsData* client = getClient(query->clientID, true);

		if(domain == NULL || client == NULL)
			continue;

		// Get client IP string
		const char *clientIP = getstr(client->ippos);

		if(istelnet)
			ssend(sock, "%lli %i %i %s %s %s %i %s\n", (long long)query->timestamp, queryID, query->id, type, getstr(domain->domainpos), clientIP, query->status, query->flags.complete ? "true" : "false");
		else {
			pack_int32(sock, (int32_t)query->timestamp);
			pack_int32(sock, query->id);

			// Use a fixstr because the length of qtype is always 4 (max is 31 for fixstr)
			if(!pack_fixstr(sock, type))
				return;

			// Use str32 for domain and client because we have no idea how long they will be (max is 4294967295 for str32)
			if(!pack_str32(sock, getstr(domain->domainpos)) || !pack_str32(sock, clientIP))
				return;

			pack_uint8(sock, query->status);
			pack_bool(sock, query->flags.complete);
		}
	}
}

// FTL_unlink_DHCP_lease()
extern bool FTL_unlink_DHCP_lease(const char *ipaddr);

void delete_lease(const char *client_message, const int sock)
{
	// Extract IP address from request
	char ipaddr[INET6_ADDRSTRLEN] = { 0 };
	if(sscanf(client_message, ">delete-lease %"xstr(INET6_ADDRSTRLEN)"s", ipaddr) < 1) {
		ssend(sock, "ERROR: No IP address specified!\n");
		return;
	}
	ipaddr[sizeof(ipaddr) - 1] = '\0';

	if(config.debug & DEBUG_API)
		logg("Received request to delete lease for %s", ipaddr);

	if(FTL_unlink_DHCP_lease(ipaddr))
		ssend(sock, "OK: Removed specified lease\n");
	else
		ssend(sock, "ERROR: Specified IP address invalid!\n");

	if(config.debug & DEBUG_API)
		logg("...done");
}

void getDNSport(const int sock)
{
	// Return DNS port used by FTL
	ssend(sock, "%d\n", config.dns_port);
}

void getMAXLOGAGE(const int sock)
{
	// Return maxlogage used by FTL
	ssend(sock, "%d\n", config.maxlogage);
}

static bool getDefaultInterface(char iface[IF_NAMESIZE], in_addr_t *gw)
{
	// Get IPv4 default route gateway and associated interface
	long dest_r = 0, gw_r = 0;
	int flags = 0, metric = 0, minmetric = __INT_MAX__;
	char iface_r[IF_NAMESIZE] = { 0 };
	char buf[1024] = { 0 };

	FILE *file;
	if((file = fopen("/proc/net/route", "r")))
	{
		// Parse /proc/net/route - the kernel's IPv4 routing table
		while(fgets(buf, sizeof(buf), file))
		{
			if(sscanf(buf, "%s %lx %lx %x %*i %*i %i", iface_r, &dest_r, &gw_r, &flags, &metric) != 5)
				continue;

			// Only analyze routes which are UP and whose
			// destinations are a gateway
			if(!(flags & RTF_UP) || !(flags & RTF_GATEWAY))
				continue;

			// Only analyze "catch all" routes (destination 0.0.0.0)
			if(dest_r != 0)
				continue;

			// Store default gateway, overwrite if we find a route with
			// a lower metric
			if(metric < minmetric)
			{
				minmetric = metric;
				*gw = gw_r;
				strcpy(iface, iface_r);

				if(config.debug & DEBUG_API)
					logg("Reading interfaces: flags: %i, addr: %s, iface: %s, metric: %i, minmetric: %i",
					     flags, inet_ntoa(*(struct in_addr *) gw), iface, metric, minmetric);
			}
		}
		fclose(file);
	}
	else
		logg("Cannot read /proc/net/route: %s", strerror(errno));

	// Return success based on having found the default gateway's address
	return gw != 0;
}

void getGateway(const int sock)
{
	in_addr_t gw = 0;
	char iface[IF_NAMESIZE] = { 0 };

	getDefaultInterface(iface, &gw);
	ssend(sock, "%s %s\n", inet_ntoa(*(struct in_addr *) &gw), iface);
}

struct if_info {
	bool carrier;
	bool default_iface;
	char *name;
	struct {
		char *v4;
		char *v6;
	} ip;
	int speed;
	ssize_t rx_bytes;
	ssize_t tx_bytes;
	sa_family_t family;
	struct if_info *next;
};

#include <dirent.h>

static bool listInterfaces(struct if_info **head, char default_iface[IF_NAMESIZE])
{
	// Loop over interfaces and extract information
	DIR *dfd;
	FILE *f;
	struct dirent *dp;
	struct if_info *tail = NULL;
	size_t tx_sum = 0, rx_sum = 0;
	char fname[64 + IF_NAMESIZE] = { 0 };
	char readbuffer[1024] = { 0 };

	// Open /sys/class/net directory
	if ((dfd = opendir("/sys/class/net")) == NULL)
	{
		logg("API: Cannot access /sys/class/net");
		return false;
	}

	// Get IP addresses of all interfaces on this machine
	struct ifaddrs *ifap = NULL;
	if(getifaddrs(&ifap) == -1)
		logg("API error: Cannot get interface addresses: %s", strerror(errno));

	// Walk /sys/class/net directory
	while ((dp = readdir(dfd)) != NULL)
	{
		// Skip "." and ".."
		if(!dp->d_name || strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;

		// Create new interface record
		struct if_info *new = calloc(1, sizeof(struct if_info));
		new->name = strdup(dp->d_name);

		new->default_iface = strcmp(new->name, default_iface) == 0;

		// Extract carrier status
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/carrier", new->name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fgets(readbuffer, sizeof(readbuffer)-1, f) != NULL)
				new->carrier = readbuffer[0] == '1';
			fclose(f);
		}
		else
			logg("Cannot read %s: %s", fname, strerror(errno));

		// Extract link speed (may not be possible, e.g., for WiFi devices with dynamic link speeds)
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/speed", new->name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%i", &(new->speed)) != 1)
				new->speed = -1;
			fclose(f);
		}
		else
			logg("Cannot read %s: %s", fname, strerror(errno));

		// Get total transmitted bytes
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/tx_bytes", new->name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(new->tx_bytes)) != 1)
				new->tx_bytes = -1;
			fclose(f);
		}
		else
			logg("Cannot read %s: %s", fname, strerror(errno));

		// Get total transmitted bytes
		snprintf(fname, sizeof(fname)-1, "/sys/class/net/%s/statistics/rx_bytes", new->name);
		if((f = fopen(fname, "r")) != NULL)
		{
			if(fscanf(f, "%zi", &(new->rx_bytes)) != 1)
				new->rx_bytes = -1;
			fclose(f);
		}
		else
			logg("Cannot read %s: %s", fname, strerror(errno));

		// Get IP address(es) of this interface
		if(ifap)
		{
			// Walk through linked list of interface addresses

			for(struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
			{
				// Skip interfaces without an address and those
				// not matching the current interface
				if(ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, new->name) != 0)
					continue;

				// If we reach this point, we found the correct interface
				new->family = ifa->ifa_addr->sa_family;
				char host[NI_MAXHOST] = { 0 };
				if(new->family == AF_INET || new->family == AF_INET6)
				{
					// Get IP address
					const int s = getnameinfo(ifa->ifa_addr,
					                          (new->family == AF_INET) ?
					                               sizeof(struct sockaddr_in) :
					                               sizeof(struct sockaddr_in6),
					                          host, NI_MAXHOST,
					                          NULL, 0, NI_NUMERICHOST);
					if (s != 0)
					{
						logg("API warning: getnameinfo() failed: %s\n", gai_strerror(s));
						continue;
					}

					if(new->family == AF_INET)
					{
						// IPv4 address
						if(!new->ip.v4)
						{
							// First or only IPv4 address of this interface
							new->ip.v4 = strdup(host);
						}
						else
						{
							// Create comma-separated list
							char *new_v4 = calloc(strlen(new->ip.v4) + strlen(host) + 2, sizeof(char));
							sprintf(new_v4, "%s,%s", new->ip.v4, host);
							free(new->ip.v4);
							new->ip.v4 = new_v4;
						}
					}
					else if(new->family == AF_INET6)
					{
						// IPv6 address
						if(!new->ip.v6)
						{
							// First or only IPv6 address of this interface
							new->ip.v6 = strdup(host);
						}
						else
						{
							// Create comma-separated list
							char *new_v6 = calloc(strlen(new->ip.v6) + strlen(host) + 2, sizeof(char));
							sprintf(new_v6, "%s,%s", new->ip.v6, host);
							free(new->ip.v6);
							new->ip.v6 = new_v6;
						}
					}
				}
			}
		}

		// Add to end of the linked list
		if(!*head)
			*head = new;
		if(tail)
			tail->next = new;
		tail = new;

		tx_sum += new->tx_bytes;
		rx_sum += new->rx_bytes;
	}

	closedir(dfd);
	freeifaddrs(ifap);

	// Create sum entry only if there is more than one interface
	if(head == NULL)
		return true;

	struct if_info *new = calloc(1, sizeof(struct if_info));
	new->name = strdup("sum");
	new->carrier = true;
	new->speed = 0;
	new->tx_bytes = tx_sum;
	new->rx_bytes = rx_sum;
	if(tail)
		tail->next = new;
	tail = new;

	return true;
}

static bool send_iface(const int sock, struct if_info *iface)
{
	double tx = 0.0, rx = 0.0;
	char txp[2] = { 0 }, rxp[2] = { 0 };
	format_memory_size(txp, iface->tx_bytes, &tx);
	format_memory_size(rxp, iface->rx_bytes, &rx);
	return ssend(sock, "%s %s %i %.1f%sB %.1f%sB %s %s\n",
	             iface->name,
	             iface->carrier ? "UP" : "DOWN",
	             iface->speed,
	             tx, txp, rx, rxp,
	             iface->carrier && iface->ip.v4 ? iface->ip.v4 : "-",
	             iface->carrier && iface->ip.v6 ? iface->ip.v6 : "-");
}

void getInterfaces(const int sock)
{
	// Get interface with default route
	in_addr_t gw = 0;
	char default_iface[IF_NAMESIZE] = { 0 };
	getDefaultInterface(default_iface, &gw);

	// Enumerate and list interfaces
	struct if_info *ifinfo = NULL;
	if(!listInterfaces(&ifinfo, default_iface))
	{
		ssend(sock, "ERROR");
		return;
	}

	// Loop over collected interface information
	struct if_info *iface = ifinfo;
	// Show only the default interface as first interface
	while(iface)
	{
		if(iface->default_iface)
		{
			send_iface(sock, iface);
			break;
		}
		iface = iface->next;
	}
	iface = ifinfo;
	// Show all but the default interface
	while(iface)
	{
		if(!iface->default_iface)
			send_iface(sock, iface);

		// Free associated memory
		struct if_info *next = iface->next;
		if(iface->name)
			free(iface->name);
		if(iface->ip.v4)
			free(iface->ip.v4);
		if(iface->ip.v6)
			free(iface->ip.v6);
		free(iface);
		iface = next;
	}
}