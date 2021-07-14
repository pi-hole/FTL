/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTL_PRIVATE
#include "special_domain.h"
// struct config
#include "../config/config.h"
// blockingreason, force_next_DNS_reply
#include "make_answer.h"

bool special_domain(const queriesData *query, const char *domain)
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
	if(config.special_domains.mozilla_canary &&
	   strcasecmp(domain, "use-application-dns.net") == 0 &&
	   (query->type == TYPE_A || query->type == TYPE_AAAA))
	{
		blockingreason = "Mozilla canary domain";
		force_next_DNS_reply = REPLY_NXDOMAIN;
		return true;
	}

	return false;
}