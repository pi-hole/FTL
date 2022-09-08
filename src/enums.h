/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Global enums
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef ENUMS_H
#define ENUMS_H

enum memory_type {
	QUERIES,
	UPSTREAMS,
	CLIENTS,
	DOMAINS,
	OVERTIME,
	DNS_CACHE,
	STRINGS
} __attribute__ ((packed));

enum dnssec_status {
	DNSSEC_UNSPECIFIED,
	DNSSEC_SECURE,
	DNSSEC_INSECURE,
	DNSSEC_BOGUS,
	DNSSEC_ABANDONED
} __attribute__ ((packed));

enum query_status {
	QUERY_UNKNOWN,
	QUERY_GRAVITY,
	QUERY_FORWARDED,
	QUERY_CACHE,
	QUERY_REGEX,
	QUERY_BLACKLIST,
	QUERY_EXTERNAL_BLOCKED_IP,
	QUERY_EXTERNAL_BLOCKED_NULL,
	QUERY_EXTERNAL_BLOCKED_NXRA,
	QUERY_GRAVITY_CNAME,
	QUERY_REGEX_CNAME,
	QUERY_BLACKLIST_CNAME,
	QUERY_RETRIED,
	QUERY_RETRIED_DNSSEC,
	QUERY_IN_PROGRESS,
	QUERY_DBBUSY,
	QUERY_SPECIAL_DOMAIN,
	QUERY_STATUS_MAX
} __attribute__ ((packed));

enum reply_type {
	REPLY_UNKNOWN,
	REPLY_NODATA,
	REPLY_NXDOMAIN,
	REPLY_CNAME,
	REPLY_IP,
	REPLY_DOMAIN,
	REPLY_RRNAME,
	REPLY_SERVFAIL,
	REPLY_REFUSED,
	REPLY_NOTIMP,
	REPLY_OTHER,
	REPLY_DNSSEC,
	REPLY_NONE,
	REPLY_BLOB,
	QUERY_REPLY_MAX
	}  __attribute__ ((packed));

enum privacy_level {
	PRIVACY_SHOW_ALL = 0,
	PRIVACY_HIDE_DOMAINS,
	PRIVACY_HIDE_DOMAINS_CLIENTS,
	PRIVACY_MAXIMUM
} __attribute__ ((packed));

enum blocking_mode {
	MODE_IP,
	MODE_NX,
	MODE_NULL,
	MODE_IP_NODATA_AAAA,
	MODE_NODATA
} __attribute__ ((packed));

enum regex_type {
	REGEX_BLACKLIST,
	REGEX_WHITELIST,
	REGEX_CLI,
	REGEX_MAX
} __attribute__ ((packed));

enum query_types {
	TYPE_A = 1,
	TYPE_AAAA,
	TYPE_ANY,
	TYPE_SRV,
	TYPE_SOA,
	TYPE_PTR,
	TYPE_TXT,
	TYPE_NAPTR,
	TYPE_MX,
	TYPE_DS,
	TYPE_RRSIG,
	TYPE_DNSKEY,
	TYPE_NS,
	TYPE_OTHER,
	TYPE_SVCB,
	TYPE_HTTPS,
	TYPE_MAX
} __attribute__ ((packed));

enum blocking_status {
	BLOCKING_DISABLED,
	BLOCKING_ENABLED,
	BLOCKING_UNKNOWN
} __attribute__ ((packed));

// Blocking status constants used by the dns_cache->blocking_status vector
// We explicitly force UNKNOWN_BLOCKED to zero on all platforms as this is the
// default value set initially with calloc
enum domain_client_status {
	UNKNOWN_BLOCKED = 0,
	GRAVITY_BLOCKED,
	BLACKLIST_BLOCKED,
	REGEX_BLOCKED,
	WHITELISTED,
	SPECIAL_DOMAIN,
	NOT_BLOCKED
} __attribute__ ((packed));

enum debug_flags {
	DEBUG_DATABASE      = (1 << 0),  /* 00000000 00000000 00000000 00000001 */
	DEBUG_NETWORKING    = (1 << 1),  /* 00000000 00000000 00000000 00000010 */
	DEBUG_LOCKS         = (1 << 2),  /* 00000000 00000000 00000000 00000100 */
	DEBUG_QUERIES       = (1 << 3),  /* 00000000 00000000 00000000 00001000 */
	DEBUG_FLAGS         = (1 << 4),  /* 00000000 00000000 00000000 00010000 */
	DEBUG_SHMEM         = (1 << 5),  /* 00000000 00000000 00000000 00100000 */
	DEBUG_GC            = (1 << 6),  /* 00000000 00000000 00000000 01000000 */
	DEBUG_ARP           = (1 << 7),  /* 00000000 00000000 00000000 10000000 */
	DEBUG_REGEX         = (1 << 8),  /* 00000000 00000000 00000001 00000000 */
	DEBUG_API           = (1 << 9),  /* 00000000 00000000 00000010 00000000 */
	DEBUG_OVERTIME      = (1 << 10), /* 00000000 00000000 00000100 00000000 */
	DEBUG_STATUS        = (1 << 11), /* 00000000 00000000 00001000 00000000 */
	DEBUG_CAPS          = (1 << 12), /* 00000000 00000000 00010000 00000000 */
	DEBUG_DNSSEC        = (1 << 13), /* 00000000 00000000 00100000 00000000 */
	DEBUG_VECTORS       = (1 << 14), /* 00000000 00000000 01000000 00000000 */
	DEBUG_RESOLVER      = (1 << 15), /* 00000000 00000000 10000000 00000000 */
	DEBUG_EDNS0         = (1 << 16), /* 00000000 00000001 00000000 00000000 */
	DEBUG_CLIENTS       = (1 << 17), /* 00000000 00000010 00000000 00000000 */
	DEBUG_ALIASCLIENTS  = (1 << 18), /* 00000000 00000100 00000000 00000000 */
	DEBUG_EVENTS        = (1 << 19), /* 00000000 00001000 00000000 00000000 */
	DEBUG_HELPER        = (1 << 20), /* 00000000 00010000 00000000 00000000 */
	DEBUG_EXTRA         = (1 << 21), /* 00000000 00100000 00000000 00000000 */
} __attribute__ ((packed));

enum events {
	RELOAD_GRAVITY,
	RELOAD_PRIVACY_LEVEL,
	RESOLVE_NEW_HOSTNAMES,
	RERESOLVE_HOSTNAMES,
	RERESOLVE_HOSTNAMES_FORCE,
	REIMPORT_ALIASCLIENTS,
	PARSE_NEIGHBOR_CACHE,
	RELOAD_BLOCKINGSTATUS,
	EVENTS_MAX
} __attribute__ ((packed));

enum refresh_hostnames {
	REFRESH_ALL,
	REFRESH_IPV4_ONLY,
	REFRESH_UNKNOWN,
	REFRESH_NONE
} __attribute__ ((packed));

enum db_result {
	NOT_FOUND,
	FOUND,
	LIST_NOT_AVAILABLE
} __attribute__ ((packed));

enum busy_reply {
	BUSY_BLOCK,
	BUSY_ALLOW,
	BUSY_REFUSE,
	BUSY_DROP
} __attribute__ ((packed));

enum thread_types {
	DB,
	GC,
	DNSclient,
	THREADS_MAX
} __attribute__ ((packed));

enum telnet_type {
	TELNETv4,
	TELNETv6,
	TELNET_SOCK,
	TELNET_MAX
} __attribute__ ((packed));

enum message_type {
	REGEX_MESSAGE,
	SUBNET_MESSAGE,
	HOSTNAME_MESSAGE,
	DNSMASQ_CONFIG_MESSAGE,
	RATE_LIMIT_MESSAGE,
	DNSMASQ_WARN_MESSAGE,
	LOAD_MESSAGE,
	SHMEM_MESSAGE,
	DISK_MESSAGE,
	INACCESSIBLE_ADLIST_MESSAGE,
	MAX_MESSAGE,
} __attribute__ ((packed));

enum ptr_type {
	PTR_PIHOLE,
	PTR_HOSTNAME,
	PTR_HOSTNAMEFQDN,
	PTR_NONE
} __attribute__ ((packed));

enum addinfo_type {
	ADDINFO_CNAME_DOMAIN = 1,
	ADDINFO_REGEX_ID
} __attribute__ ((packed));

#endif // ENUMS_H
