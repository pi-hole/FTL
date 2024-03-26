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
	DNSSEC_UNKNOWN,
	DNSSEC_SECURE,
	DNSSEC_INSECURE,
	DNSSEC_BOGUS,
	DNSSEC_ABANDONED,
	DNSSEC_TRUNCATED,
	DNSSEC_MAX
} __attribute__ ((packed));

enum query_status {
	QUERY_UNKNOWN,
	QUERY_GRAVITY,
	QUERY_FORWARDED,
	QUERY_CACHE,
	QUERY_REGEX,
	QUERY_DENYLIST,
	QUERY_EXTERNAL_BLOCKED_IP,
	QUERY_EXTERNAL_BLOCKED_NULL,
	QUERY_EXTERNAL_BLOCKED_NXRA,
	QUERY_GRAVITY_CNAME,
	QUERY_REGEX_CNAME,
	QUERY_DENYLIST_CNAME,
	QUERY_RETRIED,
	QUERY_RETRIED_DNSSEC,
	QUERY_IN_PROGRESS,
	QUERY_DBBUSY,
	QUERY_SPECIAL_DOMAIN,
	QUERY_CACHE_STALE,
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
	MODE_NODATA,
	MODE_MAX
} __attribute__ ((packed));

enum regex_type {
	REGEX_DENY,
	REGEX_ALLOW,
	REGEX_CLI,
	REGEX_MAX
} __attribute__ ((packed));

enum query_type {
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
	DNS_FAILED,
	BLOCKING_UNKNOWN
} __attribute__ ((packed));

// Blocking status constants used by the dns_cache->blocking_status vector
// We explicitly force UNKNOWN_BLOCKED to zero on all platforms as this is the
// default value set initially with calloc
enum domain_client_status {
	UNKNOWN_BLOCKED = 0,
	GRAVITY_BLOCKED,
	DENYLIST_BLOCKED,
	REGEX_BLOCKED,
	ALLOWED,
	SPECIAL_DOMAIN,
	NOT_BLOCKED
} __attribute__ ((packed));

enum debug_flag {
	DEBUG_DATABASE = 1,
	DEBUG_NETWORKING,
	DEBUG_LOCKS,
	DEBUG_QUERIES,
	DEBUG_FLAGS,
	DEBUG_SHMEM,
	DEBUG_GC,
	DEBUG_ARP,
	DEBUG_REGEX,
	DEBUG_API,
	DEBUG_TLS,
	DEBUG_OVERTIME,
	DEBUG_STATUS,
	DEBUG_CAPS,
	DEBUG_DNSSEC,
	DEBUG_VECTORS,
	DEBUG_RESOLVER,
	DEBUG_EDNS0,
	DEBUG_CLIENTS,
	DEBUG_ALIASCLIENTS,
	DEBUG_EVENTS,
	DEBUG_HELPER,
	DEBUG_CONFIG,
	DEBUG_INOTIFY,
	DEBUG_WEBSERVER,
	DEBUG_EXTRA,
	DEBUG_RESERVED,
	DEBUG_MAX
} __attribute__ ((packed));

enum events {
	RELOAD_GRAVITY,
	RESOLVE_NEW_HOSTNAMES,
	RERESOLVE_HOSTNAMES,
	RERESOLVE_HOSTNAMES_FORCE,
	REIMPORT_ALIASCLIENTS,
	PARSE_NEIGHBOR_CACHE,
	EVENTS_MAX
} __attribute__ ((packed));


enum gravity_list_type {
	GRAVITY_DOMAINLIST_ALLOW_EXACT,
	GRAVITY_DOMAINLIST_ALLOW_REGEX,
	GRAVITY_DOMAINLIST_ALLOW_ALL,
	GRAVITY_DOMAINLIST_DENY_EXACT,
	GRAVITY_DOMAINLIST_DENY_REGEX,
	GRAVITY_DOMAINLIST_DENY_ALL,
	GRAVITY_DOMAINLIST_ALL_EXACT,
	GRAVITY_DOMAINLIST_ALL_REGEX,
	GRAVITY_DOMAINLIST_ALL_ALL,
	GRAVITY_GROUPS,
	GRAVITY_ADLISTS,
	GRAVITY_CLIENTS,
	GRAVITY_GRAVITY,
	GRAVITY_ANTIGRAVITY,
	GRAVITY_ADLISTS_BLOCK,
	GRAVITY_ADLISTS_ALLOW
} __attribute__ ((packed));

enum gravity_tables {
	GRAVITY_TABLE,
	EXACT_BLACKLIST_TABLE,
	EXACT_WHITELIST_TABLE,
	REGEX_DENY_TABLE,
	REGEX_ALLOW_TABLE,
	CLIENTS_TABLE,
	GROUPS_TABLE,
	ADLISTS_TABLE,
	DENIED_DOMAINS_TABLE,
	ALLOWED_DOMAINS_TABLE,
	UNKNOWN_TABLE
} __attribute__ ((packed));

enum timers {
	DATABASE_WRITE_TIMER,
	EXIT_TIMER,
	GC_TIMER,
	LISTS_TIMER,
	REGEX_TIMER,
	ARP_TIMER,
	LAST_TIMER
} __attribute__ ((packed));

enum refresh_hostnames {
	REFRESH_ALL,
	REFRESH_IPV4_ONLY,
	REFRESH_UNKNOWN,
	REFRESH_NONE
} __attribute__ ((packed));

enum api_auth_status {
	API_AUTH_UNAUTHORIZED  = -1,
	API_AUTH_LOCALHOST  = -2,
	API_AUTH_EMPTYPASS  = -3,
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
	CONF_READER,
	TIMER,
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
	DISK_MESSAGE_EXTENDED,
	CERTIFICATE_DOMAIN_MISMATCH_MESSAGE,
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
	ADDINFO_LIST_ID
} __attribute__ ((packed));

enum listening_mode {
	LISTEN_LOCAL,
	LISTEN_ALL,
	LISTEN_SINGLE,
	LISTEN_BIND,
	LISTEN_NONE
} __attribute__ ((packed));

enum fifo_logs {
	FIFO_FTL = 1,
	FIFO_DNSMASQ,
	FIFO_WEBSERVER,
	FIFO_MAX
} __attribute__ ((packed));

enum temp_unit {
	TEMP_UNIT_C = 0,
	TEMP_UNIT_F,
	TEMP_UNIT_K
} __attribute__ ((packed));

enum adlist_type {
	ADLIST_BLOCK = 0,
	ADLIST_ALLOW
} __attribute__ ((packed));

enum cert_check {
	CERT_FILE_NOT_FOUND,
	CERT_CANNOT_PARSE_CERT,
	CERT_CANNOT_PARSE_KEY,
	CERT_DOMAIN_MISMATCH,
	CERT_DOMAIN_MATCH,
	CERT_OKAY
} __attribute__ ((packed));

enum http_method {
	HTTP_UNKNOWN = 0,
	HTTP_GET = 1 << 0,
	HTTP_POST = 1 << 1,
	HTTP_PUT = 1 << 2,
	HTTP_PATCH = 1 << 3,
	HTTP_DELETE = 1 << 4,
	HTTP_OPTIONS = 1 << 5,
};

enum api_flags {
	API_FLAG_NONE = 0,
	API_DOMAINS = 1 << 0,
	API_PARSE_JSON = 1 << 1,
	API_BATCHDELETE = 1 << 2,
};

#endif // ENUMS_H
