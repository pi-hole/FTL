/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API route prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef ROUTES_H
#define ROUTES_H

// struct mg_connection
#include "webserver/civetweb/civetweb.h"
// type cJSON
#include "webserver/cJSON/cJSON.h"
#include "webserver/http-common.h"
// regex_t
#include "regex_r.h"

// Common definitions
#define LOCALHOSTv4 "127.0.0.1"
#define LOCALHOSTv6 "::1"

// API router
int api_handler(struct mg_connection *conn, void *ignored);

// Statistic methods
int __attribute__((pure)) cmpdesc(const void *a, const void *b);
int api_stats_summary(struct ftl_conn *api);
int api_stats_query_types(struct ftl_conn *api);
int api_stats_upstreams(struct ftl_conn *api);
int api_stats_top_domains(struct ftl_conn *api);
int api_stats_top_clients(struct ftl_conn *api);
int api_stats_recentblocked(struct ftl_conn *api);

// History methods
int api_history(struct ftl_conn *api);
int api_history_clients(struct ftl_conn *api);

// History methods (database)
int api_history_database(struct ftl_conn *api);
int api_history_database_clients(struct ftl_conn *api);

// Query methods
int api_queries(struct ftl_conn *api);
int api_queries_suggestions(struct ftl_conn *api);
bool compile_filter_regex(struct ftl_conn *api, const char *path, cJSON *json, regex_t **regex, unsigned int *N_regex);

// Statistics methods (database)
int api_stats_database_top_items(struct ftl_conn *api);
int api_stats_database_summary(struct ftl_conn *api);
int api_stats_database_query_types(struct ftl_conn *api);
int api_stats_database_upstreams(struct ftl_conn *api);

// Info methods
int api_info_client(struct ftl_conn *api);
int api_info_database(struct ftl_conn *api);
int api_info_system(struct ftl_conn *api);
int api_info_ftl(struct ftl_conn *api);
int api_info_host(struct ftl_conn *api);
int api_info_sensors(struct ftl_conn *api);
int api_info_version(struct ftl_conn *api);
int api_info_messages_count(struct ftl_conn *api);
int api_info_messages(struct ftl_conn *api);
int api_info_metrics(struct ftl_conn *api);
int api_info_login(struct ftl_conn *api);

// Config methods
int api_config(struct ftl_conn *api);

// Log methods
int api_logs(struct ftl_conn *api);

// Network methods
int api_network_gateway(struct ftl_conn *api);
int api_network_interfaces(struct ftl_conn *api);
int api_network_devices(struct ftl_conn *api);
int api_client_suggestions(struct ftl_conn *api);

// DNS methods
int api_dns_blocking(struct ftl_conn *api);

// List methods
int api_list(struct ftl_conn *api);
int api_group(struct ftl_conn *api);

// Auth method
void init_api(void);
void free_api(void);
int check_client_auth(struct ftl_conn *api, const bool is_api);
int api_auth(struct ftl_conn *api);
void delete_all_sessions(void);
int api_auth_sessions(struct ftl_conn *api);
int api_auth_session_delete(struct ftl_conn *api);
bool is_local_api_user(const char *remote_addr) __attribute__((pure));

// 2FA methods
enum totp_status {
	TOTP_INVALID,
	TOTP_CORRECT,
	TOTP_REUSED,
} __attribute__ ((packed));
enum totp_status verifyTOTP(const uint32_t code);
int generateTOTP(struct ftl_conn *api);
int printTOTP(void);
int generateAppPw(struct ftl_conn *api);

// Documentation methods
int api_docs(struct ftl_conn *api);

// Teleporter methods
int api_teleporter(struct ftl_conn *api);

// Action methods
int api_action_gravity(struct ftl_conn *api);
int api_action_restartDNS(struct ftl_conn *api);
int api_action_flush_logs(struct ftl_conn *api);
int api_action_flush_arp(struct ftl_conn *api);

// Search methods
int api_search(struct ftl_conn *api);

// DHCP methods
int api_dhcp_leases_GET(struct ftl_conn *api);
int api_dhcp_leases_DELETE(struct ftl_conn *api);

#endif // ROUTES_H
