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

// API router
int api_handler(struct mg_connection *conn, void *ignored);

// Statistic methods
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
int api_info_messages(struct ftl_conn *api);
int api_info_cache(struct ftl_conn *api);

// Config methods
int api_config(struct ftl_conn *api);

// Log methods
int api_logs(struct ftl_conn *api);

// Network methods
int api_network_gateway(struct ftl_conn *api);
int api_network_interfaces(struct ftl_conn *api);
int api_network_devices(struct ftl_conn *api);

// DNS methods
int api_dns_blocking(struct ftl_conn *api);

// List methods
int api_list(struct ftl_conn *api);
int api_group(struct ftl_conn *api);

// Auth method
int check_client_auth(struct ftl_conn *api);
int api_auth(struct ftl_conn *api);

// Documentation methods
int api_docs(struct ftl_conn *api);

// Teleporter methods
int api_teleporter(struct ftl_conn *api);

// Action methods
int api_action_gravity(struct ftl_conn *api);
int api_action_poweroff(struct ftl_conn *api);
int api_action_reboot(struct ftl_conn *api);

// Search methods
int api_search(struct ftl_conn *api);

// DHCP methods
int api_dhcp_leases(struct ftl_conn *api);

#endif // ROUTES_H
