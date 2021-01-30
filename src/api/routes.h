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
#include "../civetweb/civetweb.h"
// type cJSON
#include "../cJSON/cJSON.h"
#include "../webserver/http-common.h"

// API router
int api_handler(struct mg_connection *conn, void *ignored);

// Statistic methods
int api_stats_summary(struct ftl_conn *api);
int api_stats_query_types(struct ftl_conn *api);
int api_stats_upstreams(struct ftl_conn *api);
int api_stats_top_domains(bool blocked, struct ftl_conn *api);
int api_stats_top_clients(bool blocked, struct ftl_conn *api);
int api_stats_history(struct ftl_conn *api);
int api_stats_recentblocked(struct ftl_conn *api);

// History methods
int api_history(struct ftl_conn *api);
int api_history_clients(struct ftl_conn *api);

// Statistics methods (database)
int api_stats_database_overTime_history(struct ftl_conn *api);
int api_stats_database_top_items(bool blocked, bool domains, struct ftl_conn *api);
int api_stats_database_summary(struct ftl_conn *api);
int api_stats_database_overTime_clients(struct ftl_conn *api);
int api_stats_database_query_types(struct ftl_conn *api);
int api_stats_database_upstreams(struct ftl_conn *api);

// FTL methods
int api_ftl_client(struct ftl_conn *api);
int api_ftl_logs_dns(struct ftl_conn *api);
int api_ftl_dbinfo(struct ftl_conn *api);
int api_ftl_sysinfo(struct ftl_conn *api);
int get_ftl_obj(struct ftl_conn *api, cJSON *ftl);
int get_system_obj(struct ftl_conn *api, cJSON *system);

// Network methods
int api_network(struct ftl_conn *api);

// DNS methods
int api_dns_blocking(struct ftl_conn *api);
int api_dns_cache(struct ftl_conn *api);

// List methods
int api_list(struct ftl_conn *api);
int api_group(struct ftl_conn *api);

// Version method
int api_version(struct ftl_conn *api);

// Auth method
int check_client_auth(struct ftl_conn *api);
int api_auth(struct ftl_conn *api);

// Settings methods
int api_settings_web(struct ftl_conn *api);

// Documentation methods
int api_docs(struct ftl_conn *api);

#endif // ROUTES_H
