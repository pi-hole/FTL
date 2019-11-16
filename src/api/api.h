/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API commands and MessagePack helpers
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef API_H
#define API_H

// struct mg_connection
#include "../civetweb/civetweb.h"
// http_send_json_chunk()
#include "../api/http.h"
#include "json_macros.h"

// Statistic methods
int api_stats_summary(struct mg_connection *conn);
int api_stats_overTime_history(struct mg_connection *conn);
int api_stats_overTime_clients(struct mg_connection *conn);
int api_stats_query_types(struct mg_connection *conn);
int api_stats_upstreams(struct mg_connection *conn);
int api_stats_top_domains(bool blocked, struct mg_connection *conn);
int api_stats_top_clients(bool blocked, struct mg_connection *conn);
int api_stats_history(struct mg_connection *conn);
int api_stats_recentblocked(struct mg_connection *conn);

// FTL methods
int api_ftl_clientIP(struct mg_connection *conn);
int api_ftl_version(struct mg_connection *conn);
int api_ftl_db(struct mg_connection *conn);

// DNS methods
int api_dns_status(struct mg_connection *conn);
int api_dns_somelist(struct mg_connection *conn,
                     bool show_exact, bool show_regex,
                     bool whitelist);

// Version method
int api_version(struct mg_connection *conn);

// Auth method
int api_auth(struct mg_connection *conn);
int api_auth_salt(struct mg_connection *conn);

// Settings methods
int api_settings_web(struct mg_connection *conn);

#endif // API_H
