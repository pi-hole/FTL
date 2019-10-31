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

// Statistic methods
int api_stats_summary(struct mg_connection *conn);
int api_dns_status(struct mg_connection *conn);

int api_stats_overTime_history(struct mg_connection *conn);
int api_stats_overTime_clients(struct mg_connection *conn);

void getTopDomains(const bool blocked, struct mg_connection *conn);
void getTopClients(const bool blocked_only, struct mg_connection *conn);
void getForwardDestinations(struct mg_connection *conn);
void getQueryTypes(struct mg_connection *conn);
void getAllQueries(const char *client_message, struct mg_connection *conn);
void getRecentBlocked(const char *client_message, struct mg_connection *conn);
void getQueryTypesOverTime(struct mg_connection *conn);
void getClientNames(struct mg_connection *conn);

// FTL methods
int api_ftl_clientIP(struct mg_connection *conn);
int api_ftl_version(struct mg_connection *conn);
int api_ftl_db(struct mg_connection *conn);

#endif // API_H
