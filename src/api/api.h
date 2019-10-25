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
void api_stats_summary(struct mg_connection *conn);
void api_dns_status(struct mg_connection *conn);

void getOverTime(struct mg_connection *conn);
void getTopDomains(const bool blocked, struct mg_connection *conn);
void getTopClients(const bool blocked_only, struct mg_connection *conn);
void getForwardDestinations(struct mg_connection *conn);
void getQueryTypes(struct mg_connection *conn);
void getAllQueries(const char *client_message, struct mg_connection *conn);
void getRecentBlocked(const char *client_message, struct mg_connection *conn);
void getQueryTypesOverTime(struct mg_connection *conn);
void getClientsOverTime(struct mg_connection *conn);
void getClientNames(struct mg_connection *conn);

// FTL methods
void getClientIP(struct mg_connection *conn);
void api_ftl_version(struct mg_connection *conn);
void api_ftl_db(struct mg_connection *conn);

// MessagePack serialization helpers
void pack_eom(const int sock);
void pack_bool(const int sock, const bool value);
void pack_uint8(const int sock, const uint8_t value);
void pack_uint64(const int sock, const uint64_t value);
void pack_int32(const int sock, const int32_t value);
void pack_int64(const int sock, const int64_t value);
void pack_float(const int sock, const float value);
bool pack_fixstr(const int sock, const char *string);
bool pack_str32(const int sock, const char *string);
void pack_map16_start(const int sock, const uint16_t length);

#endif // API_H
