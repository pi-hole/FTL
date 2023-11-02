/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation /api/docs (helper)
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef API_DOCS_H
#define API_DOCS_H

#include "FTL.h"
#include "webserver/civetweb/civetweb.h"
#include "webserver/http-common.h"
#include "webserver/json_macros.h"
#include "api/api.h"

static const unsigned char index_html[] = {
#include "hex/index.html"
};

static const unsigned char index_css[] = {
#include "hex/index.css"
};

static const unsigned char pi_hole_js[] = {
#include "hex/pi-hole.js"
};

static const unsigned char rapidoc_min_js[] = {
#include "hex/external/rapidoc-min.js"
};

static const unsigned char rapidoc_min_js_map[] = {
#include "hex/external/rapidoc-min.js.map"
};

static const unsigned char highlight_default_min_css[] = {
#include "hex/external/highlight-default.min.css"
};

static const unsigned char highlight_min_js[] = {
#include "hex/external/highlight.min.js"
};

static const unsigned char images_logo_svg[] = {
#include "hex/images/logo.svg"
};

static const unsigned char specs_auth_yaml[] = {
#include "hex/specs/auth.yaml"
};

static const unsigned char specs_clients_yaml[] = {
#include "hex/specs/clients.yaml"
};

static const unsigned char specs_common_yaml[] = {
#include "hex/specs/common.yaml"
};

static const unsigned char specs_dhcp_yaml[] = {
#include "hex/specs/dhcp.yaml"
};

static const unsigned char specs_dns_yaml[] = {
#include "hex/specs/dns.yaml"
};

static const unsigned char specs_docs_yaml[] = {
#include "hex/specs/docs.yaml"
};

static const unsigned char specs_domains_yaml[] = {
#include "hex/specs/domains.yaml"
};

static const unsigned char specs_info_yaml[] = {
#include "hex/specs/info.yaml"
};

static const unsigned char specs_groups_yaml[] = {
#include "hex/specs/groups.yaml"
};

static const unsigned char specs_history_yaml[] = {
#include "hex/specs/history.yaml"
};

static const unsigned char specs_lists_yaml[] = {
#include "hex/specs/lists.yaml"
};

static const unsigned char specs_main_yaml[] = {
#include "hex/specs/main.yaml"
};

static const unsigned char specs_queries_yaml[] = {
#include "hex/specs/queries.yaml"
};

static const unsigned char specs_stats_yaml[] = {
#include "hex/specs/stats.yaml"
};

static const unsigned char specs_config_yaml[] = {
#include "hex/specs/config.yaml"
};

static const unsigned char specs_network_yaml[] = {
#include "hex/specs/network.yaml"
};

static const unsigned char specs_logs_yaml[] = {
#include "hex/specs/logs.yaml"
};

static const unsigned char specs_endpoints_yaml[] = {
#include "hex/specs/endpoints.yaml"
};

static const unsigned char specs_teleporter_yaml[] = {
#include "hex/specs/teleporter.yaml"
};

static const unsigned char specs_search_yaml[] = {
#include "hex/specs/search.yaml"
};

static const unsigned char specs_action_yaml[] = {
#include "hex/specs/action.yaml"
};

struct {
    const char *path;
    const char *mime_type;
    const char *content;
    const size_t content_size;
} docs_files[] =
{
    {"index.html", "text/html", (const char*)index_html, sizeof(index_html)},
    {"index.css", "text/css", (const char*)index_css, sizeof(index_css)},
    {"pi-hole.js", "application/javascript", (const char*)pi_hole_js, sizeof(pi_hole_js)},
    {"external/rapidoc-min.js", "application/javascript", (const char*)rapidoc_min_js, sizeof(rapidoc_min_js)},
    {"external/rapidoc-min.js.map", "text/plain", (const char*)rapidoc_min_js_map, sizeof(rapidoc_min_js_map)},
    {"external/highlight-default.min.css", "text/css", (const char*)highlight_default_min_css, sizeof(highlight_default_min_css)},
    {"external/highlight.min.js", "application/javascript", (const char*)highlight_min_js, sizeof(highlight_min_js)},
    {"images/logo.svg", "image/svg+xml", (const char*)images_logo_svg, sizeof(images_logo_svg)},
    {"specs/auth.yaml", "text/plain", (const char*)specs_auth_yaml, sizeof(specs_auth_yaml)},
    {"specs/clients.yaml", "text/plain", (const char*)specs_clients_yaml, sizeof(specs_clients_yaml)},
    {"specs/config.yaml", "text/plain", (const char*)specs_config_yaml, sizeof(specs_config_yaml)},
    {"specs/common.yaml", "text/plain", (const char*)specs_common_yaml, sizeof(specs_common_yaml)},
    {"specs/dhcp.yaml", "text/plain", (const char*)specs_dhcp_yaml, sizeof(specs_dhcp_yaml)},
    {"specs/dns.yaml", "text/plain", (const char*)specs_dns_yaml, sizeof(specs_dns_yaml)},
    {"specs/domains.yaml", "text/plain", (const char*)specs_domains_yaml, sizeof(specs_domains_yaml)},
    {"specs/docs.yaml", "text/plain", (const char*)specs_docs_yaml, sizeof(specs_docs_yaml)},
    {"specs/endpoints.yaml", "text/plain", (const char*)specs_endpoints_yaml, sizeof(specs_endpoints_yaml)},
    {"specs/groups.yaml", "text/plain", (const char*)specs_groups_yaml, sizeof(specs_groups_yaml)},
    {"specs/history.yaml", "text/plain", (const char*)specs_history_yaml, sizeof(specs_history_yaml)},
    {"specs/info.yaml", "text/plain", (const char*)specs_info_yaml, sizeof(specs_info_yaml)},
    {"specs/lists.yaml", "text/plain", (const char*)specs_lists_yaml, sizeof(specs_lists_yaml)},
    {"specs/logs.yaml", "text/plain", (const char*)specs_logs_yaml, sizeof(specs_logs_yaml)},
    {"specs/main.yaml", "text/plain", (const char*)specs_main_yaml, sizeof(specs_main_yaml)},
    {"specs/network.yaml", "text/plain", (const char*)specs_network_yaml, sizeof(specs_network_yaml)},
    {"specs/queries.yaml", "text/plain", (const char*)specs_queries_yaml, sizeof(specs_queries_yaml)},
    {"specs/search.yaml", "text/plain", (const char*)specs_search_yaml, sizeof(specs_search_yaml)},
    {"specs/stats.yaml", "text/plain", (const char*)specs_stats_yaml, sizeof(specs_stats_yaml)},
    {"specs/teleporter.yaml", "text/plain", (const char*)specs_teleporter_yaml, sizeof(specs_teleporter_yaml)},
    {"specs/action.yaml", "text/plain", (const char*)specs_action_yaml, sizeof(specs_action_yaml)},
};

#endif // API_DOCS_H
