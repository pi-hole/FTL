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

#include "hex/index_html.h"
#include "hex/index_css.h"
#include "hex/pi-hole_js.h"
#include "hex/external/rapidoc-min_js.h"
#include "hex/external/rapidoc-min_js_map.h"
#include "hex/images/logo_svg.h"
#include "hex/images/favicon_ico.h"
#include "hex/specs/auth_yaml.h"
#include "hex/specs/clients_yaml.h"
#include "hex/specs/common_yaml.h"
#include "hex/specs/dhcp_yaml.h"
#include "hex/specs/dns_yaml.h"
#include "hex/specs/docs_yaml.h"
#include "hex/specs/domains_yaml.h"
#include "hex/specs/info_yaml.h"
#include "hex/specs/groups_yaml.h"
#include "hex/specs/history_yaml.h"
#include "hex/specs/lists_yaml.h"
#include "hex/specs/main_yaml.h"
#include "hex/specs/queries_yaml.h"
#include "hex/specs/stats_yaml.h"
#include "hex/specs/config_yaml.h"
#include "hex/specs/network_yaml.h"
#include "hex/specs/logs_yaml.h"
#include "hex/specs/endpoints_yaml.h"
#include "hex/specs/teleporter_yaml.h"
#include "hex/specs/search_yaml.h"
#include "hex/specs/action_yaml.h"
#include "hex/specs/padd_yaml.h"
struct {
    const char *path;
    const char *mime_type;
    const char *content;
    const size_t content_size;
} docs_files[] =
{
    {"index.html", "text/html", (const char*)index_html, index_html_len},
    {"index.css", "text/css", (const char*)index_css, index_css_len},
    {"pi-hole.js", "application/javascript", (const char*)pi_hole_js, pi_hole_js_len},
    {"external/rapidoc-min.js", "application/javascript", (const char*)external_rapidoc_min_js, external_rapidoc_min_js_len},
    {"external/rapidoc-min.js.map", "text/plain", (const char*)external_rapidoc_min_js_map, external_rapidoc_min_js_map_len},
    {"images/logo.svg", "image/svg+xml", (const char*)images_logo_svg, images_logo_svg_len},
    {"images/favicon.ico", "image/ico", (const char*)images_favicon_ico, images_favicon_ico_len},
    {"specs/auth.yaml", "text/plain", (const char*)specs_auth_yaml, specs_auth_yaml_len},
    {"specs/clients.yaml", "text/plain", (const char*)specs_clients_yaml, specs_clients_yaml_len},
    {"specs/config.yaml", "text/plain", (const char*)specs_config_yaml, specs_config_yaml_len},
    {"specs/common.yaml", "text/plain", (const char*)specs_common_yaml, specs_common_yaml_len},
    {"specs/dhcp.yaml", "text/plain", (const char*)specs_dhcp_yaml, specs_dhcp_yaml_len},
    {"specs/dns.yaml", "text/plain", (const char*)specs_dns_yaml, specs_dns_yaml_len},
    {"specs/domains.yaml", "text/plain", (const char*)specs_domains_yaml, specs_domains_yaml_len},
    {"specs/docs.yaml", "text/plain", (const char*)specs_docs_yaml, specs_docs_yaml_len},
    {"specs/endpoints.yaml", "text/plain", (const char*)specs_endpoints_yaml, specs_endpoints_yaml_len},
    {"specs/groups.yaml", "text/plain", (const char*)specs_groups_yaml, specs_groups_yaml_len},
    {"specs/history.yaml", "text/plain", (const char*)specs_history_yaml, specs_history_yaml_len},
    {"specs/info.yaml", "text/plain", (const char*)specs_info_yaml, specs_info_yaml_len},
    {"specs/lists.yaml", "text/plain", (const char*)specs_lists_yaml, specs_lists_yaml_len},
    {"specs/logs.yaml", "text/plain", (const char*)specs_logs_yaml, specs_logs_yaml_len},
    {"specs/main.yaml", "text/plain", (const char*)specs_main_yaml, specs_main_yaml_len},
    {"specs/network.yaml", "text/plain", (const char*)specs_network_yaml, specs_network_yaml_len},
    {"specs/queries.yaml", "text/plain", (const char*)specs_queries_yaml, specs_queries_yaml_len},
    {"specs/search.yaml", "text/plain", (const char*)specs_search_yaml, specs_search_yaml_len},
    {"specs/stats.yaml", "text/plain", (const char*)specs_stats_yaml, specs_stats_yaml_len},
    {"specs/teleporter.yaml", "text/plain", (const char*)specs_teleporter_yaml, specs_teleporter_yaml_len},
    {"specs/action.yaml", "text/plain", (const char*)specs_action_yaml, specs_action_yaml_len},
    {"specs/padd.yaml", "text/plain", (const char*)specs_padd_yaml, specs_padd_yaml_len},
};

#endif // API_DOCS_H
