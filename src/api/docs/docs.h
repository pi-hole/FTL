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

#include "../../FTL.h"
#include "../../civetweb/civetweb.h"
#include "../../webserver/http-common.h"
#include "../../webserver/json_macros.h"
#include "../routes.h"

static const char index_html[] = {
#include "hex/index.html"
};

static const char index_css[] = {
#include "hex/index.css"
};

static const char pi_hole_js[] = {
#include "hex/pi-hole.js"
};

static const char rapidoc_min_js[] = {
#include "hex/external/rapidoc-min.js"
};

static const char rapidoc_min_map_js[] = {
#include "hex/external/rapidoc-min.js.map"
};

static const char highlight_default_min_css[] = {
#include "hex/external/highlight-default.min.css"
};

static const char geraintluff_sha256_min_js[] = {
#include "hex/external/geraintluff-sha256.min.js"
};

static const char highlight_min_js[] = {
#include "hex/external/highlight.min.js"
};

static const char images_logo_svg[] = {
#include "hex/images/logo.svg"
};

static const char specs_auth_yaml[] = {
#include "hex/specs/auth.yaml"
};

static const char specs_clients_yaml[] = {
#include "hex/specs/clients.yaml"
};

static const char specs_dns_yaml[] = {
#include "hex/specs/dns.yaml"
};

static const char specs_domains_yaml[] = {
#include "hex/specs/domains.yaml"
};

static const char specs_ftl_yaml[] = {
#include "hex/specs/ftl.yaml"
};

static const char specs_groups_yaml[] = {
#include "hex/specs/groups.yaml"
};

static const char specs_history_yaml[] = {
#include "hex/specs/history.yaml"
};

static const char specs_lists_yaml[] = {
#include "hex/specs/lists.yaml"
};

static const char specs_main_yaml[] = {
#include "hex/specs/main.yaml"
};

static const char specs_stats_yaml[] = {
#include "hex/specs/stats.yaml"
};

static const char specs_version_yaml[] = {
#include "hex/specs/version.yaml"
};
struct {
    const char *path;
    const char *mime_type;
    const char *content;
    const size_t content_size;
} docs_files[] =
{
    {"index.html", "text/html", index_html, sizeof(index_html)},
    {"index.css", "text/css", index_css, sizeof(index_css)},
    {"pi-hole.js", "application/javascript", pi_hole_js, sizeof(pi_hole_js)},
    {"external/rapidoc-min.js", "application/javascript", rapidoc_min_js, sizeof(rapidoc_min_js)},
    {"external/rapidoc-min.map.js", "text/plain", rapidoc_min_map_js, sizeof(rapidoc_min_map_js)},
    {"external/highlight-default.min.css", "text/css", highlight_default_min_css, sizeof(highlight_default_min_css)},
    {"external/highlight.min.js", "application/javascript", highlight_min_js, sizeof(highlight_min_js)},
    {"external/geraintluff-sha256.min.js", "application/javascript", geraintluff_sha256_min_js, sizeof(geraintluff_sha256_min_js)},
    {"images/logo.svg", "image/svg+xml", images_logo_svg, sizeof(images_logo_svg)},
    {"specs/auth.yaml", "text/plain", specs_auth_yaml, sizeof(specs_auth_yaml)},
    {"specs/clients.yaml", "text/plain", specs_clients_yaml, sizeof(specs_clients_yaml)},
    {"specs/dns.yaml", "text/plain", specs_dns_yaml, sizeof(specs_dns_yaml)},
    {"specs/domains.yaml", "text/plain", specs_domains_yaml, sizeof(specs_domains_yaml)},
    {"specs/ftl.yaml", "text/plain", specs_ftl_yaml, sizeof(specs_ftl_yaml)},
    {"specs/groups.yaml", "text/plain", specs_groups_yaml, sizeof(specs_groups_yaml)},
    {"specs/history.yaml", "text/plain", specs_history_yaml, sizeof(specs_history_yaml)},
    {"specs/lists.yaml", "text/plain", specs_lists_yaml, sizeof(specs_lists_yaml)},
    {"specs/main.yaml", "text/plain", specs_main_yaml, sizeof(specs_main_yaml)},
    {"specs/stats.yaml", "text/plain", specs_stats_yaml, sizeof(specs_stats_yaml)},
    {"specs/version.yaml", "text/plain", specs_version_yaml, sizeof(specs_version_yaml)},
};

#endif // API_DOCS_H