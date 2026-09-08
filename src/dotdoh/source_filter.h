/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Inbound DoT/DoH source-address filter
*
*  A self-contained (config-independent) decision of whether an inbound
*  encrypted-DNS connection may be served under a given listening mode, so the
*  security-critical predicate can be unit-tested directly. server.c wraps this
*  with the live dns.listeningMode.
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DOTDOH_SOURCE_FILTER_H
#define DOTDOH_SOURCE_FILTER_H

#include <stdbool.h>
// enum listening_mode
#include "enums.h"

// Whether an inbound DoT/DoH connection from a downstream client (client_ip: a
// numeric IPv4/IPv6 string, optional %zone id) may be served under mode `mode`.
//
// Only LISTEN_ALL serves every origin. Every other mode serves only clients one
// hop away - loopback, a directly-attached subnet, or a point-to-point peer -
// which is exactly LISTEN_LOCAL (dnsmasq's local-service). LISTEN_SINGLE /
// LISTEN_BIND / LISTEN_NONE restrict dnsmasq by *interface* (and otherwise
// permit all origins), but the encrypted-DNS servers bind all interfaces and
// cannot replicate that, so restricting by source to local clients is the safe
// equivalent - it never turns an on-by-default server into an open resolver.
// Fails closed (NULL/unparsable address or enumeration failure -> denied).
// `iface` is the configured dns.interface: for LISTEN_SINGLE / LISTEN_BIND the
// peer must additionally sit on that interface's subnet, so a multi-homed host
// does not serve every attached subnet. Pass NULL or "" (auto/none) to match any
// local interface.
bool dotdoh_source_allowed_mode(enum listening_mode mode, const char *client_ip,
                                const char *iface);

#endif // DOTDOH_SOURCE_FILTER_H
