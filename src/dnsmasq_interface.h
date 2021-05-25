/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DNSMASQ_INTERFACE_H
#define DNSMASQ_INTERFACE_H

#include "hooks/blocking_metadata.h"
#include "hooks/cache.h"
#include "hooks/check_blocking.h"
#include "hooks/CNAME.h"
#include "hooks/detect_blocked_IP.h"
#include "hooks/dnsmasq_reload.h"
#include "hooks/dnssec.h"
#include "hooks/extract_question_flags.h"
#include "hooks/fork_and_bind.h"
#include "hooks/forwarded.h"
#include "hooks/forwarding_failed.h"
#include "hooks/iface.h"
#include "hooks/log.h"
#include "hooks/multiple_replies.h"
#include "hooks/header_analysis.h"
#include "hooks/new_query.h"
#include "hooks/print_flags.h"
#include "hooks/query_blocked.h"
#include "hooks/query_in_progress.h"
#include "hooks/received_reply.h"
#include "hooks/set_reply.h"
#include "hooks/tcp_workers.h"
#include "hooks/upstream_error.h"

#endif // DNSMASQ_INTERFACE_H
