/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DNSMASQ_INTERFACE_H
#define DNSMASQ_INTERFACE_H

// Include only files that need to be visible to the dnsmasq source code
#include "hooks/CNAME.h"
#include "hooks/dnsmasq_reload.h"
#include "hooks/fork_and_bind.h"
#include "hooks/forwarding_retried.h"
#include "hooks/hook.h"
#include "hooks/iface.h"
#include "hooks/log.h"
#include "hooks/make_answer.h"
#include "hooks/multiple_replies.h"
#include "hooks/header_analysis.h"
#include "hooks/new_query.h"
#include "hooks/query_in_progress.h"
#include "hooks/tcp_workers.h"

#endif // DNSMASQ_INTERFACE_H
