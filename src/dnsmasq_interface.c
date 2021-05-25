/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTL_PRIVATE
#include "dnsmasq_interface.h"
#include "enums.h"
#include "datastructure.h"
#include "shmem.h"
#include "overTime.h"
#include "database/common.h"
#include "database/database-thread.h"
#include "database/gravity-db.h"
#include "setupVars.h"
#include "daemon.h"
#include "timers.h"
#include "gc.h"
#include "regex_r.h"
#include "config.h"
#include "capabilities.h"
#include "resolve.h"
#include "files.h"
#include "log.h"
// global variable daemonmode
#include "args.h"
// http_init()
#include "webserver/webserver.h"
// handle_realtime_signals()
#include "signals.h"
// Eventqueue routines
#include "events.h"
// query_to_database()
#include "database/query-table.h"


