
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTL_PRIVATE
#include "log.h"
// add_to_dnsmasq_log_buffer()
#include "fifo.h"

// Used to signal dnsmasq's log routine if it should print lines when logging to
// the pihole.log file
unsigned char debug_dnsmasq_lines = 0;

// Add dnsmasq log line to internal FIFO buffer (can be queried via the API)
void FTL_dnsmasq_log(const char *payload, const int length)
{
	add_to_dnsmasq_log_fifo_buffer(payload, length);
}