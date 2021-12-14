/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq FIFO log prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef API_FTL_H
#define API_FTL_H

#include "FTL.h"

/* From RFC 3164 */
#define MAX_MSG_FIFO 1024u

// How many messages do we keep in memory (FIFO message buffer)?
// This number multiplied by MAX_MSG_FIFO (see above) gives the total buffer size
// Defaults to 128 [use 128 KB of memory for the log]
#define LOG_SIZE 128u

void add_to_dnsmasq_log_fifo_buffer(const char *payload, const size_t length);

typedef struct {
	unsigned int next_id;
	double timestamp[LOG_SIZE];
	char message[LOG_SIZE][MAX_MSG_FIFO];
} fifologData;

extern fifologData *fifo_log;

#endif // API_FTL_H