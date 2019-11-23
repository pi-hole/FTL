/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API FTL prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef API_FTL_H
#define API_FTL_H

/* From RFC 3164 */
#define MAX_MESSAGE 1024

// How many messages do we keep in memory (FIFO message buffer)?
// The memory required is the set number in kilobytes
// Defaults to 32 [uses 32 KB of memory]
#define LOG_SIZE 32

void init_dnsmasq_fifo_log(void);
void free_dnsmasq_fifo_log(void);
void add_to_dnsmasq_log_fifo_buffer(const char *payload, const int length);

typedef struct {
	int next_id;
	time_t timestamp[LOG_SIZE];
	char message[LOG_SIZE][MAX_MESSAGE];
} fifologData;

extern fifologData *fifo_log;

#endif // API_FTL_H