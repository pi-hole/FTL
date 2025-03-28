/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  NTP prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef NTP_H
#define NTP_H

#include "FTL.h"
// TIMESTR_SIZE
#include "log.h"

// uint64_t
#include <stdint.h>
// bool
#include <stdbool.h>

// Get current time in NTP (64bit) format
uint64_t gettime64(void);

// Print NTP timestamp in human-readable form
void print_debug_time(const char *label, const uint32_t *u32p, const uint64_t ntp_time);

// Start NTP server
bool ntp_server_start(void);

// Start NTP client
bool ntp_client(const char *server, const bool settime, const bool print);

// Start NTP sync thread
bool ntp_start_sync_thread(pthread_attr_t *attr);

// Sync RTC time
bool ntp_sync_rtc(void);

// Number of NTP queries to average. The more queries, the more accurate the
// time, but the longer it takes to synchronize. The minimum is 1.
#define NTP_AVERGAGE_COUNT 8

// Delay between consecutive NTP queries in microseconds
#define NTP_DELAY 500000

// number of seconds between 1900 and 1970 (MSB=1)
#define DIFF_SEC_1900_1970         (2208988800UL)
// number of seconds between 1970 and Feb 7, 2036 (6:28:16 UTC) (MSB=0)
#define DIFF_SEC_1970_2036         (2085978496UL)

// Timestamp conversion macroni (RFC 5905, Appendix A)
#define FRIC       65536.                   // 2^16 as a double
#define D2FP(r)    ((uint32_t)((r) * FRIC)) // NTP short
#define FP2D(r)    ((double)(r) / FRIC)
#define FRAC       4294967296.               // 2^32 as double
#define D2LFP(a)   ((uint64_t)((a) * FRAC))  // NTP timestamp
#define LFP2D(a)   ((double)(a) / FRAC)
#define U2LFP(a)   (((uint64_t)((a).tv_sec + DIFF_SEC_1900_1970) << 32) + (uint64_t) ((a).tv_usec / 1e6 * FRAC))

// Convert NTP timestamp to seconds and microseconds
//#define NTPtoSEC(x) (((x & 0x80000000) != 0) ? ((x >> 32) - DIFF_SEC_1900_1970) : ((x >> 32) + DIFF_SEC_1970_2036))
#define NTPtoSEC(x) ((x >> 32) - DIFF_SEC_1900_1970)
#define NTPtoUSEC(x) (suseconds_t)((LFP2D(x & 0xFFFFFFFF) * 1e6))

// Convert uint64_t to network byte order and vice versa
#define hton64(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#define ntoh64(x) ((((uint64_t)ntohl(x)) << 32) + ntohl((x) >> 32))

extern uint64_t ntp_last_sync;
extern uint32_t ntp_root_delay;
extern uint32_t ntp_root_dispersion;
extern uint8_t ntp_stratum;

#endif // NTP_H



