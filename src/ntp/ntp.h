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

// uint64_t
#include <stdint.h>
// bool
#include <stdbool.h>

//uint64_t gettime32(void);
void gettime32(uint32_t ts[], const bool netorder);
//uint64_t gettime64(void);

bool ntp_server_start(void);
bool ntp_client(const char *server);

#endif // NTP_H



