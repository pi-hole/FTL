/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  DHCP discover prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef DHCP_DISCOVER_H
#define DHCP_DISCOVER_H

// pthread_lock
#include <pthread.h>

int run_dhcp_discover(void);
int get_hardware_address(const int sock, const char *iname, unsigned char *mac);

// Global lock used by all threads
extern pthread_mutex_t dhcp_lock;

inline void start_lock(void)
{
	pthread_mutex_lock(&dhcp_lock);
}

inline void end_lock(void)
{
	pthread_mutex_unlock(&dhcp_lock);
}

#endif // DHCP_DISCOVER_H
