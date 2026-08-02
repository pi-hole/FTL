/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Cluster virtual IP address prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef CLUSTER_VIP_H
#define CLUSTER_VIP_H

#include "FTL.h"

// Is the virtual IP address currently configured on this machine?
bool vip_present(const char *address);

// Claim or release the virtual IP address. Claiming also tells the network
// the address moved, so switches and clients stop sending to the old holder
bool vip_claim(const char *address);
bool vip_release(const char *address);

// Did this process put the address there? Nothing else may be removed
bool vip_claimed(void) __attribute__ ((pure));

// ...and which address it was. False when nothing is held
bool vip_claimed_address(char *buf, const size_t size);

#endif // CLUSTER_VIP_H
