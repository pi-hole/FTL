/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Linux capabilities prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef CAPABILITIES_H
#define CAPABILITIES_H

#include <linux/capability.h>

bool check_capability(const unsigned int cap);
bool check_capabilities(void);

#endif //CAPABILITIES_H
