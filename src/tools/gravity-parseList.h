/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Gravity parseList prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

int gravity_parseList(const char *infile, const char *outfile, const char *adlistID, const bool checkOnly, const bool antigravity);
bool __attribute__((pure)) valid_domain(const char *domain, const size_t len, const bool fqdn_only);
