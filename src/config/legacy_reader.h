/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  FTL config file prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef LEGACY_READER_H
#define LEGACY_READER_H

bool getLogFilePathLegacy(FILE *fp);
const char *readFTLlegacy(void);

#endif //LEGACY_READER_H
