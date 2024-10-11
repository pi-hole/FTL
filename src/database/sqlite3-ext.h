/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  SQLite3 database engine extension prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef SQLITE3_EXT_H
#define SQLITE3_EXT_H

// Initialization point for SQLite3 extensions
void pihole_sqlite3_initalize(void);

#endif // SQLITE3_EXT_H
