/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Network table routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

bool create_network_table(void)
{
	bool ret;
	// Create FTL table in the database (holds properties like database version, etc.)
	ret = dbquery("CREATE TABLE network ( id        INTEGER PRIMARY KEY NOT NULL, \
	                                      ip        TEXT NOT NULL, \
	                                      mac       TEXT NOT NULL, \
	                                      name      TEXT, \
	                                      firstSeen INTEGER NOT NULL, \
	                                      lastSeen  INTEGER NOT NULL, \
	                                      PiholeDNS BOOLEAN NOT NULL );");
	if(!ret){ dbclose(); return false; }

	// Update database version to 3
	ret = db_set_FTL_property(DB_VERSION, 3);
	if(!ret){ dbclose(); return false; }

	return true;
}
