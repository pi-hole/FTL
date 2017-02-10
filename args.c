/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Argument parsing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

bool debug = false;
void parse_args(int argc, char* argv[])
{
	int i;
	for(i=0; i < argc; i++) {
		if(strcmp(argv[i], "debug") == 0)
			debug = true;
		if(strcmp(argv[i], "test") == 0)
			killed = 1;
		// Other arguments are ignored
	}
}
