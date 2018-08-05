/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"

void get_privacy_level(FILE *fp)
{
	// See if we got a file handle
	bool opened = false;
	if(fp == NULL)
	{
		if((fp = fopen(FTLfiles.conf, "r")) == NULL)
			return;
		opened = true;
	}

	int value = config.privacylevel;
	char *buffer = parse_FTLconf(fp, "PRIVACYLEVEL");
	if(buffer != NULL && sscanf(buffer, "%i", &value))
		if(value > 0 && value <= 65535)
			config.port = value;

	if(opened)
		fclose(fp);
}
