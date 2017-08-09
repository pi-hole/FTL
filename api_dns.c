/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API /dns/
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"

void getList(int *sock, char type, char list_type)
{
	FILE *fp;
	char *line = NULL;
	size_t size = 0;

	sendAPIResponse(*sock, type);
	ssend(*sock, "\"%s\":[", list_type == WHITELIST ? "whitelist" : "blacklist");

	if((fp = fopen(list_type == WHITELIST ? files.whitelist : files.blacklist, "r")) != NULL)
	{
		bool first = true;

		while(getline(&line, &size, fp) != -1) {
			// Skip empty lines
			if(line[0] == '\n')
				continue;

			if(!first) ssend(*sock, ",");
			first = false;

			// Trim off the newline, if it exists
			line[strcspn(line, "\r\n")] = 0;

			ssend(*sock, "\"%s\"", line);
		}
		// Free allocated memory
		if(line != NULL)
		{
			free(line);
			line = NULL;
		}

		fclose(fp);
	}

	ssend(*sock, "]");
}

void getPiholeStatus(int *sock, char type)
{
	int status = countlineswith("#addn-hosts=/etc/pihole/gravity.list", files.dnsmasqconf);
	sendAPIResponse(*sock, type);
	ssend(*sock, "\"status\":%i", status == 1 ? 0 : 1);
}

void addList(int *sock, char type, char list_type, char *data)
{
	sendAPIResponse(*sock, type);
	ssend(*sock, "\"status\": \"success\"");
}
