/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  EDNS0 parsing prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef EDNS0_HEADER
#define EDNS0_HEADER

typedef struct {
	bool client_set :1;
	bool mac_set :1;
	bool valid :1;
	char client[ADDRSTRLEN];
	char mac_byte[6];
	char mac_text[18];
	int ede;
} ednsData;

ednsData *getEDNS(void);
void FTL_parse_pseudoheaders(unsigned char *pheader, const size_t plen);

#endif // EDNS0_HEADER
