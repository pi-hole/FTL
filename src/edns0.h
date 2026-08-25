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

// Pi-hole-private EDNS0 option used by the inbound DoT/DoH server to carry the
// real downstream client of an encrypted query. Only trusted when the query
// source is loopback (our own server). Uses a code from the Local/Experimental
// range (RFC 6891) that dnsmasq does not already use for another option: avoid
// 65001 (EDNS0_OPTION_MAC), 65073/65074 (Nominum), 20292 (Umbrella).
#define EDNS0_OPTION_PIHOLE_CLIENT 65432
// Companion option carrying the kernel interface index of the local address the
// downstream client connected to (the DoT/DoH listener socket). Lets pi.hole/
// <hostname> answers over encrypted DNS use the very same interface-driven
// policy as plain DNS instead of the loopback address of our internal forward.
// Same loopback+MAC trust as the client option.
#define EDNS0_OPTION_PIHOLE_DEST 65431

typedef struct {
	bool client_set :1;
	bool mac_set :1;
	bool valid :1;
	bool private_client_set :1; // real client from EDNS0_OPTION_PIHOLE_CLIENT
	bool private_dest_set :1;   // interface index from EDNS0_OPTION_PIHOLE_DEST
	char client[ADDRSTRLEN];
	// Deliberately separate from client[] (which the ECS parser writes): an
	// external client could otherwise inject this option to overwrite the ECS
	// client and bypass the ECS anti-loopback guard.
	char private_client[ADDRSTRLEN];
	int private_dest_if; // kernel ifindex of the connected-to interface
	char mac_byte[6];
	char mac_text[18];
	int ede;
} ednsData;

ednsData *getEDNS(void);
void FTL_parse_pseudoheaders(const unsigned char *msg, const size_t msglen,
                             unsigned char *pheader, const size_t plen);

#endif // EDNS0_HEADER
