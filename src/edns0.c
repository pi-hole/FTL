/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  EDNS parsing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTLDNS
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"
#include "log.h"
#include "edns0.h"
#include "config.h"

#define LEN(header, pp, plen, len) \
    ((size_t)((pp) - (unsigned char *)(header) + (len)))

#define EDNS0_COOKIE 10

void FTL_parse_pseudoheaders(struct dns_header *header, size_t n, union mysockaddr *peer)
{
	int is_sign;
	size_t plen; 
	unsigned char *pheader, *sizep;

	// Extract additional record A.K.A. pseudoheader
	if (!(pheader = find_pseudoheader(header, n, &plen, &sizep, &is_sign, NULL)))
		return;

	// Debug logging
	if(config.debug & DEBUG_EDNS0)
		for(unsigned int i = 0; i < plen; i++)
			logg("EDNS0: pheader[%i] = 0x%02x", i, pheader[i]);

        // Working pointer
	unsigned char *p = pheader;

// RFC 6891                   EDNS(0) Extensions                   6.1.2.  Wire Format
// 
//    An OPT RR has a fixed part and a variable set of options expressed as
//    {attribute, value} pairs.  The fixed part holds some DNS metadata,
//    and also a small collection of basic extension elements that we
//    expect to be so popular that it would be a waste of wire space to
//    encode them as {attribute, value} pairs.
// 
//    The fixed part of an OPT RR is structured as follows:
// 
//        +------------+--------------+------------------------------+
//        | Field Name | Field Type   | Description                  |
//        +------------+--------------+------------------------------+
//        | NAME       | domain name  | MUST be 0 (root domain)      |
	if(*p++ != 0)
		return;
//        +------------+--------------+------------------------------+
//        | TYPE       | u_int16_t    | OPT (41)                     |
	unsigned short type;
	GETSHORT(type, p);
	if(type != 41)
		return;
//        +------------+--------------+------------------------------+
//        | CLASS      | u_int16_t    | requestor's UDP payload size |
	/* GETSHORT(class, p); */ p += 2;
//        +------------+--------------+------------------------------+
//        | TTL        | u_int32_t    | extended RCODE and flags     |
	unsigned long ttl;
	GETLONG(ttl, p);
//        +------------+--------------+------------------------------+
//        | RDLEN      | u_int16_t    | length of all RDATA          |
	unsigned short rdlen;
	GETSHORT(rdlen, p);
//        +------------+--------------+------------------------------+
//        | RDATA      | octet stream | {attribute,value} pairs      |
//        +------------+--------------+------------------------------+

//   The variable part of an OPT RR may contain zero or more options in
//   the RDATA.  Each option MUST be treated as a bit field.  Each option
//   is encoded as:
//
//                  +0 (MSB)                            +1 (LSB)
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    0: |                          OPTION-CODE                          |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    2: |                         OPTION-LENGTH                         |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    4: |                                                               |
//       /                          OPTION-DATA                          /
//       /                                                               /
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

// RFC 6891                   EDNS(0) Extensions                   6.1.3.  OPT Record TTL Field Use
//
//   The extended RCODE and flags, which OPT stores in the RR Time to Live
//   (TTL) field, are structured as follows:
//
//                  +0 (MSB)                            +1 (LSB)
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    0: |         EXTENDED-RCODE        |            VERSION            |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    2: | DO|                           Z                               |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//
//   EXTENDED-RCODE
//      Forms the upper 8 bits of extended 12-bit RCODE (together with the
//      4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0
//      indicates that an unextended RCODE is in use (values 0 through
//      15).
//
//   VERSION
//      Indicates the implementation level of the setter.  Full
//      conformance with this specification is indicated by version '0'.
//      Requestors are encouraged to set this to the lowest implemented
//      level capable of expressing a transaction, to minimise the
//      responder and network load of discovering the greatest common
//      implementation level between requestor and responder.  A
//      requestor's version numbering strategy MAY ideally be a run-time
//      configuration option.
//      If a responder does not implement the VERSION level of the
//      request, then it MUST respond with RCODE=BADVERS.  All responses
//      MUST be limited in format to the VERSION level of the request, but
//      the VERSION of each response SHOULD be the highest implementation
//      level of the responder.  In this way, a requestor will learn the
//      implementation level of a responder as a side effect of every
//      response, including error responses and including RCODE=BADVERS.
	unsigned char edns0_version = (ttl >> 16) % 0xFF;
	if(edns0_version != 0x00) return;	

	unsigned short optlen = 0;
	for (unsigned int i = 0; i + 4 < rdlen; i += 4 + optlen) // increment: two shorts (code, optlen) + payload
	{
		unsigned short code;
		GETSHORT(code, p);
		GETSHORT(optlen, p);
		// Debug logging
		if(config.debug & DEBUG_EDNS0)
			logg("EDNS0: code %u, optlen %u (i = %u)", code, optlen, i);
		if (code == 0x08)
		{
		// RFC 7871              Client Subnet in DNS Queries              6.  Option Format
		//   This protocol uses an EDNS0 [RFC6891] option to include client
		//   address information in DNS messages.  The option is structured as
		//   follows:
		//
		//                +0 (MSB)                            +1 (LSB)
		//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		//   0: |                          OPTION-CODE                          |
		//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		//   2: |                         OPTION-LENGTH                         |
		//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		//   4: |                            FAMILY                             |
		//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			short family;
			GETSHORT(family, p);
		//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		//   6: |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
		//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			unsigned char source_netmask = *p++;
			p++; // We are not interested in the scope prefix-length. It MUST be 0 in queries
		//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
		//   8: |                           ADDRESS...                          /
		//      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
			union all_addr addr = {{ 0 }};
			if(family == 1 && optlen > 4) // IPv4
				memcpy(&addr.addr4.s_addr, p, optlen - 4);
			else if(family == 2 && optlen > 4) // IPv6
				memcpy(addr.addr6.__in6_u.__u6_addr8, p, optlen - 4);
			else
				continue;

			// Advance working pointer
			p += optlen - 4;
			
			char ipaddr[ADDRSTRLEN] = { 0 };
			inet_ntop(family == 1 ? AF_INET : AF_INET6, &addr.addr4.s_addr, ipaddr, sizeof(ipaddr));
			logg("EDNS0: Identified option CLIENT SUBNET (%s/%i)", ipaddr, source_netmask);
		}
		else if(code == 0x0a)
		{
			logg("EDNS0: Identified option COOKIE");
			// Not implemented, skip this record
			p += optlen;
		}
		else if(code == 0xfde9)
		{
			logg("EDNS0: Identified option MAC ADDRESS");
			// Not implemented, skip this record
			p += optlen;
		}
		else
		{
			// Not implemented, skip this record
			p += optlen;
		}
	}
}