/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  MessagePack serialization
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api.h"

void pack_eom(int sock) {
	// This byte is explicitly never used in the MessagePack spec, so it is perfect to use as an EOM for this API.
	unsigned char eom = 0xc1;
	write(sock, &eom, sizeof(eom));
}

void pack_number(int sock, unsigned char format, void *value, size_t size) {
	write(sock, &format, sizeof(format));
	write(sock, value, size);
}

void pack_int(int sock, int value) {
	uint32_t bigEValue = htonl((uint32_t) value);
	pack_number(sock, 0xd2, &bigEValue, sizeof(bigEValue));
}

void pack_float(int sock, float value) {
	// Need to use memcpy to do a direct copy without reinterpreting the bytes. It should get optimized away.
	uint32_t bigEValue;
    memcpy(&bigEValue, &value, sizeof(bigEValue));
    bigEValue = htonl(bigEValue);
	pack_number(sock, 0xca, &bigEValue, sizeof(bigEValue));
}

void pack_unsigned_char(int sock, unsigned char value) {
	pack_number(sock, 0xcc, &value, sizeof(value));
}
