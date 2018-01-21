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
	uint8_t eom = 0xc1;
	swrite(sock, &eom, sizeof(eom));
}

void pack_basic(int sock, uint8_t format, void *value, size_t size) {
	swrite(sock, &format, sizeof(format));
	swrite(sock, value, size);
}

uint64_t leToBe64(uint64_t value) {
	char *ptr = (char *) &value;
	uint32_t part1, part2;

	// Copy the two halves of the 64 bit input into uint32_t's so we can use htonl
	memcpy(&part1, ptr, 4);
	memcpy(&part2, ptr + 4, 4);

	// Flip each half around
	part1 = htonl(part1);
	part2 = htonl(part2);

	// Arrange them to form the big-endian version of the original input
	return (uint64_t) part1 << 32 | part2;
}

void pack_bool(int sock, bool value) {
	uint8_t packed = (uint8_t) (value ? 0xc3 : 0xc2);
	swrite(sock, &packed, sizeof(packed));
}

void pack_uint8(int sock, uint8_t value) {
	pack_basic(sock, 0xcc, &value, sizeof(value));
}

void pack_uint64(int sock, uint64_t value) {
	uint64_t bigEValue = leToBe64(value);
	pack_basic(sock, 0xcf, &bigEValue, sizeof(bigEValue));
}

void pack_int32(int sock, int32_t value) {
	uint32_t bigEValue = htonl((uint32_t) value);
	pack_basic(sock, 0xd2, &bigEValue, sizeof(bigEValue));
}

void pack_int64(int sock, int64_t value) {
	// Need to use memcpy to do a direct copy without reinterpreting the bytes (making negatives into positives).
	// It should get optimized away.
	uint64_t bigEValue;
	memcpy(&bigEValue, &value, sizeof(bigEValue));
	bigEValue = leToBe64(bigEValue);
	pack_basic(sock, 0xd3, &bigEValue, sizeof(bigEValue));
}

void pack_float(int sock, float value) {
	// Need to use memcpy to do a direct copy without reinterpreting the bytes. It should get optimized away.
	uint32_t bigEValue;
	memcpy(&bigEValue, &value, sizeof(bigEValue));
	bigEValue = htonl(bigEValue);
	pack_basic(sock, 0xca, &bigEValue, sizeof(bigEValue));
}

void pack_fixstr(int sock, char *string) {
	// Make sure that the length is less than 32
	size_t length = strlen(string);

	if(length >= 32) {
		logg("Tried to send a fixstr longer than 31 bytes!");
		exit(EXIT_FAILURE);
	}

	uint8_t format = (uint8_t) (0xA0 | length);
	swrite(sock, &format, sizeof(format));
	swrite(sock, string, length);
}

void pack_str32(int sock, char *string) {
	// Make sure that the length is less than 4294967296
	size_t length = strlen(string);

	if(length >= 2147483648) {
		logg("Tried to send a str32 longer than 2147483647 bytes!");
		exit(EXIT_FAILURE);
	}

	uint8_t format = 0xdb;
	swrite(sock, &format, sizeof(format));
	uint32_t bigELength = htonl((uint32_t) length);
	swrite(sock, &bigELength, sizeof(bigELength));
	swrite(sock, string, length);
}

void pack_map16_start(int sock, uint16_t length) {
	uint8_t format = 0xde;
	swrite(sock, &format, sizeof(format));
	uint16_t bigELength = htons(length);
	swrite(sock, &bigELength, sizeof(bigELength));
}
