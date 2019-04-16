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

void pack_eom(const int sock) {
	// This byte is explicitly never used in the MessagePack spec, so it is perfect to use as an EOM for this API.
	uint8_t eom = 0xc1;
	swrite(sock, &eom, sizeof(eom));
}

static void pack_basic(const int sock, const uint8_t format, const void *value, const size_t size) {
	swrite(sock, &format, sizeof(format));
	swrite(sock, value, size);
}

static uint64_t __attribute__((const)) leToBe64(const uint64_t value) {
	const char *ptr = (char *) &value;
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

void pack_bool(const int sock, const bool value) {
	uint8_t packed = (uint8_t) (value ? 0xc3 : 0xc2);
	swrite(sock, &packed, sizeof(packed));
}

void pack_uint8(const int sock, const uint8_t value) {
	pack_basic(sock, 0xcc, &value, sizeof(value));
}

void pack_uint64(const int sock, const uint64_t value) {
	const uint64_t bigEValue = leToBe64(value);
	pack_basic(sock, 0xcf, &bigEValue, sizeof(bigEValue));
}

void pack_int32(const int sock, const int32_t value) {
	const uint32_t bigEValue = htonl((uint32_t) value);
	pack_basic(sock, 0xd2, &bigEValue, sizeof(bigEValue));
}

void pack_int64(const int sock, const int64_t value) {
	// Need to use memcpy to do a direct copy without reinterpreting the bytes (making negatives into positives).
	// It should get optimized away.
	uint64_t bigEValue;
	memcpy(&bigEValue, &value, sizeof(bigEValue));
	bigEValue = leToBe64(bigEValue);
	pack_basic(sock, 0xd3, &bigEValue, sizeof(bigEValue));
}

void pack_float(const int sock, const float value) {
	// Need to use memcpy to do a direct copy without reinterpreting the bytes. It should get optimized away.
	uint32_t bigEValue;
	memcpy(&bigEValue, &value, sizeof(bigEValue));
	bigEValue = htonl(bigEValue);
	pack_basic(sock, 0xca, &bigEValue, sizeof(bigEValue));
}

// Return true if successful
bool pack_fixstr(const int sock, const char *string) {
	// Make sure that the length is less than 32
	const size_t length = strlen(string);

	if(length >= 32) {
		logg("Tried to send a fixstr longer than 31 bytes!");
		return false;
	}

	const uint8_t format = (uint8_t) (0xA0 | length);
	swrite(sock, &format, sizeof(format));
	swrite(sock, string, length);

	return true;
}

// Return true if successful
bool pack_str32(const int sock, const char *string) {
	// Make sure that the length is less than 4294967296
	const size_t length = strlen(string);

	if(length >= 2147483648u) {
		logg("Tried to send a str32 longer than 2147483647 bytes!");
		return false;
	}

	const uint8_t format = 0xdb;
	swrite(sock, &format, sizeof(format));
	const uint32_t bigELength = htonl((uint32_t) length);
	swrite(sock, &bigELength, sizeof(bigELength));
	swrite(sock, string, length);

	return true;
}

void pack_map16_start(const int sock, const uint16_t length) {
	const uint8_t format = 0xde;
	swrite(sock, &format, sizeof(format));
	const uint16_t bigELength = htons(length);
	swrite(sock, &bigELength, sizeof(bigELength));
}
