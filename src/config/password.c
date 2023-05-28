/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole password hashing
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "password.h"

// crypto library
#include <nettle/sha2.h>
#include <nettle/base64.h>
#include <nettle/version.h>

// Convert RAW data into hex representation
// Two hexadecimal digits are generated for each input byte.
void sha256_raw_to_hex(uint8_t *data, char *buffer)
{
	for (unsigned int i = 0; i < SHA256_DIGEST_SIZE; i++)
	{
		sprintf(buffer, "%02x", data[i]);
		buffer += 2;
	}
}

static char * __attribute__((malloc)) double_sha256_password(const char *password)
{
	char response[2 * SHA256_DIGEST_SIZE + 1] = { 0 };
	uint8_t raw_response[SHA256_DIGEST_SIZE];
	struct sha256_ctx ctx;

	// Hash password a first time
	sha256_init(&ctx);
	sha256_update(&ctx,
	              strlen(password),
	              (uint8_t*)password);

	sha256_digest(&ctx, SHA256_DIGEST_SIZE, raw_response);
	sha256_raw_to_hex(raw_response, response);

	// Hash password a second time
	sha256_init(&ctx);
	sha256_update(&ctx,
	              strlen(response),
	              (uint8_t*)response);

	sha256_digest(&ctx, SHA256_DIGEST_SIZE, raw_response);
	sha256_raw_to_hex(raw_response, response);

	return strdup(response);
}

char * __attribute__((malloc)) create_password(const char *password)
{
	return double_sha256_password(password);
}