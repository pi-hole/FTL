/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API Implementation 2FA methods
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "api/api.h"
#include "webserver/json_macros.h"
#include "log.h"
#include "config/config.h"
// getrandom()
#include "daemon.h"
// generate_app_password()
#include "config/password.h"

// TOTP+HMAC
#include <nettle/hmac.h>
#include <nettle/sha1.h>

static uint32_t hotp(const uint8_t *key, size_t key_len, const uint64_t counter, const uint8_t digits)
{
	// Initialize HMAC-SHA1 (RFC 2104)
	// TOTP uses HMAC-SHA1 (RFC 6238, section 5.1)
	struct hmac_sha1_ctx ctx;
	hmac_sha1_set_key(&ctx, key_len, key);

	// Convert counter to big endian
	const uint64_t counter_be = htobe64(counter);

	// Compute HMAC-SHA1
	hmac_sha1_update(&ctx, sizeof(counter_be), (uint8_t*)&counter_be);
	uint8_t out[SHA1_DIGEST_SIZE];
	hmac_sha1_digest(&ctx, SHA1_DIGEST_SIZE, out);

	// Truncate HMAC-SHA1 for ease of use
	// RFC 6238 (section 5.3): offset = last nibble of hash
	const uint8_t offset = out[SHA1_DIGEST_SIZE-1] & 0x0F;
	// RFC 6238 (section 5.3): binary = (hash[offset] & 0x7F)   << 24 |
	//                                  (hash[offset+1] & 0xFF) << 16 |
	//                                  (hash[offset+2] & 0xFF) << 8 |
	//                                  (hash[offset+3] & 0xFF)
	const uint32_t binary = (out[offset] & 0x7F) << 24 |
	                        (out[offset+1] & 0xFF) << 16 |
	                        (out[offset+2] & 0xFF) << 8 |
	                        (out[offset+3] & 0xFF);
	// RFC 6238 (section 5.3): HOTP = binary mod 10^digits
	uint32_t mask = 10;
	for(unsigned int i = 1; i < digits; i++)
		mask *= 10;
	return binary % mask;
}

// RFC 6238 (section 4.1): T0 is the Unix time to start counting time steps
// (default value is 0, i.e., the Unix epoch) and is also a system parameter.
#define RFC6238_T0 0
// RFC 6238 (section 5.2): We RECOMMEND a default time-step size of 30 seconds.
// This default value of 30 seconds is selected as a balance between security
// and usability.
#define RFC6238_X 30
// RFC 6238 (section 4, R6): The algorithm MUST use a strong shared secret. The
// length of the shared secret MUST be at least 128 bits (16 Byte). This
// document RECOMMENDs a shared secret length of 160 bits (20 Byte).
#define RFC6238_SECRET_LEN 160/8
// The number of digits to truncate to is not specified in RFC 6238. RFC 4226
// (section 5.3) specifies that the default is 6 (up to 8) digits, however, the
// example given in RFC 6238 uses 8 digits.
#define RFC6238_DIGITS 6

static uint32_t totp(const uint8_t *key, const size_t key_len, const time_t now)
{
	// Get time
	// RFC 6238 (section 4.2): T = (Current Unix time - T0) / X
	// T is an integer and represents the number of time steps between the
	// initial time T0 and the current time. T needs to be big endian
	const uint64_t T = (now - RFC6238_T0) / RFC6238_X;

	// RFC 6238 (section 4.2): TOTP(K, T) = HOTP(K,C) with C = T
	return hotp(key, key_len, T, RFC6238_DIGITS);
}

static bool decode_base32_to_uint8_array(const char *base32, uint8_t *out, const size_t out_len)
{
	// Base32 alphabet
	const char *b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	// Check input for validity
	if(out_len == 0 || out_len*8/5 < strlen(base32) || out_len*8%5 != 0)
	{
		log_err("Decoding base32 2FA secret failed, invalid length (%zu)", out_len);
		return false;
	}

	// Initialize output array
	memset(out, 0, out_len);

	// Iterate over input string
	size_t out_pos = 0u;
	for(size_t i = 0; i < strlen(base32); i++)
	{
		// Get current character
		const char c = base32[i];

		// Get position of current character in base32 alphabet
		const char *c_pos = strchr(b32, toupper(c));
		if(c_pos == NULL)
		{
			log_err("Decoding base32 2FA secret failed, invalid character '%c'", c);
			return false;
		}

		// Get value of current character
		const uint8_t c_val = (uint8_t)(c_pos-b32);

		// Iterate over 5 bits of the current character
		for(unsigned int j = 0; j < 5; j++)
		{
			// Current bit position
			const unsigned int bit = 4-j;

			// Get current bit in the current character
			const uint8_t c_bit = (c_val >> bit) & 1;

			// Get current byte position in the output array
			out_pos = (i*5+j)/8;

			// If we are out of bounds, return false
			if(out_pos >= out_len)
			{
				log_err("Decoding base32 2FA secret failed, out of bounds (%zu >= %zu)", out_pos, out_len);
				return false;
			}

			// Set current bit in the output array
			out[out_pos] |= c_bit << (7-((i*5+j)%8));
		}
	}

	return true;
}

static bool encode_uint8_t_array_to_base32(const uint8_t *in, const size_t in_len, char *base32, size_t base32_len)
{
	// Base32 alphabet
	const char *b32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

	// Check input for validity
	if(in_len == 0 || in_len > base32_len*5/8 || in_len%5 != 0)
	{
		log_err("Encoding base32 2FA secret failed, invalid input length");
		return false;
	}

	// Initialize base32 output array
	memset(base32, 0, base32_len);

	// Iterate over input string
	size_t base32_pos = 0u;
	for(size_t i = 0; i < in_len; i++)
	{
		// Get current byte
		const uint8_t b = in[i];

		// Iterate over 8 bits of the current byte
		for(unsigned int j = 0; j < 8; j++)
		{
			// Current bit position
			const unsigned int bit = 7-j;

			// Get current bit in the current byte
			const uint8_t b_bit = (b >> bit) & 1;

			// Get current byte position in the base32 output array
			base32_pos = (i*8+j)/5;

			// If we are out of bounds, return false
			if(base32_pos >= base32_len)
			{
				log_err("Decoding base32 2FA secret failed, base32 output array is too small");
				return false;
			}

			// Set current bit in the base32 output array
			base32[base32_pos] |= b_bit << (4-((i*8+j)%5));
		}
	}

	// Iterate over base32 output array and replace each byte with its
	// corresponding character in the base32 alphabet
	for(size_t i = 0; i <= base32_pos; i++)
		base32[i] = b32[(uint8_t)base32[i]];

	return true;
}

static uint32_t last_code = 0;
enum totp_status verifyTOTP(const uint32_t incode)
{
	// Decode base32 secret
	uint8_t decoded_secret[RFC6238_SECRET_LEN];
	if(!decode_base32_to_uint8_array(config.webserver.api.totp_secret.v.s, decoded_secret, sizeof(decoded_secret)))
		return false;

	// Get current time
	const time_t now = time(NULL);

	// Verify code for the previous, the current and the next time step
	for(int i = -1; i <= 1; i++)
	{
		const uint32_t gencode = totp(decoded_secret, sizeof(decoded_secret), now + i*RFC6238_X);

		// Verify code
		// RFC 6238 (section 4.2): If the calculated value matches the value
		// provided by the user, then the user is authenticated
		// RFC 6238 (section 4.3): The server MUST NOT accept a TOTP value
		// generated more than 30 seconds in the future
		// RFC 6238 (section 4.3): The server MUST NOT accept a TOTP value
		// generated more than 30 seconds in the past
		// RFC 6238 (section 4.3): The server MUST NOT accept a TOTP value
		// it accepted previously
		if(gencode == incode)
		{
			if(gencode == last_code)
			{
				log_warn("2FA code has already been used (%i, %u), please wait %lu seconds",
				         i, gencode, (unsigned long)(RFC6238_X - (now % RFC6238_X)));
				return TOTP_REUSED;
			}
			const char *which = i == -1 ? "previous" : i == 0 ? "current" : "next";
			log_debug(DEBUG_API, "2FA code from %s time step is valid", which);
			last_code = gencode;
			return TOTP_CORRECT;
		}
	}

	return TOTP_INVALID;
}

// Print TOTP code to stdout (for CLI use)
int printTOTP(void)
{
	if(strlen(config.webserver.api.totp_secret.v.s) == 0)
	{
		puts("0");
		return EXIT_SUCCESS;
	}
	// Decode base32 secret
	uint8_t decoded_secret[RFC6238_SECRET_LEN];
	if(!decode_base32_to_uint8_array(config.webserver.api.totp_secret.v.s, decoded_secret, sizeof(decoded_secret)))
		return EXIT_FAILURE;

	// Get current time
	const time_t now = time(NULL);
	const uint32_t code = totp(decoded_secret, sizeof(decoded_secret), now);

	printf("%u\n", code);

	return EXIT_SUCCESS;
}


// A QR code may be generated from the data using
// otpauth://totp/<label>?secret=<secret>&issuer=<issuer>&algorithm=<algorithm>&digits=<digits>&period=<period>
int generateTOTP(struct ftl_conn *api)
{
	// Generate random secret using the system's random number generator
	uint8_t random_secret[RFC6238_SECRET_LEN];
	if(getrandom(random_secret, sizeof(random_secret), 0) < (ssize_t)sizeof(random_secret))
	{
		return send_json_error(api, 500, "internal_error", "Failed to generate random secret", strerror(errno));
	}

	// Encode base32 secret
	const size_t base32_len = sizeof(random_secret)*8/5+1;
	char *base32 = calloc(base32_len, sizeof(char));
	if(!encode_uint8_t_array_to_base32(random_secret, sizeof(random_secret), base32, base32_len))
		return send_json_error(api, 500, "internal_error", "Failed to encode secret", "Check FTL.log for details");

	// Create JSON object
	cJSON *tjson = cJSON_CreateObject();
	JSON_REF_STR_IN_OBJECT(tjson, "type", "totp");
	JSON_REF_STR_IN_OBJECT(tjson, "account", config.webserver.domain.v.s);
	JSON_REF_STR_IN_OBJECT(tjson, "issuer", "Pi-hole%20API");
	JSON_REF_STR_IN_OBJECT(tjson, "algorithm", "SHA1");
	JSON_ADD_NUMBER_TO_OBJECT(tjson, "digits", RFC6238_DIGITS);
	JSON_ADD_NUMBER_TO_OBJECT(tjson, "period", RFC6238_X);
	JSON_ADD_NUMBER_TO_OBJECT(tjson, "offset", RFC6238_T0);
	JSON_COPY_STR_TO_OBJECT(tjson, "secret", base32);
	free(base32);
	base32 = NULL;

	// Generate a few codes to show the user how to use the secret
	cJSON *codes = cJSON_CreateArray();
	for(int i = 0; i < 5; i++)
	{
		const time_t now = time(NULL) + (i-1)*RFC6238_X;
		const uint32_t code = totp(random_secret, sizeof(random_secret), now);
		JSON_ADD_NUMBER_TO_ARRAY(codes, code);
	}
	JSON_ADD_ITEM_TO_OBJECT(tjson, "codes", codes);

	// Send JSON response
	cJSON *json = cJSON_CreateObject();
	JSON_ADD_ITEM_TO_OBJECT(json, "totp", tjson);
	JSON_SEND_OBJECT(json);
}

int generateAppPw(struct ftl_conn *api)
{
	// Generate and set app password
	char *password = NULL, *pwhash = NULL;
	if(!generate_app_password(&password, &pwhash))
	{
		return send_json_error(api,
		                       500,
		                       "internal_error",
		                       "Failed to generate app password",
		                       "Check FTL.log for details");
	}

	// Create JSON object
	cJSON *tjson = cJSON_CreateObject();
	JSON_COPY_STR_TO_OBJECT(tjson, "password", password);
	JSON_COPY_STR_TO_OBJECT(tjson, "hash", pwhash);
	free(password);
	password = NULL;
	free(pwhash);
	pwhash = NULL;

	// Send JSON response
	cJSON *json = cJSON_CreateObject();
	JSON_ADD_ITEM_TO_OBJECT(json, "app", tjson);
	JSON_SEND_OBJECT(json);
}

#if 0
#define RFC6238_TESTKEY "12345678901234567890"
#define RFC6238_TESTTIME 59
#define RFC6238_TESTTOTP 94287082

int test_totp(struct ftl_conn *api)
{
	// Generate base32 secret
	uint8_t secret[sizeof(RFC6238_TESTKEY)-1];
	for(size_t i = 0; i < sizeof(secret); i++)
		secret[i] = RFC6238_TESTKEY[i];

	// Encode base32 secret
	char base32_secret[sizeof(secret)*8/5+1];
	if(!encode_uint8_t_array_to_base32(secret, sizeof(secret), base32_secret, sizeof(base32_secret)))
		return false;

	// Decode base32 secret
	uint8_t decoded_secret[sizeof(RFC6238_TESTKEY)-1];
	if(!decode_base32_to_uint8_array(base32_secret, decoded_secret, sizeof(decoded_secret)))
		return false;

	// Get test time
	const time_t now = RFC6238_TESTTIME;

	// Verify code for the current time and the previous and next time step
	for(int i = -1; i <= 1; i++)
	{
		// Verify code
		const time_t t = now + i*RFC6238_X;
		if(totp(decoded_secret, sizeof(decoded_secret), t) == RFC6238_TESTTOTP)
			log_info("Code is valid for time %ld", t);
	}

	return 200;
}
#endif
