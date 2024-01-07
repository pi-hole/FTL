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
#include "log.h"
#include "config/config.h"
#include "password.h"
// genrandom() with fallback
#include "daemon.h"
// sleepms()
#include "timers.h"

// Randomness generator
#include "webserver/x509.h"

// writeFTLtoml()
#include "config/toml_writer.h"

// crypto library
#include <nettle/sha2.h>
#include <nettle/base64.h>
#include <nettle/version.h>
#include <nettle/balloon.h>

// Salt length for balloon hashing
// The purpose of including salts is to modify the function used to hash each
// user's password so that each stored password hash will have to be attacked
// individually. The only security requirement is that they are unique per user,
// there is no benefit in them being unpredictable or difficult to guess.
//
// As a prime example, Linux uses 64 bits in the shadow password system. In
// 2023, using 128 bits should be sufficient for the foreseeable future.
#define SALT_LEN 16 // 16 bytes = 128 bits

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

static char * __attribute__((malloc)) base64_encode(const uint8_t *data, const size_t length)
{
	// Base64 encoding requires 4 bytes for every 3 bytes of input, plus
	// additional bytes for padding. The output buffer must be large enough
	// to hold the encoded data.
	char *encoded = calloc(BASE64_ENCODE_LENGTH(length) + BASE64_ENCODE_FINAL_LENGTH, sizeof(char));

	// Encode the data
	size_t out_len;
	struct base64_encode_ctx ctx;
	base64_encode_init(&ctx);
	out_len = base64_encode_update(&ctx, encoded, length, data);
	out_len += base64_encode_final(&ctx, encoded + out_len);

	// Length check
	if(out_len > BASE64_ENCODE_LENGTH(length) + BASE64_ENCODE_FINAL_LENGTH)
		log_warn("Base64 encoding may have failed: Output buffer too small? (%zu > %zu)",
		         out_len, BASE64_ENCODE_LENGTH(length) + BASE64_ENCODE_FINAL_LENGTH);

	return encoded;
}

static uint8_t * __attribute__((malloc)) base64_decode(const char *data, size_t *length)
{
	// Base64 decoding requires 3 bytes for every 4 bytes of input, plus
	// additional bytes for padding. The output buffer must be large enough
	// to hold the decoded data.
	uint8_t *decoded = calloc(BASE64_DECODE_LENGTH(strlen(data)), sizeof(uint8_t));

	// Decode the data
	struct base64_decode_ctx ctx;
	base64_decode_init(&ctx);
	base64_decode_update(&ctx, length, decoded, strlen(data), data);
	base64_decode_final(&ctx);

	return decoded;
}

// Balloon hashing is a key derivation function presenting proven memory-hard
// password-hashing and modern design. It was created by Dan Boneh, Henry
// Corrigan-Gibbs (both at Stanford University) and Stuart Schechter (Microsoft
// Research) in 2016. It is a recommended function in NIST password
// guidelines. (see https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver)
// (introduction taken from https://en.wikipedia.org/wiki/Balloon_hashing)
//
// If phc_string is true, the output will be formatted as a PHC string
// Otherwise, the output will be the raw password hash
static char * __attribute__((malloc)) balloon_password(const char *password,
                                                       const uint8_t salt[SALT_LEN],
                                                       const bool phc_string)
{
	// Parameter check
	if(password == NULL || salt == NULL)
		return NULL;

	struct timespec start, end;
	// Record starting time
	if(config.debug.api.v.b)
		clock_gettime(CLOCK_MONOTONIC, &start);

	// The space parameter s_cost determines how many blocks of working
	// space the algorithm will require during its computation.  It is
	// common to set s_cost to a high value in order to increase the cost of
	// hardware accelerators built by the adversary.
	// The algorithm will need (s_cost + 1) * digest_size
	//    -> 32KB for s_cost = 1024 and algo = SHA256
	const size_t s_cost = 1024;

	// The time parameter t_cost determines the number of rounds of
	// computation that the algorithm will perform. This can be used to
	// further increase the cost of computation without raising the memory
	// requirement.
	const size_t t_cost = 32;

	// Scratch buffer scratch is a user allocated working space required by
	// the algorithm.  To determine the required size of the scratch buffer
	// use the utility function balloon_itch.  Output of BALLOON algorithm
	// will be written into the output buffer dst that has to be at least
	// digest_size bytes long.
	uint8_t *scratch = calloc(balloon_itch(SHA256_DIGEST_SIZE, s_cost), sizeof(uint8_t));

	// Compute hash of given password password salted with salt and write
	// the result into the output buffer dst
	balloon_sha256(s_cost, t_cost,
	               strlen(password), (const uint8_t *)password,
	               SALT_LEN, salt, scratch, scratch);

	if(config.debug.api.v.b)
	{
		// Record ending time
		clock_gettime(CLOCK_MONOTONIC, &end);

		// Compute elapsed time
		double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
		log_debug(DEBUG_API, "Balloon hashing took %.1f milliseconds", 1e3*elapsed);
	}

	if(!phc_string)
	{
		// Return raw hash
		return (char*)scratch;
	}

	char *salt_base64 = base64_encode(salt, SALT_LEN);
	char *scratch_base64 = base64_encode(scratch, SHA256_DIGEST_SIZE);

	// Build PHC string-like output (output string is 101 bytes long (measured))
	char *output = calloc(128, sizeof(char));
	int size = snprintf(output, 128, "$BALLOON-SHA256$v=1$s=%zu,t=%zu$%s$%s",
	                    s_cost,
	                    t_cost,
	                    salt_base64,
	                    scratch_base64);

	if(size < 0)
	{
		// Error
		log_err("Error while generating PHC string: %s", strerror(errno));
		goto clean_and_exit;
	}

clean_and_exit:
	free(scratch);
	free(salt_base64);
	free(scratch_base64);

	return output;
}

// Parse a PHC string and return the parameters and hash
// Returns true on success, false on error
static bool parse_PHC_string(const char *phc, size_t *s_cost, size_t *t_cost, uint8_t **salt, uint8_t **hash)
{
	int version = 0;
	char algorithm[64] = { 0 };
	char salt_base64[64] = { 0 };
	char hash_base64[64] = { 0 };

	// Parse PHC string
	int size = sscanf(phc, "$%63[^$]$v=%d$s=%zu,t=%zu$%63[^$]$%63[^$]$",
	                  algorithm,
	                  &version,
	                  s_cost,
	                  t_cost,
	                  salt_base64,
	                  hash_base64);

	// Add null-terminators
	algorithm[sizeof(algorithm) - 1] = '\0';
	salt_base64[sizeof(salt_base64) - 1] = '\0';
	hash_base64[sizeof(hash_base64) - 1] = '\0';

	// Debug output
	log_debug(DEBUG_API, "Parsed PHC string: '%s'", phc);
	log_debug(DEBUG_API, "   -> Algorithm: '%s'", algorithm);
	log_debug(DEBUG_API, "   -> Version: %d", version);
	log_debug(DEBUG_API, "   -> s_cost: %zu", *s_cost);
	log_debug(DEBUG_API, "   -> t_cost: %zu", *t_cost);
	log_debug(DEBUG_API, "   -> Salt: '%s'", salt_base64);
	log_debug(DEBUG_API, "   -> Hash: '%s'", hash_base64);

	// Check parsing result
	if(size != 6)
	{
		// Error
		log_err("Error while parsing PHC string: Found %d instead of 6 elements in definition", size);
		return false;
	}

	// Check PHC string version and algorithm
	if(version != 1)
	{
		// Error
		log_err("Unsupported PHC string version: %d", version);
		return false;
	}

	if(strcmp(algorithm, "BALLOON-SHA256") != 0)
	{
		// Error
		log_err("Unsupported PHC string algorithm: %s", algorithm);
		return false;
	}

	// Decode salt and hash
	size_t salt_len = 0;
	*salt = base64_decode(salt_base64, &salt_len);
	if(*salt == NULL)
	{
		// Error
		log_err("Error while decoding salt: %s", strerror(errno));
		return false;
	}
	if(salt_len != SALT_LEN)
	{
		// Error
		log_err("Invalid decoded salt length: %zu, should be %d",
		        salt_len, SALT_LEN);
		return false;
	}

	size_t hash_len = 0;
	*hash = base64_decode(hash_base64, &hash_len);
	if(*hash == NULL)
	{
		// Error
		log_err("Error while decoding hash: %s", strerror(errno));
		return false;
	}
	if(hash_len != SHA256_DIGEST_SIZE)
	{
		// Error
		log_err("Invalid decoded hash length: %zu, should be %d",
		        hash_len, SHA256_DIGEST_SIZE);
		return false;
	}

	return true;
}

char * __attribute__((malloc)) create_password(const char *password)
{
	// Generate a 128 bit random salt
	// genrandom() returns cryptographically secure random data
	uint8_t salt[SALT_LEN] = { 0 };
	if(getrandom(salt, sizeof(salt), 0) < 0)
	{
		log_err("getrandom() failed in create_password()");
		return NULL;
	}

	// Generate balloon PHC-encoded password hash
	return balloon_password(password, salt, true);
}

enum password_result verify_login(const char *password)
{
	enum password_result pw = verify_password(password, config.webserver.api.pwhash.v.s, true);
	if(pw == PASSWORD_CORRECT)
		log_debug(DEBUG_API, "Password correct");
	else
		log_debug(DEBUG_API, "Password incorrect");

	// Check if an application password is set and if it matches
	if(pw == PASSWORD_INCORRECT &&
	   strlen(config.webserver.api.app_pwhash.v.s) > 0 &&
	   verify_password(password, config.webserver.api.app_pwhash.v.s, true) == PASSWORD_CORRECT)
	{
		log_debug(DEBUG_API, "App password correct");
		return APPPASSWORD_CORRECT;
	}

	// Return result
	return pw;
}

enum password_result verify_password(const char *password, const char *pwhash, const bool rate_limiting)
{
	// No password set
	if(pwhash == NULL || pwhash[0] == '\0')
		return NO_PASSWORD_SET;

	// No password supplied
	if(password == NULL || password[0] == '\0')
		return PASSWORD_INCORRECT;

	// Check if there has already been one login attempt within this second
	static time_t last_password_attempt = 0;
	static unsigned int num_password_attempts = 0;
	if(rate_limiting &&
	   last_password_attempt > 0 &&
	   last_password_attempt == time(NULL))
	{
		// Check if we have reached the maximum number of attempts
		if(++num_password_attempts > MAX_PASSWORD_ATTEMPTS_PER_SECOND)
		{
			// Rate limit reached
			sleepms(250);
			return PASSWORD_RATE_LIMITED;
		}
	}
	else
	{
		// Reset counter
		num_password_attempts = 1;
		last_password_attempt = time(NULL);
	}

	// Check password hash format
	if(pwhash[0] == '$')
	{
		// Parse PHC string
		size_t s_cost = 0;
		size_t t_cost = 0;
		uint8_t *salt = NULL;
		uint8_t *config_hash = NULL;
		if(!parse_PHC_string(pwhash, &s_cost, &t_cost, &salt, &config_hash))
			return PASSWORD_INCORRECT;
		if(salt == NULL || config_hash == NULL)
			return PASSWORD_INCORRECT;
		char *supplied = balloon_password(password, salt, false);
		const bool result = memcmp(config_hash, supplied, SHA256_DIGEST_SIZE) == 0;

		// Free allocated memory
		free(supplied);
		free(salt);
		free(config_hash);

		// Successful logins do not count against rate-limiting
		if(result)
			num_password_attempts--;

		return result ? PASSWORD_CORRECT : PASSWORD_INCORRECT;
	}
	else
	{
		// Legacy password
		char *supplied = double_sha256_password(password);
		const bool result = strcmp(pwhash, supplied) == 0;
		free(supplied);

		// Upgrade double-hashed password to BALLOON hash
		if(result)
		{
			char *new_hash = create_password(password);
			if(new_hash != NULL)
			{
				log_info("Upgrading password from SHA256^2 to BALLOON-SHA256");
				if(config.webserver.api.pwhash.t == CONF_STRING_ALLOCATED)
					free(config.webserver.api.pwhash.v.s);
				config.webserver.api.pwhash.v.s = new_hash;
				config.webserver.api.pwhash.t = CONF_STRING_ALLOCATED;
				writeFTLtoml(true);
				free(new_hash);
			}

			// Successful logins do not count against rate-limiting
			num_password_attempts--;
		}

		return result ? PASSWORD_CORRECT : PASSWORD_INCORRECT;
	}
}

static double sqroot(double square)
{
	double root = square / 3.0;
	if (square <= 0) return 0.0;
	for (unsigned int i=0; i<32; i++)
		root = (root + square / root) / 2;
	return root;
}

static int performance_test_task(const size_t s_cost, const size_t t_cost, const uint8_t password[],
                                 const size_t pwlen, uint8_t salt[SALT_LEN],
                                 double *elapsed1, double *elapsed2)
{
		struct timespec start, end, end2;
		// Scratch buffer scratch is a user allocated working space required by
		// the algorithm.  To determine the required size of the scratch buffer
		// use the utility function balloon_itch.  Output of BALLOON algorithm
		// will be written into the output buffer dst that has to be at least
		// digest_size bytes long.
		const size_t scratch_size = balloon_itch(SHA256_DIGEST_SIZE, s_cost);
		uint8_t *scratch = calloc(scratch_size, sizeof(uint8_t));
		if(scratch == NULL)
		{
			printf("Could not allocate %zu bytes of memory for test!\n", scratch_size);
			return -1;
		}

		// Record starting time
		clock_gettime(CLOCK_MONOTONIC, &start);

		// Compute hash of given password password salted with salt and write
		// the result into the output buffer dst
		balloon_sha256(s_cost, t_cost, pwlen, password, SALT_LEN, salt, scratch, scratch);

		// Record end time
		clock_gettime(CLOCK_MONOTONIC, &end);

		// Compute hash of given password password salted with salt and write
		// the result into the output buffer dst
		balloon_sha256(s_cost, t_cost, pwlen, password, SALT_LEN, salt, scratch, scratch);

		// Record end time
		clock_gettime(CLOCK_MONOTONIC, &end2);

		// Free allocated memory
		free(scratch);

		// Compute elapsed time
		*elapsed1 = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
		*elapsed2 = (end2.tv_sec - end.tv_sec) + (end2.tv_nsec - end.tv_nsec) / 1000000000.0;
		char prefix[2] = { 0 };
		double formatted = 0.0;
		format_memory_size(prefix, (unsigned long long)scratch_size, &formatted);
		const double avg = (*elapsed1 + *elapsed2)/2;
		const double stdev = sqroot(((*elapsed1 - avg)*(*elapsed1 - avg) + (*elapsed2 - avg)*(*elapsed2 - avg))/2);
		printf("s = %5zu, t = %5zu took %6.1f +/- %4.1f ms (scratch buffer %6.1f%1sB) -> %.0f\n",
		       s_cost, t_cost, 1e3*avg, 1e3*stdev, formatted, prefix, 1.0*(s_cost*t_cost)/avg);

		// Break if test took longer than half a second
		if(avg > 0.5)
			return 1;
		return 0;
}

// Run performance tests until individual test result gets beyond 3 seconds
int run_performance_test(void)
{
	struct timespec start, end;
	// Record starting time
	clock_gettime(CLOCK_MONOTONIC, &start);

	// Test password
	const uint8_t password[] = "abcdefghijklmnopqrstuvwxyz0123456789!\"§$%&/()=?";

	// Generate a 128 bit random salt
	// genrandom() returns cryptographically secure random data
	uint8_t salt[SALT_LEN] = { 0 };
	if(getrandom(salt, sizeof(salt), 0) < 0)
	{
		printf("Could not generate random salt!\n");
		return EXIT_FAILURE;
	}

	printf("Running time-performance test:\n");
	size_t t_t_cost = 16;
	const size_t t_s_cost = 512;
	cJSON *time_test = cJSON_CreateArray();
	unsigned int i = 0;
	while(true)
	{
		double elapsed1 = 0.0, elapsed2 = 0.0;
		const int ret = performance_test_task(t_s_cost, t_t_cost, password, sizeof(password), salt,
		                                      &elapsed1, &elapsed2);

		if(ret == -1)
			return EXIT_FAILURE;

		if(i > 0)
		{
			// We do not want to include the first test in the
			// average as the first call is slower
			cJSON_AddItemToArray(time_test, cJSON_CreateNumber(1.0*(t_s_cost*t_t_cost)/elapsed1));
			cJSON_AddItemToArray(time_test, cJSON_CreateNumber(1.0*(t_s_cost*t_t_cost)/elapsed2));
		}

		if(ret == 1)
			break;

		// Double time costs
		t_t_cost *= 2;
		i++;
	}

	printf("\nRunning space-performance test:\n");
	const size_t s_t_cost = 512;
	size_t s_s_cost = 8;
	cJSON *space_test = cJSON_CreateArray();
	while(true)
	{
		double elapsed1 = 0.0, elapsed2 = 0.0;
		const int ret = performance_test_task(s_s_cost, s_t_cost, password, sizeof(password), salt,
		                                      &elapsed1, &elapsed2);

		cJSON_AddItemToArray(space_test, cJSON_CreateNumber(1.0*(s_t_cost*s_s_cost)/elapsed1));
		cJSON_AddItemToArray(space_test, cJSON_CreateNumber(1.0*(s_t_cost*s_s_cost)/elapsed2));

		if(ret == -1)
			return EXIT_FAILURE;
		else if(ret == 1)
			break;

		// Double space costs
		s_s_cost *= 2;
	}

	clock_gettime(CLOCK_MONOTONIC, &end);
	const double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;

	// Compute average time and space costs from data in cJSON arrays
	cJSON *item = NULL;
	double t_avg_sum1 = 0.0;
	cJSON_ArrayForEach(item, time_test)
	{
		t_avg_sum1 += item->valuedouble;
	}
	t_avg_sum1 /= cJSON_GetArraySize(time_test);

	double s_avg_sum1 = 0.0;
	cJSON_ArrayForEach(item, space_test)
	{
		s_avg_sum1 += item->valuedouble;
	}
	s_avg_sum1 /= cJSON_GetArraySize(space_test);

	// Get standard deviations
	double t_stdev_sum1 = 0.0;
	cJSON_ArrayForEach(item, time_test)
	{
		t_stdev_sum1 += (item->valuedouble - t_avg_sum1)*(item->valuedouble - t_avg_sum1);
	}
	t_stdev_sum1 = sqroot(t_stdev_sum1/cJSON_GetArraySize(time_test));

	double s_stdev_sum1 = 0.0;
	cJSON_ArrayForEach(item, space_test)
	{
		s_stdev_sum1 += (item->valuedouble - s_avg_sum1)*(item->valuedouble - s_avg_sum1);
	}
	s_stdev_sum1 = sqroot(s_stdev_sum1/cJSON_GetArraySize(space_test));

	// Free allocated memory
	cJSON_Delete(time_test);
	cJSON_Delete(space_test);

	// Print results
	printf("\nAverage time-performance index:  %9.0f +/- %.0f (s = %zu)\n", t_avg_sum1, t_stdev_sum1, t_s_cost);
	printf("Average space-performance index: %9.0f +/- %.0f (t = %zu)\n", s_avg_sum1, s_stdev_sum1, s_t_cost);
	printf("\nTotal test time: %.1f seconds\n\n", elapsed);

	return EXIT_SUCCESS;
}

bool set_and_check_password(struct conf_item *conf_item, const char *password)
{
	// Get password hash as allocated string (an empty string is hashed to an empty string)
	char *pwhash = strlen(password) > 0 ? create_password(password) : strdup("");

	// Verify that the password hash is valid or that no password is set
	const enum password_result status = verify_password(password, pwhash, false);
	if(status != PASSWORD_CORRECT && status != NO_PASSWORD_SET)
	{
		free(pwhash);
		log_warn("Failed to create password hash (verification failed), password remains unchanged");
		return false;
	}

	// Get pointer to pwhash instead
	conf_item--;

	// Free previously allocated memory (if applicable)
	if(conf_item->t == CONF_STRING_ALLOCATED)
		free(conf_item->v.s);

	// Set item
	conf_item->v.s = pwhash;
	log_debug(DEBUG_CONFIG, "Set %s to \"%s\"", conf_item->k, conf_item->v.s);

	return true;
}

bool generate_app_password(char **password, char **pwhash)
{
	// Generate a 128 bit random salt
	// genrandom() returns cryptographically secure random data
	uint8_t salt[SALT_LEN] = { 0 };
	if(getrandom(salt, sizeof(salt), 0) < 0)
	{
		log_err("getrandom() failed in generate_app_password()");
		return false;
	}

	// Generate a 256 bit random password
	uint8_t password_raw[256/8] = { 0 };
	if(getrandom(password_raw, sizeof(password_raw), 0) < 0)
	{
		log_err("getrandom() failed in generate_app_password()");
		return false;
	}

	// Encode password as base64
	*password = base64_encode(password_raw, sizeof(password_raw));

	// Generate balloon PHC-encoded password hash
	*pwhash = balloon_password(*password, salt, true);

	// Verify that the password hash is valid
	if(verify_password(*password, *pwhash, false) != PASSWORD_CORRECT)
	{
		free(password);
		free(pwhash);
		log_warn("Failed to create password hash (verification failed), app password not available");
		return false;
	}

	return true;
}
