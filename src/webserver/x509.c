/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  X.509 certificate and randomness generator routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "log.h"
#include "x509.h"
#include <mbedtls/rsa.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define RSA_KEY_SIZE 4096
#define BUFFER_SIZE 16000

// Generate private RSA key
static int generate_private_key_rsa(mbedtls_pk_context *key,
                                    mbedtls_ctr_drbg_context *ctr_drbg,
                                    unsigned char key_buffer[])
{
	int ret;
	if((ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0)
	{
		printf("ERROR: mbedtls_pk_setup returned %d\n", ret);
		return ret;
	}

	if((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random,
	                              ctr_drbg, RSA_KEY_SIZE, 65537)) != 0)
	{
		printf("ERROR: mbedtls_rsa_gen_key returned %d\n", ret);
		return ret;
	}

	// Export key in PEM format
	if ((ret = mbedtls_pk_write_key_pem(key, key_buffer, BUFFER_SIZE)) != 0) {
		printf("ERROR: mbedtls_pk_write_key_pem returned %d\n", ret);
		return ret;
	}

	return 0;
}

// Generate private EC key (secp521r1)
static int generate_private_key_ec(mbedtls_pk_context *key,
                                   mbedtls_ctr_drbg_context *ctr_drbg,
                                   unsigned char key_buffer[])
{
	int ret;
	// Setup key
	if((ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
	{
		printf("ERROR: mbedtls_pk_setup returned %d\n", ret);
		return ret;
	}

	// Generate key
	if((ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP521R1, mbedtls_pk_ec(*key),
	                              mbedtls_ctr_drbg_random, ctr_drbg)) != 0)
	{
		printf("ERROR: mbedtls_ecp_gen_key returned %d\n", ret);
		return ret;
	}

	// Export key in PEM format
	if ((ret = mbedtls_pk_write_key_pem(key, key_buffer, BUFFER_SIZE)) != 0) {
		printf("ERROR: mbedtls_pk_write_key_pem returned %d\n", ret);
		return ret;
	}

	return 0;
}

bool generate_certificate(const char* certfile, bool rsa)
{
	int ret;
	mbedtls_x509write_cert crt;
	mbedtls_pk_context key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "pihole-FTL";
	unsigned char cert_buffer[BUFFER_SIZE];
	unsigned char key_buffer[BUFFER_SIZE];
	size_t olen = 0;

	// Initialize structures
	mbedtls_x509write_crt_init(&crt);
	mbedtls_pk_init(&key);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	// Initialize random number generator
	printf("Initializing random number generator...\n");
	if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
	                                (const unsigned char *) pers, strlen(pers))) != 0)
	{
		printf("ERROR: mbedtls_ctr_drbg_seed returned %d\n", ret);
		return false;
	}

	// Generate key
	if(rsa)
	{
		// Generate RSA key
		printf("Generating RSA key...\n");
		if((ret = generate_private_key_rsa(&key, &ctr_drbg, key_buffer)) != 0)
		{
			printf("ERROR: generate_private_key returned %d\n", ret);
			return false;
		}
	}
	else
	{
		// Generate EC key
		printf("Generating EC key...\n");
		if((ret = generate_private_key_ec(&key, &ctr_drbg, key_buffer)) != 0)
		{
			printf("ERROR: generate_private_key_ec returned %d\n", ret);
			return false;
		}
	}

	// Create string with random digits for unique serial number
	// RFC 2459: The serial number is an integer assigned by the CA to each
	// certificate. It MUST be unique for each certificate issued by a given
	// CA (i.e., the issuer name and serial number identify a unique
	// certificate).
	// We generate a random string of 16 digits, which should be unique enough
	// for our purposes. We use the same random number generator as for the
	// key generation to ensure that the serial number is not predictable.
	// The serial number could be a constant, e.g., 1, but this would allow
	// only one certificate being issued with a given browser. Any new generated
	// certificate would be rejected by the browser as it would have the same
	// serial number as the previous one and uniques is violated.
	unsigned char serial[16] = { 0 };
	mbedtls_ctr_drbg_random(&ctr_drbg, serial, sizeof(serial));
	for(unsigned int i = 0; i < sizeof(serial) - 1; i++)
		serial[i] = '0' + (serial[i] % 10);
	serial[sizeof(serial) - 1] = '\0';

	// Generate certificate
	printf("Generating new certificate with serial number %s...\n", serial);
	mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

	mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial)-1);
	mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&crt, &key);
	mbedtls_x509write_crt_set_issuer_key(&crt, &key);
	mbedtls_x509write_crt_set_subject_name(&crt, "CN=pi.hole");
	mbedtls_x509write_crt_set_issuer_name(&crt, "CN=pi.hole");
	mbedtls_x509write_crt_set_validity(&crt, "20010101000000", "20301231235959");
	mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
	mbedtls_x509write_crt_set_subject_key_identifier(&crt);
	mbedtls_x509write_crt_set_authority_key_identifier(&crt);

	// Export certificate in PEM format
	if((ret = mbedtls_x509write_crt_pem(&crt, cert_buffer, sizeof(cert_buffer),
	                                    mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
	{
		printf("ERROR: mbedtls_x509write_crt_pem returned %d\n", ret);
		return false;
	}

	// Write private key and certificate to file
	FILE *f = NULL;
	printf("Storing key + certificate in %s ...\n", certfile);
	if ((f = fopen(certfile, "wb")) == NULL)
	{
		printf("ERROR: Could not open %s for writing\n", certfile);
		return false;
	}

	// Write private key
	olen = strlen((char *) key_buffer);
	if (fwrite(key_buffer, 1, olen, f) != olen)
	{
		printf("ERROR: Could not write key to %s\n", certfile);
		fclose(f);
		return false;
	}

	// Write certificate
	olen = strlen((char *) cert_buffer);
	if (fwrite(cert_buffer, 1, olen, f) != olen)
	{
		printf("ERROR: Could not write certificate to %s\n", certfile);
		fclose(f);
		return false;
	}

	// Close key+cert file
	fclose(f);

	// Create second file with certificate only
	char *certfile2 = calloc(strlen(certfile) + 5, sizeof(char));
	strcpy(certfile2, certfile);

	// If the certificate file name ends with ".pem" or ".key", replace it with ".crt"
	// Otherwise, append ".crt" to the certificate file name
	if (strlen(certfile2) > 4 &&
	     (strcmp(certfile2 + strlen(certfile2) - 4, ".pem") == 0 ||
	      strcmp(certfile2 + strlen(certfile2) - 4, ".key") == 0))
		certfile2[strlen(certfile) - 4] = '\0';

	strcat(certfile2, ".crt");

	printf("Storing certificate in %s ...\n", certfile2);
	if ((f = fopen(certfile2, "wb")) == NULL)
	{
		printf("ERROR: Could not open %s for writing\n", certfile2);
		return false;
	}

	// Write certificate
	olen = strlen((char *) cert_buffer);
	if (fwrite(cert_buffer, 1, olen, f) != olen)
	{
		printf("ERROR: Could not write certificate to %s\n", certfile2);
		fclose(f);
		return false;
	}

	// Close cert file
	fclose(f);
	free(certfile2);

	// Free resources
	mbedtls_x509write_crt_free(&crt);
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return true;
}
