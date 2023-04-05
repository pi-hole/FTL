/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  X.509 certificate routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
#include "../log.h"
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
		log_err("mbedtls_pk_setup returned %d", ret);
		return ret;
	}

	if((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random,
	                              ctr_drbg, RSA_KEY_SIZE, 65537)) != 0)
	{
		log_err("mbedtls_rsa_gen_key returned %d", ret);
		return ret;
	}

	// Export key in PEM format
	if ((ret = mbedtls_pk_write_key_pem(key, key_buffer, BUFFER_SIZE)) != 0) {
		log_err("mbedtls_pk_write_key_pem returned %d", ret);
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
		log_err("mbedtls_pk_setup returned %d", ret);
		return ret;
	}

	// Generate key
	if((ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP521R1, mbedtls_pk_ec(*key),
	                              mbedtls_ctr_drbg_random, ctr_drbg)) != 0)
	{
		log_err("mbedtls_ecp_gen_key returned %d", ret);
		return ret;
	}

	// Export key in PEM format
	if ((ret = mbedtls_pk_write_key_pem(key, key_buffer, BUFFER_SIZE)) != 0) {
		log_err("mbedtls_pk_write_key_pem returned %d", ret);
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
	log_info("Initializing random number generator...");
	if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
	                                (const unsigned char *) pers, strlen(pers))) != 0)
	{
		log_err("mbedtls_ctr_drbg_seed returned %d", ret);
		return false;
	}

	if(rsa)
	{
		// Generate RSA key
		log_info("Generating RSA key...");
		if((ret = generate_private_key_rsa(&key, &ctr_drbg, key_buffer)) != 0)
		{
			log_err("generate_private_key returned %d", ret);
			return false;
		}
	}
	else
	{
		// Generate EC key
		log_info("Generating EC key...");
		if((ret = generate_private_key_ec(&key, &ctr_drbg, key_buffer)) != 0)
		{
			log_err("generate_private_key_ec returned %d", ret);
			return false;
		}
	}

	// Create string with random digits for unique serial number
	unsigned char serial[16] = { 0 };
	for(int i = 0; i < 15; i++)
		serial[i] = '0' + (rand() % 10);

	// Generate certificate
	log_info("Generating new certificate with serial number %s...", serial);
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
		log_err("mbedtls_x509write_crt_pem returned %d", ret);
		return false;
	}

	// Write private key and certificate to file
	FILE *f = NULL;
	log_info("Storing key + certificate in %s ...", certfile);
	if ((f = fopen(certfile, "wb")) == NULL)
	{
		log_err("Could not open %s for writing", certfile);
		return false;
	}

	// Write private key
	olen = strlen((char *) key_buffer);
	if (fwrite(key_buffer, 1, olen, f) != olen)
	{
		log_err("Could not write key to %s", certfile);
		fclose(f);
		return false;
	}

	// Write certificate
	olen = strlen((char *) cert_buffer);
	if (fwrite(cert_buffer, 1, olen, f) != olen)
	{
		log_err("Could not write certificate to %s", certfile);
		fclose(f);
		return false;
	}

	// Close file
	fclose(f);

	// Free ressources
	mbedtls_x509write_crt_free(&crt);
	mbedtls_pk_free(&key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return true;
}
