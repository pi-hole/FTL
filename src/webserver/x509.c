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

// Generate private EC key
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

	// Generate key SECP384R1 key (NIST P-384)
	if((ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP384R1, mbedtls_pk_ec(*key),
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

bool generate_certificate(const char* certfile, bool rsa, const char *domain)
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
	mbedtls_x509write_crt_set_issuer_name(&crt, "CN=pi.hole");
	mbedtls_x509write_crt_set_validity(&crt, "20010101000000", "20301231235959");
	mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
	mbedtls_x509write_crt_set_subject_key_identifier(&crt);
	mbedtls_x509write_crt_set_authority_key_identifier(&crt);


	// Set subject name depending on the (optionally) specified domain
	{
		char *subject_name = calloc(strlen(domain) + 4, sizeof(char));
		strcpy(subject_name, "CN=");
		strcat(subject_name, domain);
		mbedtls_x509write_crt_set_subject_name(&crt, subject_name);
		free(subject_name);
	}


	// Add "DNS:pi.hole" as subject alternative name (SAN)
	//
	// Since RFC 2818 (May 2000), the Common Name (CN) field is ignored
	// in certificates if the subject alternative name extension is present.
	//
	// Furthermore, RFC 3280 (4.2.1.7, 1. paragraph) specifies that
	// subjectAltName must always be used and that the use of the CN field
	// should be limited to support legacy implementations.
	//
	mbedtls_x509_san_list san_dns_pihole = { 0 };
	san_dns_pihole.node.type = MBEDTLS_X509_SAN_DNS_NAME;
	san_dns_pihole.node.san.unstructured_name.p = (unsigned char *) "pi.hole";
	san_dns_pihole.node.san.unstructured_name.len = 7; // strlen("pi.hole")
	san_dns_pihole.next = NULL; // No further element

	// Furthermore, add the domain when a custom domain is used to make the
	// certificate more universal
	mbedtls_x509_san_list san_dns_domain = { 0 };
	if(strcasecmp(domain, "pi.hole") != 0)
	{
		san_dns_domain.node.type = MBEDTLS_X509_SAN_DNS_NAME;
		san_dns_domain.node.san.unstructured_name.p = (unsigned char *) domain;
		san_dns_domain.node.san.unstructured_name.len = strlen(domain);
		san_dns_domain.next = NULL; // No more SANs (linked list)

		san_dns_pihole.next = &san_dns_domain; // Link this domain
	}

	ret = mbedtls_x509write_crt_set_subject_alternative_name(&crt, &san_dns_pihole);
	if (ret != 0)
		printf("mbedtls_x509write_crt_set_subject_alternative_name returned %d\n", ret);


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

// This function reads a X.509 certificate from a file and prints a
// human-readable representation of the certificate to stdout. If a domain is
// specified, we only check if this domain is present in the certificate.
// Otherwise, we print verbose human-readable information about the certificate
// and about the private key (if requested).
enum cert_check read_certificate(const char* certfile, const char *domain, const bool private_key)
{
	if(certfile == NULL && domain == NULL)
	{
		log_err("No certificate file specified\n");
		return CERT_FILE_NOT_FOUND;
	}

	mbedtls_x509_crt crt;
	mbedtls_pk_context key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_x509_crt_init(&crt);
	mbedtls_pk_init(&key);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	printf("Reading certificate from %s ...\n\n", certfile);

	// Check if the file exists and is readable
	if(access(certfile, R_OK) != 0)
	{
		log_err("Could not read certificate file: %s\n", strerror(errno));
		return CERT_FILE_NOT_FOUND;
	}

	int rc = mbedtls_pk_parse_keyfile(&key, certfile, NULL, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (rc != 0)
	{
		log_err("Cannot parse key: Error code %d\n", rc);
		return CERT_CANNOT_PARSE_KEY;
	}

	rc = mbedtls_x509_crt_parse_file(&crt, certfile);
	if (rc != 0)
	{
		log_err("Cannt parse certificate: Error code %d\n", rc);
		return CERT_CANNOT_PARSE_CERT;
	}

	// Parse mbedtls_x509_parse_subject_alt_names()
	mbedtls_x509_sequence *sans = &crt.subject_alt_names;
	bool found = false;
	if(domain != NULL)
	{
		// Loop over all SANs
		while(sans != NULL)
		{
			// Parse the SAN
			mbedtls_x509_subject_alternative_name san = { 0 };
			const int ret = mbedtls_x509_parse_subject_alt_name(&sans->buf, &san);

			// Check if SAN is used (otherwise ret < 0, e.g.,
			// MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE) and if it is a
			// DNS name, skip otherwise
			if(ret < 0 || san.type != MBEDTLS_X509_SAN_DNS_NAME)
				goto next_san;

			// Check if the SAN matches the domain
			if(strncasecmp(domain, (char*)san.san.unstructured_name.p, san.san.unstructured_name.len) == 0)
			{
				found = true;
				break;
			}
next_san:
			// Go to next SAN
			sans = sans->next;
		}

		// Also check against the common name (CN) field
		char subject[MBEDTLS_X509_MAX_DN_NAME_SIZE];
		if(mbedtls_x509_dn_gets(subject, sizeof(subject), &crt.subject) > 0)
		{
			// Check subject == "CN=<domain>"
			if(strlen(subject) > 3 && strncasecmp(subject, "CN=", 3) == 0 && strcasecmp(domain, subject + 3) == 0)
				found = true;
			// Check subject == "<domain>"
			else if(strcasecmp(domain, subject) == 0)
				found = true;
		}


		// Free resources
		mbedtls_x509_crt_free(&crt);
		mbedtls_pk_free(&key);
		mbedtls_entropy_free(&entropy);
		mbedtls_ctr_drbg_free(&ctr_drbg);
		return found ? CERT_DOMAIN_MATCH : CERT_DOMAIN_MISMATCH;
	}

	// else: Print verbose information about the certificate
	char certinfo[BUFFER_SIZE] = { 0 };
	mbedtls_x509_crt_info(certinfo, BUFFER_SIZE, "  ", &crt);
	puts("Certificate (X.509):\n");
	puts(certinfo);

	if(!private_key)
		goto end;

	puts("Private key:");
	const char *keytype = mbedtls_pk_get_name(&key);
	printf("  Type: %s\n", keytype);
	mbedtls_pk_type_t pk_type = mbedtls_pk_get_type(&key);
	if(pk_type == MBEDTLS_PK_RSA)
	{
		mbedtls_rsa_context *rsa = mbedtls_pk_rsa(key);
		printf("  RSA modulus: %zu bit\n", 8*mbedtls_rsa_get_len(rsa));
		mbedtls_mpi E, N, P, Q, D;
		mbedtls_mpi_init(&E); // E = public exponent (public)
		mbedtls_mpi_init(&N); // N = P * Q (public)
		mbedtls_mpi_init(&P); // P = prime factor 1 (private)
		mbedtls_mpi_init(&Q); // Q = prime factor 2 (private)
		mbedtls_mpi_init(&D); // D = private exponent (private)
		mbedtls_mpi DP, DQ, QP;
		mbedtls_mpi_init(&DP);
		mbedtls_mpi_init(&DQ);
		mbedtls_mpi_init(&QP);
		if(mbedtls_rsa_export(rsa, &N, &P, &Q, &D, &E) != 0 ||
		   mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP) != 0)
		{
			puts(" could not export RSA parameters\n");
			return EXIT_FAILURE;
		}
		puts("  Core parameters:");
		if(mbedtls_mpi_write_file("  Exponent:\n    E = 0x", &E, 16, NULL) != 0)
		{
			puts(" could not write MPI\n");
			return EXIT_FAILURE;
		}

		if(mbedtls_mpi_write_file("  Modulus:\n    N = 0x", &N, 16, NULL) != 0)
		{
			puts(" could not write MPI\n");
			return EXIT_FAILURE;
		}

		if(mbedtls_mpi_cmp_mpi(&P, &Q) >= 0)
		{
			if(mbedtls_mpi_write_file("  Prime factors:\n    P = 0x", &P, 16, NULL) != 0 ||
			   mbedtls_mpi_write_file("    Q = 0x", &Q, 16, NULL) != 0)
			{
				puts(" could not write MPIs\n");
				return EXIT_FAILURE;
			}
		}
		else
		{
			if(mbedtls_mpi_write_file("  Prime factors:\n    Q = 0x", &Q, 16, NULL) != 0 ||
			   mbedtls_mpi_write_file("\n    P = 0x", &P, 16, NULL) != 0)
			{
				puts(" could not write MPIs\n");
				return EXIT_FAILURE;
			}
		}

		if(mbedtls_mpi_write_file("  Private exponent:\n    D = 0x", &D, 16, NULL) != 0)
		{
			puts(" could not write MPI\n");
			return EXIT_FAILURE;
		}

		mbedtls_mpi_free(&N);
		mbedtls_mpi_free(&P);
		mbedtls_mpi_free(&Q);
		mbedtls_mpi_free(&D);
		mbedtls_mpi_free(&E);

		puts("  CRT parameters:");
		if(mbedtls_mpi_write_file("  D mod (P-1):\n    DP = 0x", &DP, 16, NULL) != 0 ||
		   mbedtls_mpi_write_file("  D mod (Q-1):\n    DQ = 0x", &DQ, 16, NULL) != 0 ||
		   mbedtls_mpi_write_file("  Q^-1 mod P:\n    QP = 0x", &QP, 16, NULL) != 0)
		{
			puts(" could not write MPIs\n");
			return EXIT_FAILURE;
		}

		mbedtls_mpi_free(&DP);
		mbedtls_mpi_free(&DQ);
		mbedtls_mpi_free(&QP);

	}
	else if(pk_type == MBEDTLS_PK_ECKEY)
	{
		mbedtls_ecp_keypair *ec = mbedtls_pk_ec(key);
		mbedtls_ecp_curve_type ect = mbedtls_ecp_get_type(&ec->private_grp);
		switch (ect)
		{
			case MBEDTLS_ECP_TYPE_NONE:
				puts("  Curve type: Unknown");
				break;
			case MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS:
				puts("  Curve type: Short Weierstrass (y^2 = x^3 + a x + b)");
				break;
			case MBEDTLS_ECP_TYPE_MONTGOMERY:
				puts("  Curve type: Montgomery (y^2 = x^3 + a x^2 + x)");
				break;
		}
		const size_t bitlen = mbedtls_mpi_bitlen(&ec->private_d);
		printf("  Bitlen:  %zu bit\n", bitlen);

		mbedtls_mpi_write_file("  Private key:\n    D = 0x", &ec->private_d, 16, NULL);
		mbedtls_mpi_write_file("  Public key:\n    X = 0x", &ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), 16, NULL);
		mbedtls_mpi_write_file("    Y = 0x", &ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), 16, NULL);
		mbedtls_mpi_write_file("    Z = 0x", &ec->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Z), 16, NULL);
	}
	else
	{
		puts("Sorry, but FTL does not know how to print key information for this type\n");
		goto end;
	}

	// Print private key in PEM format
	mbedtls_pk_write_key_pem(&key, (unsigned char*)certinfo, BUFFER_SIZE);
	puts("Private key (PEM):");
	puts(certinfo);

end:
	// Print public key in PEM format
	mbedtls_pk_write_pubkey_pem(&key, (unsigned char*)certinfo, BUFFER_SIZE);
	puts("Public key (PEM):");
	puts(certinfo);

	// Free resources
	mbedtls_x509_crt_free(&crt);
	mbedtls_pk_free(&key);
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);

	return CERT_OKAY;
}
