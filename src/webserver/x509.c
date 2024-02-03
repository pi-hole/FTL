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

// Write a key and/or certificate to a file
static bool write_to_file(const char *filename, const char *type, const char *suffix, const char *cert, const char *key)
{
	// Create file with CA certificate only
	char *targetname = calloc(strlen(filename) + (suffix != NULL ? strlen(suffix) : 0) + 1, sizeof(char));
	strcpy(targetname, filename);

	if(suffix != NULL)
	{
		// If the certificate file name ends with ".pem", replace it
		// with the specified suffix. Otherwise, append the specified
		// suffix to the certificate file name
		if (strlen(targetname) > 4 && strcmp(targetname + strlen(targetname) - 4, ".pem") == 0)
			targetname[strlen(filename) - 4] = '\0';

		strcat(targetname, suffix);
	}

	printf("Storing %s in %s ...\n", type, targetname);
	FILE *f = NULL;
	if ((f = fopen(targetname, "wb")) == NULL)
	{
		printf("ERROR: Could not open %s for writing\n", targetname);
		return false;
	}

	// Write key (if provided)
	if(key != NULL)
	{
		const size_t olen = strlen((char *) key);
		if (fwrite(key, 1, olen, f) != olen)
		{
			printf("ERROR: Could not write key to %s\n", targetname);
			fclose(f);
			return false;
		}
	}

	// Write certificate (if provided)
	if(cert != NULL)
	{
		const size_t olen = strlen((char *) cert);
		if (fwrite(cert, 1, olen, f) != olen)
		{
			printf("ERROR: Could not write certificate to %s\n", targetname);
			fclose(f);
			return false;
		}
	}

	// Close cert file
	fclose(f);
	free(targetname);

	return true;
}

bool generate_certificate(const char* certfile, bool rsa, const char *domain)
{
	int ret;
	mbedtls_x509write_cert ca_cert, server_cert;
	mbedtls_pk_context ca_key, server_key;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char *pers = "pihole-FTL";
	unsigned char ca_buffer[BUFFER_SIZE];
	unsigned char cert_buffer[BUFFER_SIZE];
	unsigned char key_buffer[BUFFER_SIZE];
	unsigned char ca_key_buffer[BUFFER_SIZE];

	// Initialize structures
	mbedtls_x509write_crt_init(&ca_cert);
	mbedtls_x509write_crt_init(&server_cert);
	mbedtls_pk_init(&ca_key);
	mbedtls_pk_init(&server_key);
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
		if((ret = generate_private_key_rsa(&ca_key, &ctr_drbg, ca_key_buffer)) != 0)
		{
			printf("ERROR: generate_private_key returned %d\n", ret);
			return false;
		}
		if((ret = generate_private_key_rsa(&server_key, &ctr_drbg, key_buffer)) != 0)
		{
			printf("ERROR: generate_private_key returned %d\n", ret);
			return false;
		}
	}
	else
	{
		// Generate EC key
		printf("Generating EC key...\n");
		if((ret = generate_private_key_ec(&ca_key, &ctr_drbg, ca_key_buffer)) != 0)
		{
			printf("ERROR: generate_private_key_ec returned %d\n", ret);
			return false;
		}
		if((ret = generate_private_key_ec(&server_key, &ctr_drbg, key_buffer)) != 0)
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
	unsigned char serial1[16] = { 0 }, serial2[16] = { 0 };
	mbedtls_ctr_drbg_random(&ctr_drbg, serial1, sizeof(serial1));
	for(unsigned int i = 0; i < sizeof(serial1) - 1; i++)
		serial1[i] = '0' + (serial1[i] % 10);
	serial1[sizeof(serial1) - 1] = '\0';
	mbedtls_ctr_drbg_random(&ctr_drbg, serial2, sizeof(serial2));
	for(unsigned int i = 0; i < sizeof(serial2) - 1; i++)
		serial2[i] = '0' + (serial2[i] % 10);
	serial2[sizeof(serial2) - 1] = '\0';

	// Create validity period
	// Use YYYYMMDDHHMMSS as required by RFC 5280 (UTCTime)
	const time_t now = time(NULL);
	struct tm tms = { 0 };
	struct tm *tm = gmtime_r(&now, &tms);
	char not_before[16] = { 0 };
	char not_after[16] = { 0 };
	strftime(not_before, sizeof(not_before), "%Y%m%d%H%M%S", tm);
	tm->tm_year += 30; // 30 years from now
	strftime(not_after, sizeof(not_after), "%Y%m%d%H%M%S", tm);

	// 1. Create CA certificate
	printf("Generating new CA with serial number %s...\n", serial1);
	mbedtls_x509write_crt_set_version(&ca_cert, MBEDTLS_X509_CRT_VERSION_3);

	mbedtls_x509write_crt_set_serial_raw(&ca_cert, serial1, sizeof(serial1)-1);
	mbedtls_x509write_crt_set_md_alg(&ca_cert, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&ca_cert, &ca_key);
	mbedtls_x509write_crt_set_subject_key_identifier(&ca_cert);
	mbedtls_x509write_crt_set_issuer_key(&ca_cert, &ca_key);
	mbedtls_x509write_crt_set_authority_key_identifier(&ca_cert);
	mbedtls_x509write_crt_set_issuer_name(&ca_cert, "CN=pi.hole,O=Pi-hole,C=DE");
	mbedtls_x509write_crt_set_subject_name(&ca_cert, "CN=pi.hole,O=Pi-hole,C=DE");
	mbedtls_x509write_crt_set_validity(&ca_cert, not_before, not_after);
	mbedtls_x509write_crt_set_basic_constraints(&ca_cert, 1, -1);

	// Export CA in PEM format
	if((ret = mbedtls_x509write_crt_pem(&ca_cert, ca_buffer, sizeof(ca_buffer),
	                                    mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
	{
		printf("ERROR: mbedtls_x509write_crt_pem (CA) returned %d\n", ret);
		return false;
	}

	printf("Generating new server certificate with serial number %s...\n", serial2);
	mbedtls_x509write_crt_set_version(&server_cert, MBEDTLS_X509_CRT_VERSION_3);

	mbedtls_x509write_crt_set_serial_raw(&server_cert, serial2, sizeof(serial2)-1);
	mbedtls_x509write_crt_set_md_alg(&server_cert, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&server_cert, &server_key);
	mbedtls_x509write_crt_set_subject_key_identifier(&server_cert);
	mbedtls_x509write_crt_set_issuer_key(&server_cert, &ca_key);
	mbedtls_x509write_crt_set_authority_key_identifier(&server_cert);
	// subject name set below
	mbedtls_x509write_crt_set_issuer_name(&server_cert, "CN=pi.hole,O=Pi-hole,C=DE");
	mbedtls_x509write_crt_set_validity(&server_cert, not_before, not_after);
	mbedtls_x509write_crt_set_basic_constraints(&server_cert, 0, -1);

	// Set subject name depending on the (optionally) specified domain
	{
		char *subject_name = calloc(strlen(domain) + 4, sizeof(char));
		strcpy(subject_name, "CN=");
		strcat(subject_name, domain);
		mbedtls_x509write_crt_set_subject_name(&server_cert, subject_name);
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

	ret = mbedtls_x509write_crt_set_subject_alternative_name(&server_cert, &san_dns_pihole);
	if (ret != 0)
		printf("mbedtls_x509write_crt_set_subject_alternative_name returned %d\n", ret);

	// Export certificate in PEM format
	if((ret = mbedtls_x509write_crt_pem(&server_cert, cert_buffer, sizeof(cert_buffer),
	                                    mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
	{
		printf("ERROR: mbedtls_x509write_crt_pem returned %d\n", ret);
		return false;
	}

	// Create file with CA certificate only
	write_to_file(certfile, "CA certificate", "_ca.crt", (char*)ca_buffer, NULL);

	// Create file with server certificate only
	write_to_file(certfile, "server certificate", ".crt", (char*)cert_buffer, NULL);

	// Write server's private key and certificate to file
	write_to_file(certfile, "server key + certificate", NULL, (char*)cert_buffer, (char*)key_buffer);

	// Free resources
	mbedtls_x509write_crt_free(&ca_cert);
	mbedtls_x509write_crt_free(&server_cert);
	mbedtls_pk_free(&ca_key);
	mbedtls_pk_free(&server_key);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return true;
}

static bool check_wildcard_domain(const char *domain, char *san, const size_t san_len)
{
	// Also check if the SAN is a wildcard domain and if the domain
	// matches the wildcard (e.g. "*.pi-hole.net" and "abc.pi-hole.net")
	const bool is_wild = san_len > 1 && san[0] == '*';
	if(!is_wild)
		return false;

	// The domain must be at least as long as the wildcard domain
	const size_t domain_len = strlen(domain);
	if(domain_len < san_len - 1)
		return false;

	// Check if the domain ends with the wildcard domain
	// Attention: The SAN is not NUL-terminated, so we need to
	//            use the length field
	const char *wild_domain = domain + domain_len - san_len + 1;
	return strncasecmp(wild_domain, san + 1, san_len) == 0;
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

	log_info("Reading certificate from %s ...", certfile);

	// Check if the file exists and is readable
	if(access(certfile, R_OK) != 0)
	{
		log_err("Could not read certificate file: %s", strerror(errno));
		return CERT_FILE_NOT_FOUND;
	}

	bool has_key = true;
	int rc = mbedtls_pk_parse_keyfile(&key, certfile, NULL, mbedtls_ctr_drbg_random, &ctr_drbg);
	if (rc != 0)
	{
		log_info("No key found");
		has_key = false;
	}

	rc = mbedtls_x509_crt_parse_file(&crt, certfile);
	if (rc != 0)
	{
		log_err("Cannot parse certificate: Error code %d", rc);
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
			// Attention: The SAN is not NUL-terminated, so we need to
			//            use the length field
			if(strncasecmp(domain, (char*)san.san.unstructured_name.p, san.san.unstructured_name.len) == 0)
			{
				found = true;
				// Free resources
				mbedtls_x509_free_subject_alt_name(&san);
				break;
			}

			// Also check if the SAN is a wildcard domain and if the domain
			// matches the wildcard
			if(check_wildcard_domain(domain, (char*)san.san.unstructured_name.p, san.san.unstructured_name.len))
			{
				found = true;
				// Free resources
				mbedtls_x509_free_subject_alt_name(&san);
				break;
			}
next_san:
			// Free resources
			mbedtls_x509_free_subject_alt_name(&san);

			// Go to next SAN
			sans = sans->next;
		}

		// Also check against the common name (CN) field
		char subject[MBEDTLS_X509_MAX_DN_NAME_SIZE];
		const size_t subject_len = mbedtls_x509_dn_gets(subject, sizeof(subject), &crt.subject);
		if(subject_len > 0)
		{
			// Check subjects prefixed with "CN="
			if(subject_len > 3 && strncasecmp(subject, "CN=", 3) == 0)
			{
				// Check subject + 3 to skip the prefix
				if(strncasecmp(domain, subject + 3, subject_len - 3) == 0)
					found = true;
				// Also check if the subject is a wildcard domain
				else if(check_wildcard_domain(domain, subject + 3, subject_len - 3))
					found = true;
			}
			// Check subject == "<domain>"
			else if(strcasecmp(domain, subject) == 0)
				found = true;
			// Also check if the subject is a wildcard domain and if the domain
			// matches the wildcard
			else if(check_wildcard_domain(domain, subject, subject_len))
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

	if(!private_key || !has_key)
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
		mbedtls_ecp_curve_type ec_type = mbedtls_ecp_get_type(&ec->private_grp);
		switch (ec_type)
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
