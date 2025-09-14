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

#ifndef HAVE_MBEDTLS
#define HAVE_MBEDTLS
#endif

#ifdef HAVE_MBEDTLS
# include <mbedtls/rsa.h>
# include <mbedtls/x509.h>
# include <mbedtls/x509_crt.h>

// We enforce at least mbedTLS v3.5.0 if we use it
#if MBEDTLS_VERSION_NUMBER < 0x03050000
# error "mbedTLS version 3.5.0 or later is required"
#endif

#define RSA_KEY_SIZE 4096
#define BUFFER_SIZE 16000
#define PIHOLE_ISSUER "CN=pi.hole,O=Pi-hole,C=DE"

static bool read_id_file(const char *filename, char *buffer, size_t buffer_size)
{
	FILE *f = fopen(filename, "r");
	if(f == NULL)
		return false;

	if(fread(buffer, 1, buffer_size, f) != buffer_size)
	{
		fclose(f);
		return false;
	}

	fclose(f);
	return true;
}

static mbedtls_entropy_context entropy = { 0 };
static mbedtls_ctr_drbg_context ctr_drbg = { 0 };
/**
 * @brief Initializes the entropy and random number generator.
 *
 * This function initializes the entropy and random number generator using
 * mbedtls library functions. It ensures that the initialization is performed
 * only once. Calling this function multiple times has no adverse effect.
 *
 * @return true if the initialization is successful or has already been
 * performed, false if there is an error during initialization.
 */
bool init_entropy(void)
{
	// Check if already initialized
	static bool initialized = false;
	if(initialized)
		return true;

	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	// Get machine-id (this may fail in containers)
	// https://www.freedesktop.org/software/systemd/man/latest/machine-id.html
	char machine_id[128] = { 0 };
	read_id_file("/etc/machine-id", machine_id, sizeof(machine_id));

	// The boot_id random ID that is regenerated on each boot. As such it
	// can be used to identify the local machine’s current boot. It’s
	// universally available on any recent Linux kernel. It’s a good and
	// safe choice if you need to identify a specific boot on a specific
	// booted kernel.
	// Read /proc/sys/kernel/random/boot_id and append it to machine_id
	// The UUID is in format 8-4-4-4-12 and, hence, 36 characters long
	char boot_id[37] = { 0 };
	if(read_id_file("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id)))
	{
		boot_id[36] = '\0';
		strncat(machine_id, boot_id, sizeof(machine_id) - strlen(machine_id) - 1);
	}

	// Initialize random number generator
	int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char*)machine_id, strlen(machine_id));
	if(ret != 0)
	{
		log_err("mbedtls_ctr_drbg_seed returned %d\n", ret);
		return false;
	}

	initialized = true;
	return true;
}

/**
 * @brief Frees the resources allocated for entropy and CTR-DRBG contexts.
 *
 * This function releases the memory and resources associated with the
 * entropy and CTR-DRBG contexts, ensuring that they are properly cleaned up.
 * It should be called when these contexts are no longer needed to avoid
 * memory leaks.
 */
void destroy_entropy(void)
{
	mbedtls_entropy_free(&entropy);
	mbedtls_ctr_drbg_free(&ctr_drbg);
}

/**
 * @brief Generates random bytes using the CTR_DRBG (Counter mode Deterministic
 * Random Byte Generator).
 *
 * @param output Pointer to the buffer where the generated random bytes will be
 * stored.
 * @param len The number of random bytes to generate.
 * @return The number of bytes generated on success, or -1 on failure.
 */
ssize_t drbg_random(unsigned char *output, size_t len)
{
	init_entropy();
	const int ret = mbedtls_ctr_drbg_random(&ctr_drbg, output, len);
	if(ret != 0)
	{
		log_err("mbedtls_ctr_drbg_random returned %d\n", ret);
		return -1;
	}

	// Return number of bytes generated
	return len;
}

// Generate private RSA key
static int generate_private_key_rsa(mbedtls_pk_context *key,
                                    unsigned char key_buffer[])
{
	int ret;
	if((ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0)
	{
		printf("ERROR: mbedtls_pk_setup returned %d\n", ret);
		return ret;
	}

	if((ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random,
	                              &ctr_drbg, RSA_KEY_SIZE, 65537)) != 0)
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
	                              mbedtls_ctr_drbg_random, &ctr_drbg)) != 0)
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
static bool write_to_file(const char *filename, const char *type, const char *suffix, const char *cert, const char *key, const char *cacert)
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

	// Restrict permissions to owner read/write only
	if(fchmod(fileno(f), S_IRUSR | S_IWUSR) != 0)
		log_warn("Unable to set permissions on file \"%s\": %s", targetname, strerror(errno));

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

	// Write CA certificate (if provided)
	if(cacert != NULL)
	{
		const size_t olen = strlen((char *) cacert);
		if (fwrite(cacert, 1, olen, f) != olen)
		{
			printf("ERROR: Could not write CA certificate to %s\n", targetname);
			fclose(f);
			return false;
		}
	}

	// Close cert file
	fclose(f);
	free(targetname);

	return true;
}

bool generate_certificate(const char* certfile, bool rsa, const char *domain, const unsigned int validity_days)
{
	int ret;
	mbedtls_x509write_cert ca_cert, server_cert;
	mbedtls_pk_context ca_key, server_key;
	unsigned char ca_buffer[BUFFER_SIZE];
	unsigned char cert_buffer[BUFFER_SIZE];
	unsigned char key_buffer[BUFFER_SIZE];
	unsigned char ca_key_buffer[BUFFER_SIZE];

	// Initialize structures
	mbedtls_x509write_crt_init(&ca_cert);
	mbedtls_x509write_crt_init(&server_cert);
	mbedtls_pk_init(&ca_key);
	mbedtls_pk_init(&server_key);
	init_entropy();

	// Generate key
	if(rsa)
	{
		// Generate RSA key
		printf("Generating RSA key...\n");
		if((ret = generate_private_key_rsa(&ca_key, ca_key_buffer)) != 0)
		{
			printf("ERROR: generate_private_key returned %d\n", ret);
			return false;
		}
		if((ret = generate_private_key_rsa(&server_key, key_buffer)) != 0)
		{
			printf("ERROR: generate_private_key returned %d\n", ret);
			return false;
		}
	}
	else
	{
		// Generate EC key
		printf("Generating EC key...\n");
		if((ret = generate_private_key_ec(&ca_key, ca_key_buffer)) != 0)
		{
			printf("ERROR: generate_private_key_ec returned %d\n", ret);
			return false;
		}
		if((ret = generate_private_key_ec(&server_key, key_buffer)) != 0)
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
	tm->tm_mday += validity_days > 0 ? validity_days : 30*365; // If no validity is specified, use 30 years
	tm->tm_isdst = -1; // Not set, let mktime() determine it
	mktime(tm); // normalize time
	// Check for leap year, and adjust the date accordingly
	const bool isLeapYear = tm->tm_year % 4 == 0 && (tm->tm_year % 100 != 0 || tm->tm_year % 400 == 0);
	tm->tm_mday = tm->tm_mon == 1 && tm->tm_mday == 29 && !isLeapYear ? 28 : tm->tm_mday;
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
	mbedtls_x509write_crt_set_issuer_name(&ca_cert, PIHOLE_ISSUER);
	mbedtls_x509write_crt_set_subject_name(&ca_cert, PIHOLE_ISSUER);
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
	mbedtls_x509write_crt_set_issuer_name(&server_cert, PIHOLE_ISSUER);
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
	write_to_file(certfile, "CA certificate", "_ca.crt", (char*)ca_buffer, NULL, NULL);

	// Create file with server certificate only
	write_to_file(certfile, "server certificate", ".crt", (char*)cert_buffer, NULL, NULL);

	// Write server's private key and certificate to file
	write_to_file(certfile, "server key + certificate", NULL, (char*)cert_buffer, (char*)key_buffer, (char*)ca_buffer);

	// Free resources
	mbedtls_x509write_crt_free(&ca_cert);
	mbedtls_x509write_crt_free(&server_cert);
	mbedtls_pk_free(&ca_key);
	mbedtls_pk_free(&server_key);

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
	return strncasecmp(wild_domain, san + 1, san_len - 1) == 0;
}

static bool search_domain(mbedtls_x509_crt *crt, mbedtls_x509_sequence *sans, const char *domain)
{
	bool found = false;
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

	if(found)
		return true;

	// Also check against the common name (CN) field
	char subject[MBEDTLS_X509_MAX_DN_NAME_SIZE];
	const size_t subject_len = mbedtls_x509_dn_gets(subject, sizeof(subject), &(crt->subject));
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

	return found;
}


// This function reads a X.509 certificate from a file and prints a
// human-readable representation of the certificate to stdout. If a domain is
// specified, we only check if this domain is present in the certificate.
// Otherwise, we print verbose human-readable information about the certificate
// and about the private key (if requested).
enum cert_check read_certificate(const char *certfile, const char *domain, const bool private_key)
{
	if(certfile == NULL && domain == NULL)
	{
		log_err("No certificate file specified\n");
		return CERT_FILE_NOT_FOUND;
	}

	mbedtls_x509_crt crt;
	mbedtls_pk_context key;
	mbedtls_x509_crt_init(&crt);
	mbedtls_pk_init(&key);
	init_entropy();

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

	// When a domain is specified, possibly return early
	if(domain != NULL)
		return search_domain(&crt, sans, domain) ? CERT_DOMAIN_MATCH : CERT_DOMAIN_MISMATCH;

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

	return CERT_OKAY;
}

/**
 * @brief Checks if the certificate at the given file path is currently valid and will remain valid for at least the specified number of days.
 *
 * This function loads an X.509 certificate from the specified file, verifies that it is readable and parsable,
 * and checks its validity period. It ensures that the certificate is already valid (not before date is in the past)
 * and that it will not expire within the next `valid_for_at_least_days` days.
 *
 * @param certfile Path to the certificate file to check. If NULL, the function returns CERT_FILE_NOT_FOUND.
 * @param valid_for_at_least_days The minimum number of days the certificate should remain valid from now.
 *
 * @return enum cert_check
 *         - CERT_OKAY: Certificate is valid and will remain valid for at least the specified number of days.
 *         - CERT_FILE_NOT_FOUND: Certificate file is not specified, does not exist, or is not readable.
 *         - CERT_CANNOT_PARSE_CERT: Certificate file could not be parsed.
 *         - CERT_NOT_YET_VALID: Certificate is not yet valid (valid_from is in the future).
 *         - CERT_EXPIRES_SOON: Certificate will expire within the specified number of days.
 */
enum cert_check cert_currently_valid(const char *certfile, const time_t valid_for_at_least_days)
{
	// If no file was specified, we do not want to recreate it
	if(certfile == NULL)
		return CERT_FILE_NOT_FOUND;

	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);

	// Check if the file exists and is readable
	if(access(certfile, R_OK) != 0)
	{
		log_err("Could not read certificate file: %s", strerror(errno));
		return CERT_FILE_NOT_FOUND;
	}

	int rc = mbedtls_x509_crt_parse_file(&crt, certfile);
	if (rc != 0)
	{
		log_err("Cannot parse certificate: Error code %d", rc);
		return CERT_CANNOT_PARSE_CERT;
	}

	// Compare validity of certificate
	// - crt.valid_from needs to be in the past
	// - crt.valid_to should be further away than at least two days
	mbedtls_x509_time until = { 0 };
	mbedtls_x509_time_gmtime(mbedtls_time(NULL) + valid_for_at_least_days * (24 * 3600), &until);
	const bool is_valid_to = mbedtls_x509_time_cmp(&(crt.valid_to), &until) > 0;
	const bool is_valid_from = mbedtls_x509_time_is_past(&(crt.valid_from));

	// Free resources
	mbedtls_x509_crt_free(&crt);

	// Return result
	if(!is_valid_from)
		return CERT_NOT_YET_VALID;
	if(!is_valid_to)
		return CERT_EXPIRES_SOON;
	return CERT_OKAY;
}

bool is_pihole_certificate(const char *certfile)
{
	// Check if the file exists and is readable
	if(access(certfile, R_OK) != 0)
	{
		log_err("Could not read certificate file: %s", strerror(errno));
		return false;
	}

	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);

	int rc = mbedtls_x509_crt_parse_file(&crt, certfile);
	if (rc != 0)
	{
		log_err("Cannot parse certificate: Error code %d", rc);
		return false;
	}
	// Check if the issuer is "pi.hole"
	const bool is_pihole_issuer = strncasecmp((char*)crt.issuer.val.p, "pi.hole", crt.issuer.val.len) == 0;
	// Check if the subject is "pi.hole"
	const bool is_pihole_subject = strncasecmp((char*)crt.subject.val.p, "pi.hole", crt.subject.val.len) == 0;


	// Free resources
	mbedtls_x509_crt_free(&crt);

	return is_pihole_issuer && is_pihole_subject;
}

#else

enum cert_check read_certificate(const char* certfile, const char *domain, const bool private_key)
{
	log_err("FTL was not compiled with mbedtls support");
	return CERT_FILE_NOT_FOUND;
}

bool init_entropy(void)
{
	log_warn("FTL was not compiled with mbedtls support, fallback random number generator not available");
	return false;
}

void destroy_entropy(void)
{
}

ssize_t drbg_random(unsigned char *output, size_t len)
{
	log_warn("FTL was not compiled with mbedtls support, fallback random number generator not available");
	return -1;
}

#endif
