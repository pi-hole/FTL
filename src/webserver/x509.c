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
# ifndef MBEDTLS_MPI_INIT
# define MBEDTLS_MPI_INIT { 0, 1, 0 }
# endif
# include <mbedtls/x509_crt.h>
# include <mbedtls/pk.h>

// We enforce at least mbedTLS v3.5.0 if we use it
#if MBEDTLS_VERSION_NUMBER < 0x03050000
# error "mbedTLS version 3.5.0 or later is required"
#endif

#define RSA_KEY_SIZE 4096
#define EC_KEY_SIZE 384
#define BUFFER_SIZE 16000
#define PIHOLE_ISSUER "CN=pi.hole,O=Pi-hole,C=DE"

// Generate private RSA or EC key
static int generate_private_key(mbedtls_pk_context *pk_key, const bool rsa,
                                unsigned char key_buffer[])
{
	int ret;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	const psa_status_t status = psa_crypto_init();
	if(status != PSA_SUCCESS)
	{
		log_err("Failed to initialize PSA crypto, returned %d\n", (int)status);
		return CERT_CANNOT_PARSE_CERT;
	}
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_DECRYPT);
	psa_set_key_type(&attributes, rsa ? PSA_KEY_TYPE_RSA_KEY_PAIR : PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, rsa ? RSA_KEY_SIZE : EC_KEY_SIZE);

	// Generate key
	mbedtls_svc_key_id_t key = MBEDTLS_SVC_KEY_ID_INIT;
	if((ret = psa_generate_key(&attributes, &key)) != PSA_SUCCESS) {
		printf("ERROR: psa_generate_key failed: %d\n", ret);
		return ret;
	}

	// Copy key to mbedtls_pk_context
	if((ret = mbedtls_pk_copy_from_psa(key, pk_key)) != 0) {
		printf("ERROR: mbedtls_pk_copy_from_psa returned %d\n", ret);
		return ret;
	}

	// Destroy the key handle as we have copied the key
	psa_reset_key_attributes(&attributes);
	psa_destroy_key(key);

	// Export key in PEM format
	if ((ret = mbedtls_pk_write_key_pem(pk_key, key_buffer, BUFFER_SIZE)) != 0) {
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

	// Generate key
	printf("Generating %s key...\n", rsa ? "RSA" : "EC");
	if((ret = generate_private_key(&ca_key, rsa, ca_key_buffer)) != 0)
	{
		printf("ERROR: generate_private_key returned %d\n", ret);
		return false;
	}
	if((ret = generate_private_key(&server_key, rsa, key_buffer)) != 0)
	{
		printf("ERROR: generate_private_key returned %d\n", ret);
		return false;
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
	for(unsigned int i = 0; i < sizeof(serial1) - 1; i++)
		serial1[i] = '0' + (rand() % 10);
	serial1[sizeof(serial1) - 1] = '\0';
	for(unsigned int i = 0; i < sizeof(serial2) - 1; i++)
		serial2[i] = '0' + (rand() % 10);
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
	if((ret = mbedtls_x509write_crt_pem(&ca_cert, ca_buffer, sizeof(ca_buffer))) != 0)
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
	if((ret = mbedtls_x509write_crt_pem(&server_cert, cert_buffer, sizeof(cert_buffer))) != 0)
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

	log_info("Reading certificate from %s ...", certfile);

	// Check if the file exists and is readable
	if(access(certfile, R_OK) != 0)
	{
		log_err("Could not read certificate file: %s", strerror(errno));
		return CERT_FILE_NOT_FOUND;
	}

	const psa_status_t status = psa_crypto_init();
	if(status != PSA_SUCCESS)
	{
		log_err("Failed to initialize PSA crypto, returned %d\n", (int)status);
		return CERT_CANNOT_PARSE_CERT;
	}

	mbedtls_pk_context key;
	mbedtls_pk_init(&key);
	bool has_key = true;
	int rc = mbedtls_pk_parse_keyfile(&key, certfile, NULL);
	if (rc != 0)
	{
		log_info("No key found");
		has_key = false;
	}

	mbedtls_x509_crt crt;
	mbedtls_x509_crt_init(&crt);
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
	puts("Certificate (X.509):");
	puts(certinfo);

	if(!private_key || !has_key)
		goto end;

	psa_key_attributes_t key_attributes = PSA_KEY_ATTRIBUTES_INIT;
	mbedtls_pk_get_psa_attributes(&key, PSA_KEY_USAGE_DERIVE, &key_attributes);

	puts("Private key:");
	psa_key_type_t pk_type = psa_get_key_type(&key_attributes);
	printf("  ID: %u\n", psa_get_key_id(&key_attributes));
	const size_t key_bits = psa_get_key_bits(&key_attributes);
	printf("  Keysize: %zu bits\n", key_bits);
	printf("  Algorithm: %u\n", psa_get_key_algorithm(&key_attributes));
	printf("  Lifetime: %u\n", psa_get_key_lifetime(&key_attributes));
	if(PSA_KEY_TYPE_IS_RSA(pk_type))
	{
		printf("  Type: RSA (%s)\n\n", pk_type == PSA_KEY_TYPE_RSA_KEY_PAIR ? "key pair" : "public key only");
	}
	else if(PSA_KEY_TYPE_IS_ECC_KEY_PAIR(pk_type) || PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(pk_type))
	{
		printf("  Type: ECC (%s)\n", PSA_KEY_TYPE_IS_ECC_KEY_PAIR(pk_type) ? "key pair" : "public key only");
		const psa_ecc_family_t ecc_family = PSA_KEY_TYPE_ECC_GET_FAMILY(pk_type);
		switch(ecc_family)
		{
			case PSA_ECC_FAMILY_SECP_K1:
				printf("  Curvetype: SEC Koblitz curve over prime fields (secp%zuk1)\n", key_bits);
				break;
			case PSA_ECC_FAMILY_SECP_R1:
				printf("  Curvetype: SEC random curve over prime fields (secp%zur1)\n", key_bits);
				break;
			case PSA_ECC_FAMILY_SECP_R2:
				printf("  Curve family: secp%zur2 is obsolete and not supported\n", key_bits);
				break;
			case PSA_ECC_FAMILY_SECT_K1:
				printf("  Curvetype: SEC Koblitz curve over binary fields (sect%zuk1)\n", key_bits);
				break;
			case PSA_ECC_FAMILY_SECT_R1:
				printf("  Curvetype: SEC random curve over binary fields (sect%zur1)\n", key_bits);
				break;
			case PSA_ECC_FAMILY_SECT_R2:
				printf("  Curvetype: SEC additional random curve over binary fields (sect%zur2)\n", key_bits);
				break;
			case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
				printf("  Curvetype: Brainpool P random curve (brainpoolP%zur1)\n", key_bits);
				break;
			case PSA_ECC_FAMILY_MONTGOMERY:
				printf("  Curvetype: Montgomery curve (Curve%s)\n", key_bits == 255 ? "25519" : key_bits == 448 ? "448" : "Unknown");
				break;
			case PSA_ECC_FAMILY_TWISTED_EDWARDS:
				printf("  Curvetype: Twisted Edwards curve (Ed%s)\n", key_bits == 255 ? "25519" : key_bits == 448 ? "448" : "Unknown");
				break;
			default:
				puts("  Curvetype: Unknown");
				break;
		}
		puts("");
	}
	else if(PSA_KEY_TYPE_IS_DH(pk_type))
	{
		printf("  Type: Diffie-Hellman (%s)\n\n", PSA_KEY_TYPE_IS_DH_KEY_PAIR(pk_type) ? "key pair" : "public key only");
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

#endif
