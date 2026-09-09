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

#ifdef HAVE_TLS
# include <openssl/opensslv.h>
# include <openssl/bio.h>
# include <openssl/bn.h>
# include <openssl/evp.h>
# include <openssl/pem.h>
# include <openssl/x509.h>
# include <openssl/x509v3.h>
// open(), O_* flags for the atomic 0600 key-file creation
#include <fcntl.h>
// sha256 and base64, for the public-key pin the cluster peers compare
#include <nettle/sha2.h>
// NETTLE_VERSION_MAJOR
#include <nettle/version.h>
#include <nettle/base64.h>

// We enforce at least OpenSSL v3.0.0 if we use it (providers, EVP_PKEY_Q_keygen)
#if OPENSSL_VERSION_NUMBER < 0x30000000L
# error "OpenSSL version 3.0.0 or later is required"
#endif

#define RSA_KEY_SIZE 4096
#define EC_KEY_CURVE "P-384"
#define PIHOLE_ISSUER_CN "pi.hole"
#define PIHOLE_ISSUER_O "Pi-hole"
#define PIHOLE_ISSUER_C "DE"

// Read the pending data of a memory BIO into a freshly allocated,
// NUL-terminated string (caller frees). Returns NULL on error.
static char *bio_to_string(BIO *bio)
{
	char *data = NULL;
	const long len = BIO_get_mem_data(bio, &data);
	if(len < 0 || data == NULL)
		return NULL;

	char *out = calloc((size_t)len + 1, sizeof(char));
	if(out == NULL)
		return NULL;

	memcpy(out, data, (size_t)len);
	out[len] = '\0';
	return out;
}

// Serialize an X.509 certificate to a PEM string (caller frees)
static char *x509_to_pem(X509 *cert)
{
	BIO *bio = BIO_new(BIO_s_mem());
	if(bio == NULL)
		return NULL;

	char *pem = NULL;
	if(PEM_write_bio_X509(bio, cert) == 1)
		pem = bio_to_string(bio);

	BIO_free(bio);
	return pem;
}

// Serialize a private key to a PEM string (caller frees)
static char *pkey_to_pem(EVP_PKEY *key)
{
	BIO *bio = BIO_new(BIO_s_mem());
	if(bio == NULL)
		return NULL;

	char *pem = NULL;
	if(PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0, NULL, NULL) == 1)
		pem = bio_to_string(bio);

	BIO_free(bio);
	return pem;
}

// Generate a private RSA or EC key using the OpenSSL default provider
static EVP_PKEY *generate_private_key(const bool rsa)
{
	EVP_PKEY *pkey = rsa
		? EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)RSA_KEY_SIZE)
		: EVP_PKEY_Q_keygen(NULL, NULL, "EC", EC_KEY_CURVE);

	if(pkey == NULL)
		log_err("Failed to generate %s key", rsa ? "RSA" : "EC");

	return pkey;
}

// Set a distinguished name from its CN (required) plus optional O and C
static bool set_name(X509_NAME *name, const char *cn, const char *o, const char *c)
{
	if(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0) != 1 ||
	   (o != NULL && X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)o, -1, -1, 0) != 1) ||
	   (c != NULL && X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)c, -1, -1, 0) != 1))
	{
		log_err("Failed to set certificate distinguished name (CN=%s)", cn);
		return false;
	}
	return true;
}

// Add a configured X.509v3 extension to a certificate
static bool add_ext(X509 *cert, X509V3_CTX *ctx, int nid, const char *value)
{
	X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, ctx, nid, value);
	if(ex == NULL)
	{
		log_err("Failed to create X.509 extension (NID %d)", nid);
		return false;
	}

	const int added = X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	if(added != 1)
	{
		log_err("Failed to add X.509 extension (NID %d)", nid);
		return false;
	}
	return true;
}

// Assign a random, positive serial number to a certificate. Serials must be
// unique per issuer (RFC 5280); a random one keeps browsers from rejecting a
// freshly issued certificate as a duplicate of an earlier one.
static bool set_random_serial(X509 *cert)
{
	bool ok = false;
	BIGNUM *bn = BN_new();
	// 128 random bits (16 octets, positive) - comfortably above the CA/Browser
	// Forum minimum of 64 bits of entropy and well within the 20-octet limit.
	if(bn != NULL && BN_rand(bn, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) == 1)
	{
		// A serial number must be a positive, non-zero integer (RFC 5280).
		// Guard against the astronomically unlikely all-zero draw.
		if(BN_is_zero(bn))
			BN_one(bn);
		ok = BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(cert)) != NULL;
	}

	BN_free(bn);
	return ok;
}

// Create and sign an X.509 certificate.
//
// subject_key is embedded as the certificate's public key, issuer_key signs
// it. issuer_cert provides the authority key identifier (pass the certificate
// itself for a self-signed CA). san, when not NULL, is an OpenSSL SAN string
// such as "DNS:pi.hole,DNS:example.com".
static X509 *build_certificate(EVP_PKEY *subject_key, EVP_PKEY *issuer_key, X509 *issuer_cert,
                               X509_NAME *subject, X509_NAME *issuer, const bool is_ca,
                               const char *san, const long validity_secs)
{
	X509 *cert = X509_new();
	if(cert == NULL)
		return NULL;

	if(X509_set_version(cert, X509_VERSION_3) != 1 ||
	   !set_random_serial(cert) ||
	   X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL ||
	   X509_gmtime_adj(X509_getm_notAfter(cert), validity_secs) == NULL ||
	   X509_set_pubkey(cert, subject_key) != 1 ||
	   X509_set_subject_name(cert, subject) != 1 ||
	   X509_set_issuer_name(cert, issuer) != 1)
	{
		log_err("Failed to assemble certificate");
		X509_free(cert);
		return NULL;
	}

	// The issuer certificate (self for a CA) supplies the authority key
	// identifier; the order below matters as the AKI is derived from the
	// issuer's subject key identifier.
	X509V3_CTX ctx;
	memset(&ctx, 0, sizeof(ctx));
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, issuer_cert != NULL ? issuer_cert : cert, cert, NULL, NULL, 0);

	// CN is ignored when a SAN is present (RFC 2818) and RFC 3280 requires the
	// SAN, so add it alongside the CN set above.
	// A leaf needs extendedKeyUsage=serverAuth or Apple clients (iOS 13+, macOS
	// 10.15+) reject it even under a privately-trusted root; set keyUsage too.
	if(!add_ext(cert, &ctx, NID_basic_constraints, is_ca ? "critical,CA:TRUE" : "critical,CA:FALSE") ||
	   !add_ext(cert, &ctx, NID_key_usage, is_ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature,keyEncipherment") ||
	   !add_ext(cert, &ctx, NID_subject_key_identifier, "hash") ||
	   !add_ext(cert, &ctx, NID_authority_key_identifier, "keyid:always") ||
	   (!is_ca && !add_ext(cert, &ctx, NID_ext_key_usage, "serverAuth")) ||
	   (san != NULL && !add_ext(cert, &ctx, NID_subject_alt_name, san)))
	{
		X509_free(cert);
		return NULL;
	}

	if(X509_sign(cert, issuer_key, EVP_sha256()) == 0)
	{
		log_err("Failed to sign certificate");
		X509_free(cert);
		return NULL;
	}

	return cert;
}

// Write a key and/or certificate to a file
static bool write_to_file(const char *filename, const char *type, const char *suffix, const char *cert, const char *key, const char *cacert)
{
	// Build the target file name (filename with an optional suffix replacing a
	// trailing ".pem")
	char *targetname = calloc(strlen(filename) + (suffix != NULL ? strlen(suffix) : 0) + 1, sizeof(char));
	if(targetname == NULL)
	{
		printf("ERROR: Could not allocate memory for file name\n");
		return false;
	}
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

	// Write to a temporary file next to the target and rename it into place at
	// the end. This way a partial or failed write (e.g. disk full during the
	// automatic renewal) never truncates or corrupts a certificate file that
	// is currently in use by the running web server.
	char *tempname = calloc(strlen(targetname) + sizeof(".tmp"), sizeof(char));
	if(tempname == NULL)
	{
		printf("ERROR: Could not allocate memory for file name\n");
		free(targetname);
		return false;
	}
	strcpy(tempname, targetname);
	strcat(tempname, ".tmp");

	printf("Storing %s in %s ...\n", type, targetname);
	// open() with 0600 creates the temp file atomically (no group/world-readable
	// window like fopen()+fchmod()). O_EXCL after unlink() means we create it
	// ourselves; O_NOFOLLOW refuses to write through a planted symlink.
	unlink(tempname); // best-effort: clear a stale .tmp or a planted decoy
	const int fd = open(tempname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR);
	if(fd < 0)
	{
		printf("ERROR: Could not open %s for writing: %s\n", tempname, strerror(errno));
		free(targetname);
		free(tempname);
		return false;
	}
	FILE *f = fdopen(fd, "wb");
	if(f == NULL)
	{
		printf("ERROR: Could not open %s for writing: %s\n", tempname, strerror(errno));
		close(fd);
		unlink(tempname); // do not leave the freshly-created 0600 file behind
		free(targetname);
		free(tempname);
		return false;
	}

	// Pin permissions to owner read/write only (open() already created it 0600,
	// but a restrictive umask could have trimmed it further)
	if(fchmod(fileno(f), S_IRUSR | S_IWUSR) != 0)
		log_warn("Unable to set permissions on file \"%s\": %s", tempname, strerror(errno));

	// Write the key, certificate and CA certificate in this order (whichever
	// are provided)
	bool ok = true;
	const char *parts[3] = { key, cert, cacert };
	for(unsigned int i = 0; ok && i < sizeof(parts) / sizeof(parts[0]); i++)
	{
		if(parts[i] == NULL)
			continue;
		const size_t olen = strlen(parts[i]);
		if(fwrite(parts[i], 1, olen, f) != olen)
		{
			printf("ERROR: Could not write to %s\n", tempname);
			ok = false;
		}
	}

	// Flush and fsync before the rename so a crash mid-renewal leaves either the
	// complete new file or the untouched old one, never a truncated certificate.
	if(ok && (fflush(f) != 0 || fsync(fileno(f)) != 0))
	{
		printf("ERROR: Could not flush %s to disk\n", tempname);
		ok = false;
	}
	// fclose() always runs (closing the descriptor on every path); a close
	// failure is only treated as fatal if the data was otherwise written
	// successfully.
	const bool close_failed = (fclose(f) != 0);
	if(close_failed && ok)
	{
		printf("ERROR: Could not finalize %s\n", tempname);
		ok = false;
	}

	// Atomically move the completed file into place, or discard it on error so
	// the previous (still valid) file is left untouched
	if(ok && rename(tempname, targetname) != 0)
	{
		printf("ERROR: Could not rename %s to %s\n", tempname, targetname);
		ok = false;
	}
	if(!ok)
		unlink(tempname);

	free(targetname);
	free(tempname);

	return ok;
}

bool generate_certificate(const char* certfile, bool rsa, const char *domain, const unsigned int validity_days)
{
	bool success = false;
	EVP_PKEY *ca_key = NULL, *server_key = NULL;
	X509 *ca_cert = NULL, *server_cert = NULL;
	X509_NAME *ca_name = NULL, *server_name = NULL;
	char *san = NULL, *ca_pem = NULL, *cert_pem = NULL, *key_pem = NULL;

	// Reject domains containing characters that would break the subject and
	// SAN config syntax. A comma or whitespace could otherwise inject
	// additional SAN entries or produce an invalid certificate.
	for(const char *p = domain; *p != '\0'; p++)
	{
		if(*p == ',' || *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
		{
			log_err("Invalid character in domain \"%s\"", domain);
			return false;
		}
	}

	// Generate keys
	printf("Generating %s key...\n", rsa ? "RSA" : "EC");
	ca_key = generate_private_key(rsa);
	server_key = generate_private_key(rsa);
	if(ca_key == NULL || server_key == NULL)
		goto cleanup;

	// Validity period: valid from now until now + validity_days. If no
	// validity is specified, use 30 years.
	const long validity_secs = (validity_days > 0 ? (long)validity_days : 30L * 365L) * 24L * 3600L;

	// Distinguished names: CA is "CN=pi.hole,O=Pi-hole,C=DE", the server
	// certificate uses the (optionally custom) domain as its CN.
	ca_name = X509_NAME_new();
	server_name = X509_NAME_new();
	if(ca_name == NULL || server_name == NULL)
		goto cleanup;
	if(!set_name(ca_name, PIHOLE_ISSUER_CN, PIHOLE_ISSUER_O, PIHOLE_ISSUER_C) ||
	   !set_name(server_name, domain, NULL, NULL))
		goto cleanup;

	// 1. Create self-signed CA certificate
	printf("Generating new CA...\n");
	ca_cert = build_certificate(ca_key, ca_key, NULL, ca_name, ca_name, true, NULL, validity_secs);
	if(ca_cert == NULL)
		goto cleanup;

	// Add "DNS:pi.hole" as subject alternative name (SAN), plus the custom
	// domain (when used) to make the certificate more universal.
	if(strcasecmp(domain, "pi.hole") == 0)
		san = strdup("DNS:pi.hole");
	else
	{
		const size_t len = strlen("DNS:pi.hole,DNS:") + strlen(domain) + 1;
		san = calloc(len, sizeof(char));
		if(san != NULL)
			snprintf(san, len, "DNS:pi.hole,DNS:%s", domain);
	}
	if(san == NULL)
		goto cleanup;

	// 2. Create server certificate signed by the CA
	printf("Generating new server certificate...\n");
	server_cert = build_certificate(server_key, ca_key, ca_cert, server_name, ca_name, false, san, validity_secs);
	if(server_cert == NULL)
		goto cleanup;

	// Export everything to PEM
	ca_pem = x509_to_pem(ca_cert);
	cert_pem = x509_to_pem(server_cert);
	key_pem = pkey_to_pem(server_key);
	if(ca_pem == NULL || cert_pem == NULL || key_pem == NULL)
	{
		printf("ERROR: Could not serialize certificate to PEM\n");
		goto cleanup;
	}

	// Write the CA certificate, the server certificate, and the combined
	// server key + certificate; fail if any of the writes fails.
	if(!write_to_file(certfile, "CA certificate", "_ca.crt", ca_pem, NULL, NULL) ||
	   !write_to_file(certfile, "server certificate", ".crt", cert_pem, NULL, NULL) ||
	   !write_to_file(certfile, "server key + certificate", NULL, cert_pem, key_pem, ca_pem))
		goto cleanup;

	success = true;

cleanup:
	free(san);
	free(ca_pem);
	free(cert_pem);
	// Scrub the plaintext private key from the heap before releasing it; the cert
	// and CA are public, but this key copy should not linger in freed memory.
	if(key_pem != NULL)
		OPENSSL_cleanse(key_pem, strlen(key_pem));
	free(key_pem);
	X509_free(ca_cert);
	X509_free(server_cert);
	X509_NAME_free(ca_name);
	X509_NAME_free(server_name);
	EVP_PKEY_free(ca_key);
	EVP_PKEY_free(server_key);

	return success;
}

static bool check_wildcard_domain(const char *domain, const char *san, const size_t san_len)
{
	// A leading "*." wildcard matches exactly one left-most label (RFC 6125):
	// "*.pi-hole.net" covers "abc.pi-hole.net" but not "a.b.pi-hole.net" or the
	// bare "pi-hole.net". Mirrors OpenSSL's X509_check_host() rules.
	if(san_len < 2 || san[0] != '*' || san[1] != '.')
		return false;

	// The wildcard tail is everything after '*' (e.g. ".pi-hole.net"); the domain
	// must end with it plus the one label replacing '*'. The SAN is not
	// NUL-terminated, so use the length field.
	const char *tail = san + 1;
	const size_t tail_len = san_len - 1;
	const size_t domain_len = strlen(domain);
	if(domain_len <= tail_len)
		return false;

	// The replacing label may not itself span multiple labels, i.e. the part of
	// the domain before the tail must contain no dot.
	const size_t label_len = domain_len - tail_len;
	if(memchr(domain, '.', label_len) != NULL)
		return false;

	return strncasecmp(domain + label_len, tail, tail_len) == 0;
}

// Copy the first Common Name (CN) of an X.509 name into buf as a NUL-terminated
// string, returning its length or -1 if there is none (or it does not fit).
// Replaces the convenience X509_NAME_get_text_by_NID(), deprecated in OpenSSL
// 4.0, with the plain, non-deprecated entry accessors.
static int get_common_name(const X509_NAME *name, char *buf, size_t buflen)
{
	if(buflen == 0)
		return -1;
	buf[0] = '\0';
	const int idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
	if(idx < 0)
		return -1;
	const X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
	const ASN1_STRING *data = entry != NULL ? X509_NAME_ENTRY_get_data(entry) : NULL;
	if(data == NULL)
		return -1;
	const int len = ASN1_STRING_length(data);
	const unsigned char *txt = ASN1_STRING_get0_data(data);
	if(txt == NULL || len < 0 || (size_t)len >= buflen)
		return -1;
	memcpy(buf, txt, (size_t)len);
	buf[len] = '\0';
	return len;
}

// Check whether the given domain is covered by the certificate, either through
// one of its subject alternative names (SAN) or, as a fallback, its CN.
static bool search_domain(X509 *crt, const char *domain)
{
	bool found = false;

	// Loop over all subject alternative names (SANs)
	GENERAL_NAMES *sans = X509_get_ext_d2i(crt, NID_subject_alt_name, NULL, NULL);
	if(sans != NULL)
	{
		const int count = sk_GENERAL_NAME_num(sans);
		for(int i = 0; i < count && !found; i++)
		{
			const GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);

			// Only DNS names are of interest here
			if(gn == NULL || gn->type != GEN_DNS)
				continue;

			// Attention: The SAN is not NUL-terminated, so we need
			//            to use the length field
			const char *name = (const char *)ASN1_STRING_get0_data(gn->d.dNSName);
			const size_t len = (size_t)ASN1_STRING_length(gn->d.dNSName);

			if(strlen(domain) == len && strncasecmp(domain, name, len) == 0)
				found = true;
			else if(check_wildcard_domain(domain, name, len))
				found = true;
		}
		GENERAL_NAMES_free(sans);
	}

	if(found)
		return true;

	// Also check against the common name (CN) field
	char cn[256] = { 0 };
	const int cn_len = get_common_name(X509_get_subject_name(crt), cn, sizeof(cn));
	if(cn_len > 0)
	{
		// cn is NUL-terminated by get_common_name(); use strlen() as the length
		// so a CN longer than the buffer cannot lead to an out-of-bounds read
		// regardless of the returned length
		if(strcasecmp(domain, cn) == 0)
			found = true;
		else if(check_wildcard_domain(domain, cn, strlen(cn)))
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
	if(certfile == NULL)
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

	// Load the certificate
	X509 *crt = NULL;
	BIO *bio = BIO_new_file(certfile, "r");
	if(bio != NULL)
	{
		crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}
	if(crt == NULL)
	{
		log_err("Cannot parse certificate");
		return CERT_CANNOT_PARSE_CERT;
	}

	// Load the private key (if any) from a fresh handle on the same file
	EVP_PKEY *key = NULL;
	BIO *kbio = BIO_new_file(certfile, "r");
	if(kbio != NULL)
	{
		key = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
		BIO_free(kbio);
	}
	const bool has_key = key != NULL;
	if(!has_key)
		log_info("No key found");

	// When a domain is specified, only check the domain and return
	if(domain != NULL)
	{
		const enum cert_check result = search_domain(crt, domain) ? CERT_DOMAIN_MATCH : CERT_DOMAIN_MISMATCH;
		X509_free(crt);
		if(key != NULL)
			EVP_PKEY_free(key);
		return result;
	}

	// else: Print verbose information about the certificate
	BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
	if(out == NULL)
	{
		log_err("Cannot allocate output stream for certificate");
		X509_free(crt);
		if(key != NULL)
			EVP_PKEY_free(key);
		return CERT_CANNOT_PARSE_CERT;
	}
	puts("Certificate (X.509):");
	X509_print(out, crt);

	// Print private key information (if requested and available)
	if(private_key && has_key)
	{
		puts("Private key:");
		EVP_PKEY_print_private(out, key, 2, NULL);
		puts("\nPrivate key (PEM):");
		PEM_write_bio_PrivateKey(out, key, NULL, NULL, 0, NULL, NULL);
	}

	// Print public key in PEM format (taken from the certificate)
	puts("Public key (PEM):");
	EVP_PKEY *pub = X509_get_pubkey(crt);
	if(pub != NULL)
	{
		PEM_write_bio_PUBKEY(out, pub);
		EVP_PKEY_free(pub);
	}

	BIO_free(out);
	X509_free(crt);
	if(key != NULL)
		EVP_PKEY_free(key);

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

	// Check if the file exists and is readable
	if(access(certfile, R_OK) != 0)
	{
		log_err("Could not read certificate file: %s", strerror(errno));
		return CERT_FILE_NOT_FOUND;
	}

	X509 *crt = NULL;
	BIO *bio = BIO_new_file(certfile, "r");
	if(bio != NULL)
	{
		crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}
	if(crt == NULL)
	{
		log_err("Cannot parse certificate");
		return CERT_CANNOT_PARSE_CERT;
	}

	// Validity check via ASN1_TIME_cmp_time_t() (X509_cmp_time() is deprecated in
	// OpenSSL 4.0): notBefore must be in the past, notAfter beyond `future`. A
	// compare error (-2) matches neither, so it fails closed.
	const time_t future = time(NULL) + valid_for_at_least_days * (24 * 3600);
	const bool is_valid_from = ASN1_TIME_cmp_time_t(X509_get0_notBefore(crt), time(NULL)) == -1;
	const bool is_valid_to = ASN1_TIME_cmp_time_t(X509_get0_notAfter(crt), future) == 1;

	// Free resources
	X509_free(crt);

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

	X509 *crt = NULL;
	BIO *bio = BIO_new_file(certfile, "r");
	if(bio != NULL)
	{
		crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}
	if(crt == NULL)
	{
		log_err("Cannot parse certificate");
		return false;
	}

	// Check if both the issuer and subject common name are "pi.hole"
	char issuer_cn[256] = { 0 };
	char subject_cn[256] = { 0 };
	get_common_name(X509_get_issuer_name(crt), issuer_cn, sizeof(issuer_cn));
	get_common_name(X509_get_subject_name(crt), subject_cn, sizeof(subject_cn));

	// Free resources
	X509_free(crt);

	return strcasecmp(issuer_cn, "pi.hole") == 0 && strcasecmp(subject_cn, "pi.hole") == 0;
}

// What a peer compares this node's certificate against: the SHA-256 of the
// public key in its DER form, base64-encoded. This is the value behind curl's
// "sha256//..." pin, and it survives a certificate being reissued for the same
// key
bool certificate_pin(const char *certfile, char *out, const size_t outlen)
{
	X509 *crt = NULL;
	BIO *bio = BIO_new_file(certfile, "r");
	if(bio != NULL)
	{
		crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
		BIO_free(bio);
	}
	if(crt == NULL)
	{
		log_debug(DEBUG_ANY, "Cannot read a certificate from %s", certfile);
		return false;
	}

	// The public key alone, in the encoding a pin is taken over
	unsigned char *der = NULL;
	EVP_PKEY *key = X509_get_pubkey(crt);
	const int len = key != NULL ? i2d_PUBKEY(key, &der) : -1;
	EVP_PKEY_free(key);
	X509_free(crt);

	if(len <= 0 || der == NULL)
	{
		log_debug(DEBUG_ANY, "Cannot read the public key of %s", certfile);
		OPENSSL_free(der);
		return false;
	}

	uint8_t digest[SHA256_DIGEST_SIZE];
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (size_t)len, der);
#if NETTLE_VERSION_MAJOR >= 4
	sha256_digest(&ctx, digest);
#else
	sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);
#endif
	OPENSSL_free(der);

	// Base64 of the raw digest, which is what curl expects after "sha256//"
	struct base64_encode_ctx b64;
	char encoded[BASE64_ENCODE_LENGTH(SHA256_DIGEST_SIZE) + BASE64_ENCODE_FINAL_LENGTH + 1] = { 0 };
	base64_encode_init(&b64);
	size_t written = base64_encode_update(&b64, encoded, SHA256_DIGEST_SIZE, digest);
	written += base64_encode_final(&b64, encoded + written);
	encoded[written] = '\0';

	if(written >= outlen)
		return false;

	memcpy(out, encoded, written + 1);

	return true;
}

#else

enum cert_check read_certificate(const char* certfile, const char *domain, const bool private_key)
{
	log_err("FTL was not compiled with TLS support");
	return CERT_FILE_NOT_FOUND;
}

bool certificate_pin(const char *certfile, char *out, const size_t outlen)
{
	return false;
}

#endif
