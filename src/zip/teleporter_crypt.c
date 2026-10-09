/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Teleporter archive encryption
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "zip/teleporter_crypt.h"
// get_secure_randomness()
#include "config/config.h"
#include "config/password.h"
#include <poll.h>
#include <termios.h>
#include <nettle/balloon.h>
#include <nettle/gcm.h>
#include <nettle/memops.h>
#include <nettle/sha2.h>

// Encrypted archive layout, all integers big-endian:
//   magic[8] | version | kdf | cipher | reserved | s_cost (4) | t_cost (4) |
//   salt[16] | nonce[12] | ciphertext | tag[16]
// The whole header is authenticated as associated data
#define ENC_MAGIC "PIHOLETP"
#define ENC_MAGIC_LEN 8
#define ENC_VERSION 1
#define ENC_KDF_BALLOON_SHA256 1
#define ENC_CIPHER_AES256_GCM 1
#define ENC_SALT_LEN 16
#define ENC_NONCE_LEN GCM_IV_SIZE
#define ENC_TAG_LEN GCM_DIGEST_SIZE
#define ENC_HEADER_LEN (ENC_MAGIC_LEN + 4 + 4 + 4 + ENC_SALT_LEN + ENC_NONCE_LEN)

// 2 MiB of working memory, about 0.2 s on a desktop CPU and a few seconds on
// a Pi Zero. Archives store their own costs, the limits below bound what an
// uploaded file can make us spend on key derivation
#define ENC_S_COST 65536u
#define ENC_T_COST 3u
#define ENC_MAX_S_COST (1u << 18)
#define ENC_MAX_T_COST 16u

#define STDIN_TIMEOUT_MS 3000

static void put_u32(uint8_t *p, const uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get_u32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

bool teleporter_is_encrypted(const uint8_t *data, const size_t size)
{
	return data != NULL && size >= ENC_MAGIC_LEN && memcmp(data, ENC_MAGIC, ENC_MAGIC_LEN) == 0;
}

static bool derive_key(const char *password, const uint8_t *salt,
                       const uint32_t s_cost, const uint32_t t_cost,
                       uint8_t key[SHA256_DIGEST_SIZE])
{
	uint8_t *scratch = calloc(balloon_itch(SHA256_DIGEST_SIZE, s_cost), sizeof(uint8_t));
	if(scratch == NULL)
		return false;

	balloon_sha256(s_cost, t_cost, strlen(password), (const uint8_t *)password,
	               ENC_SALT_LEN, salt, scratch, key);

	explicit_bzero(scratch, balloon_itch(SHA256_DIGEST_SIZE, s_cost));
	free(scratch);
	return true;
}

const char *teleporter_encrypt(const uint8_t *in, const size_t inlen, const char *password,
                               uint8_t **out, size_t *outlen)
{
	if(password == NULL || password[0] == '\0')
		return "Password must not be empty";

	const size_t total = ENC_HEADER_LEN + inlen + ENC_TAG_LEN;
	uint8_t *buf = calloc(total, sizeof(uint8_t));
	if(buf == NULL)
		return "Failed to allocate memory for encrypted archive";

	// Header
	memcpy(buf, ENC_MAGIC, ENC_MAGIC_LEN);
	uint8_t *p = buf + ENC_MAGIC_LEN;
	*p++ = ENC_VERSION;
	*p++ = ENC_KDF_BALLOON_SHA256;
	*p++ = ENC_CIPHER_AES256_GCM;
	*p++ = 0;
	put_u32(p, ENC_S_COST); p += 4;
	put_u32(p, ENC_T_COST); p += 4;
	uint8_t *salt = p; p += ENC_SALT_LEN;
	uint8_t *nonce = p;
	if(!get_secure_randomness(salt, ENC_SALT_LEN + ENC_NONCE_LEN))
	{
		free(buf);
		return "Failed to generate random salt and nonce";
	}

	uint8_t key[SHA256_DIGEST_SIZE];
	if(!derive_key(password, salt, ENC_S_COST, ENC_T_COST, key))
	{
		free(buf);
		return "Failed to allocate memory for key derivation";
	}

	struct gcm_aes256_ctx ctx;
	gcm_aes256_set_key(&ctx, key);
	gcm_aes256_set_iv(&ctx, ENC_NONCE_LEN, nonce);
	gcm_aes256_update(&ctx, ENC_HEADER_LEN, buf);
	gcm_aes256_encrypt(&ctx, inlen, buf + ENC_HEADER_LEN, in);
	gcm_aes256_digest(&ctx, ENC_TAG_LEN, buf + ENC_HEADER_LEN + inlen);
	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(key, sizeof(key));

	*out = buf;
	*outlen = total;
	return NULL;
}

const char *teleporter_decrypt(const uint8_t *in, const size_t inlen, const char *password,
                               uint8_t **out, size_t *outlen)
{
	if(!teleporter_is_encrypted(in, inlen) || inlen < ENC_HEADER_LEN + ENC_TAG_LEN)
		return "Not an encrypted Teleporter archive";
	if(password == NULL || password[0] == '\0')
		return "This Teleporter archive is password-protected, a password is required";

	const uint8_t *p = in + ENC_MAGIC_LEN;
	const uint8_t version = *p++;
	const uint8_t kdf = *p++;
	const uint8_t cipher = *p++;
	p++; // reserved
	if(version != ENC_VERSION || kdf != ENC_KDF_BALLOON_SHA256 || cipher != ENC_CIPHER_AES256_GCM)
		return "Unsupported encrypted Teleporter archive version";

	const uint32_t s_cost = get_u32(p); p += 4;
	const uint32_t t_cost = get_u32(p); p += 4;
	if(s_cost == 0 || s_cost > ENC_MAX_S_COST || t_cost == 0 || t_cost > ENC_MAX_T_COST)
		return "Invalid key derivation parameters in encrypted Teleporter archive";
	const uint8_t *salt = p; p += ENC_SALT_LEN;
	const uint8_t *nonce = p;

	const size_t clen = inlen - ENC_HEADER_LEN - ENC_TAG_LEN;
	// Allocate at least one byte so an empty plaintext is not mistaken for
	// an allocation failure
	uint8_t *buf = calloc(clen > 0 ? clen : 1, sizeof(uint8_t));
	if(buf == NULL)
		return "Failed to allocate memory for decrypted archive";

	uint8_t key[SHA256_DIGEST_SIZE];
	if(!derive_key(password, salt, s_cost, t_cost, key))
	{
		free(buf);
		return "Failed to allocate memory for key derivation";
	}

	uint8_t tag[ENC_TAG_LEN];
	struct gcm_aes256_ctx ctx;
	gcm_aes256_set_key(&ctx, key);
	gcm_aes256_set_iv(&ctx, ENC_NONCE_LEN, nonce);
	gcm_aes256_update(&ctx, ENC_HEADER_LEN, in);
	gcm_aes256_decrypt(&ctx, clen, buf, in + ENC_HEADER_LEN);
	gcm_aes256_digest(&ctx, ENC_TAG_LEN, tag);
	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(key, sizeof(key));

	// A wrong password and a modified file are indistinguishable here
	if(!memeql_sec(tag, in + inlen - ENC_TAG_LEN, ENC_TAG_LEN))
	{
		explicit_bzero(buf, clen);
		free(buf);
		return "Wrong password or corrupted archive";
	}

	*out = buf;
	*outlen = clen;
	return NULL;
}

static char *read_line(const char *prompt)
{
	const bool tty = isatty(STDIN_FILENO);
	struct termios old, noecho;
	if(tty)
	{
		// Never read a password with echo on or restore a state we did not get
		if(tcgetattr(STDIN_FILENO, &old) != 0)
		{
			fprintf(stderr, "Error: Cannot read terminal settings: %s\n", strerror(errno));
			return NULL;
		}
		noecho = old;
		noecho.c_lflag &= ~(tcflag_t)ECHO;
		if(tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho) != 0)
		{
			fprintf(stderr, "Error: Cannot disable terminal echo: %s\n", strerror(errno));
			return NULL;
		}
		fputs(prompt, stderr);
		fflush(stderr);
	}
	else
	{
		// An inherited stdin nobody writes to (ssh without -n, a
		// supervisor's pipe, ...) must not block a script forever
		struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
		int rc;
		do {
			rc = poll(&pfd, 1, STDIN_TIMEOUT_MS);
		} while(rc < 0 && errno == EINTR);
		if(rc == 0)
		{
			fprintf(stderr, "Warning: No password received on stdin within %d s, assuming none\n",
			        STDIN_TIMEOUT_MS / 1000);
			return strdup("");
		}
	}

	char buf[TELEPORTER_MAX_PASSWORD_LEN + 2];
	const bool ok = fgets(buf, sizeof(buf), stdin) != NULL;

	if(tty)
	{
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
		fputc('\n', stderr);
	}
	// EOF counts as an empty line, e.g., stdin redirected from /dev/null
	if(!ok)
		return strdup("");

	size_t len = strlen(buf);
	while(len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r'))
		buf[--len] = '\0';
	if(len > TELEPORTER_MAX_PASSWORD_LEN)
	{
		explicit_bzero(buf, sizeof(buf));
		fprintf(stderr, "Error: Password too long (max %d bytes)\n", TELEPORTER_MAX_PASSWORD_LEN);
		return NULL;
	}

	char *pw = strdup(buf);
	explicit_bzero(buf, sizeof(buf));
	return pw;
}

// Prompt without echo on a terminal, otherwise read one line from stdin so
// scripts can pipe the password in without exposing it in argv. On export, an
// empty password means no encryption
char *teleporter_read_password(const bool export)
{
	char *pw = read_line(export ? "Teleporter password (empty for none): " : "Teleporter password: ");
	if(pw == NULL || (pw[0] == '\0' && export))
		return pw;
	if(pw[0] == '\0')
	{
		fprintf(stderr, "Error: This Teleporter archive is password-protected, a password is required\n");
		free(pw);
		return NULL;
	}

	if(export && isatty(STDIN_FILENO))
	{
		char *pw2 = read_line("Repeat password: ");
		const bool match = pw2 != NULL && strcmp(pw, pw2) == 0;
		if(pw2 != NULL)
		{
			explicit_bzero(pw2, strlen(pw2));
			free(pw2);
		}
		if(!match)
		{
			fprintf(stderr, "Error: Passwords do not match\n");
			explicit_bzero(pw, strlen(pw));
			free(pw);
			return NULL;
		}
	}

	return pw;
}
