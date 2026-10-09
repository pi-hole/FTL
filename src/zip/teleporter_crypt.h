/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Teleporter archive encryption
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef TELEPORTER_CRYPT_H
#define TELEPORTER_CRYPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TELEPORTER_ENC_EXT ".enc"
#define TELEPORTER_MAX_PASSWORD_LEN 1024

bool teleporter_is_encrypted(const uint8_t *data, const size_t size);
const char *teleporter_encrypt(const uint8_t *in, const size_t inlen, const char *password,
                               uint8_t **out, size_t *outlen);
const char *teleporter_decrypt(const uint8_t *in, const size_t inlen, const char *password,
                               uint8_t **out, size_t *outlen);
char *teleporter_read_password(const bool export);

#endif // TELEPORTER_CRYPT_H
