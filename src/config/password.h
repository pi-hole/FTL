/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config password prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef PASSWORD_H
#define PASSWORD_H
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

void sha256_raw_to_hex(uint8_t *data, char *buffer);
char *create_password(const char *password) __attribute__((malloc));
bool verify_password(const char *password, const char *pwhash);
int run_performance_test(void);

#endif //PASSWORD_H
