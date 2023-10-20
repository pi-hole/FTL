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
char verify_password(const char *password, const char *pwhash, const bool rate_limiting);
int run_performance_test(void);
bool set_and_check_password(struct conf_item *conf_item, const char *password);

enum password_result {
	PASSWORD_INCORRECT = 0,
	PASSWORD_CORRECT = 1,
	PASSWORD_RATE_LIMITED = -1
} __attribute__((packed));

// The maximum number of password attempts per second
#define MAX_PASSWORD_ATTEMPTS_PER_SECOND 3

#endif //PASSWORD_H
