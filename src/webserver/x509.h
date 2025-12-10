/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  X.509 certificate and randomness generator prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef X509_H
#define X509_H

#include "enums.h"
#include <stdbool.h>
// ssize_t
#include <unistd.h>
// time_t
#include <time.h>

bool generate_certificate(const char *certfile, bool rsa, const char *domain, const unsigned int validity_days);
enum cert_check read_certificate(const char *certfile, const char *domain, const bool private_key);
enum cert_check cert_currently_valid(const char *certfile, const time_t valid_for_at_least_days);
bool is_pihole_certificate(const char *certfile);

#endif // X509_H
