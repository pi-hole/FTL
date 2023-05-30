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

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

bool generate_certificate(const char* certfile, bool rsa);

#endif // X509_H
