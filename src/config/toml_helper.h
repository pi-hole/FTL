/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  TOML config writer prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef CONFIG_WRITER_H
#define CONFIG_WRITER_H

#include "../FTL.h"

FILE *openFTLtoml(const char *mode) __attribute((malloc)) __attribute((nonnull(1)));
void catTOMLsection(FILE *fp, const unsigned int indent, const char *key);
void catTOMLextrainfo(FILE *fp, const unsigned int indent, const char *infostr);
void catTOMLstring(FILE *fp, const unsigned int indent, const char *key, const char *description, const char *values, const char *val, const char *dptr);
void catTOMLbool(FILE *fp, const unsigned int indent, const char *key, const char *description, const bool val, const bool dval);
void catTOMLint(FILE *fp, const unsigned int indent, const char *key, const char *description, const int val, const int dval);
void catTOMLuint(FILE *fp, const unsigned int indent, const char *key, const char *description, const unsigned int val, const unsigned int dval);

#endif //CONFIG_WRITER_H
