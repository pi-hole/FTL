/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Environment-related prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef CONFIG_ENV_H
#define CONFIG_ENV_H

#include "FTL.h"
// union conf_value
#include "config.h"
// type toml_table_t
#include "tomlc99/toml.h"

#define FTLCONF_PREFIX "FTLCONF_"

int dist(const char *str);

void getEnvVars(void);
void freeEnvVars(void);
void printFTLenv(void);
bool readEnvValue(struct conf_item *conf_item, struct config *newconf);

#endif //CONFIG_ENV_H
