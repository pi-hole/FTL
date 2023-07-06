/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  FTL CLI config file prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef CONFIG_CLI_H
#define CONFIG_CLI_H

int set_config_from_CLI(const char *key, const char *value);
int get_config_from_CLI(const char *key, const bool quiet);

#endif //CONFIG_CLI_H