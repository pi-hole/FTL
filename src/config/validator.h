/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config validation routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef CONFIG_VALIDATOR_H
#define CONFIG_VALIDATOR_H

#include "FTL.h"
#include "config/config.h"

bool validate_stub(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]) __attribute__((const));
bool validate_dns_hosts(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);
bool validate_dns_cnames(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);
bool validate_cidr(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);
bool validate_ip_port(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);
bool validate_domain(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);
bool validate_filepath(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);
bool validate_filepath_empty(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);
bool validate_filepath_dash(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);
bool validate_regex_array(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);
bool validate_dns_revServers(union conf_value *val, const char *key, char err[VALIDATOR_ERRBUF_LEN]);

#endif // CONFIG_VALIDATOR_H
