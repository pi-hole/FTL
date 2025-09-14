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

#include "FTL.h"
// union conf_value
#include "config.h"
// type toml_result_t
#include "tomlc17/tomlc17.h"

void indentTOML(FILE *fp, const unsigned int indent);
FILE *openFTLtoml(const char *mode, const unsigned int version, bool *locked) __attribute((malloc)) __attribute((nonnull(1)));
void closeFTLtoml(FILE *fp, const bool locked);
void print_comment(FILE *fp, const char *str, const char *intro, const unsigned int width, const unsigned int indent);
void print_toml_allowed_values(const cJSON *allowed_values, FILE *fp, const unsigned int indent);
void writeTOMLvalue(FILE * fp, const int indent, const enum conf_type t, union conf_value *v);
void readTOMLvalue(struct conf_item *conf_item, const char* key, toml_datum_t toml, struct config *newconf);

#endif //CONFIG_WRITER_H
