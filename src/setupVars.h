/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL.conf processing prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef SETUPVARS_H
#define SETUPVARS_H

void check_setupVarsconf(void);
char * read_setupVarsconf(const char * key);
void getSetupVarsArray(const char * input);
void clearSetupVarsArray(void);
bool insetupVarsArray(const char * str);
bool getSetupVarsBool(const char * input) __attribute__((pure));
char* find_equals(const char* s) __attribute__((pure));
void trim_whitespace(char *string);
void check_blocking_status(void);
bool get_blockingstatus(void) __attribute__((pure));
void set_blockingstatus(bool enabled);
char *get_password_hash(void) __attribute__((malloc));

#endif //SETUPVARS_H
