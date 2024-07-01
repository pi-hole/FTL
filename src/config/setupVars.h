/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  setupVars.conf processing prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef SETUPVARS_H
#define SETUPVARS_H

void importsetupVarsConf(void);
char *read_setupVarsconf(const char * key);
void getSetupVarsArray(const char * input);
void clearSetupVarsArray(void);
bool getSetupVarsBool(const char * input) __attribute__((pure));
char *find_equals(char* s) __attribute__((pure));
void trim_whitespace(char *string);

#endif //SETUPVARS_H
