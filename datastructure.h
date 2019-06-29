/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Datastructure prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef DATASTRUCTURE_H
#define DATASTRUCTURE_H

void strtolower(char *str);
int findForwardID(const char * forward, const bool count);
int findDomainID(const char *domain);
int findClientID(const char *client, const bool count);
bool isValidIPv4(const char *addr);
bool isValidIPv6(const char *addr);
const char *getDomainString(const int queryID);
const char *getClientIPString(const int queryID);
const char *getClientNameString(const int queryID);

#endif //DATASTRUCTURE_H
