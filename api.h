/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API commands and structures
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// Statistic methods
void getStats(int *sock);
void getOverTime(int *sock, char type);
void getTopDomains (char *client_message, int *sock, char type);
void getTopClients(char *client_message, int *sock, char type);
void getForwardDestinations(char *client_message, int *sock, char type);
void getQueryTypes(int *sock, char type);
void getAllQueries(char *client_message, int *sock, char type);
void getRecentBlocked(char *client_message, int *sock, char type);
void getForwardDestinationsOverTime(int *sock, char type);
void getQueryTypesOverTime(int *sock, char type);
void getClientsOverTime(int *sock);
void getClientNames(int *sock);

// FTL methods
void getMemoryUsage(int *sock, char type);
void getClientID(int *sock, char type);
void getVersion(int *sock, char type);
void getDBstats(int *sock, char type);
void getUnknownQueries(int *sock);

// DNS methods
void getList(int *sock, char type, char list_type);
void addList(int *sock, char type, char list_type, char *data);
void removeList(int *sock, char type, char list_type, char *client_message);
void getPiholeStatus(int *sock, char type);

// General API commands
bool matchesRegex(char *regex_expression, char *input);
bool isValidDomain(char *domain);

// MessagePack serialization helpers
void pack_eom(int sock);
void pack_int(int sock, int value);
void pack_float(int sock, float value);
void pack_unsigned_char(int sock, unsigned char value);
