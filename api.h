/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API commands
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// Endpoints under /stats/
void getStats(int *sock, char type);
void getOverTime(int *sock, char type);
void getTopDomains (char *client_message, int *sock, char type);
void getTopClients(char *client_message, int *sock, char type);
void getForwardDestinations(char *client_message, int *sock, char type);

void getQueryTypes(int *sock, char type);
void getAllQueries(char *client_message, int *sock, char type);
void getRecentBlocked(char *client_message, int *sock, char type);
void getMemoryUsage(int *sock, char type);
void getForwardDestinationsOverTime(int *sock, char type);
void getClientID(int *sock, char type);
void getQueryTypesOverTime(int *sock, char type);
void getVersion(int *sock, char type);
void getDBstats(int *sock, char type);
void getClientsOverTime(int *sock);
void getClientNames(int *sock);

// Endpoints under /dns/
void getList(int *sock, char type, char list_type);
void addList(int *sock, char type, char list_type, char *data);
void removeList(int *sock, char type, char list_type, char *client_message);
void getPiholeStatus(int *sock, char type);

// HTTP Response Codes
enum { OK, BAD_REQUEST, INTERNAL_ERROR, NOT_FOUND };

// General API commands
char* getPayload(char *http_message);
void sendAPIResponse(int sock, char type, char http_code);
bool matchesRegex(char *regex_expression, char *input);
bool isValidDomain(char *domain);
