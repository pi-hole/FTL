/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  API commands and MessagePack helpers
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// Statistic methods
void getStats(int *sock);
void getOverTime(int *sock);
void getTopDomains(char *client_message, int *sock);
void getTopClients(char *client_message, int *sock);
void getForwardDestinations(char *client_message, int *sock);
void getQueryTypes(int *sock);
void getAllQueries(char *client_message, int *sock);
void getRecentBlocked(char *client_message, int *sock);
void getQueryTypesOverTime(int *sock);
void getClientsOverTime(int *sock);
void getClientNames(int *sock);
void getDomainDetails(char *client_message, int *sock);

// FTL methods
void getClientID(int *sock);
void getVersion(int *sock);
void getDBstats(int *sock);
void getUnknownQueries(int *sock);

// DNS resolver methods (dnsmasq_interface.c)
void getCacheInformation(int *sock);

// MessagePack serialization helpers
void pack_eom(int sock);
void pack_bool(int sock, bool value);
void pack_uint8(int sock, uint8_t value);
void pack_uint64(int sock, uint64_t value);
void pack_int32(int sock, int32_t value);
void pack_int64(int sock, int64_t value);
void pack_float(int sock, float value);
bool pack_fixstr(int sock, char *string);
bool pack_str32(int sock, char *string);
void pack_map16_start(int sock, uint16_t length);
