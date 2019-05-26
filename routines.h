/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Global prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef ROUTINES_H
#define ROUTINES_H

// daemon.c
void go_daemon(void);
void timer_start(const int i);
double timer_elapsed_msec(const int i);
void sleepms(const int milliseconds);
void savepid(void);
char * getUserName(void);
void removepid(void);

// log.c
void open_FTL_log(const bool test);
void logg(const char* format, ...) __attribute__ ((format (gnu_printf, 1, 2)));
void log_counter_info(void);
void format_memory_size(char *prefix, unsigned long int bytes, double *formated);
void log_FTL_version(bool crashreport);
void get_timestr(char *timestring, const time_t timein);

// datastructure.c
void strtolower(char *str);
int findForwardID(const char * forward, const bool count);
int findDomainID(const char *domain);
int findClientID(const char *client, const bool count);
bool isValidIPv4(const char *addr);
bool isValidIPv6(const char *addr);
const char *getDomainString(const int queryID);
const char *getClientIPString(const int queryID);
const char *getClientNameString(const int queryID);

void close_telnet_socket(void);
void close_unix_socket(void);
void seom(const int sock);
void ssend(const int sock, const char *format, ...) __attribute__ ((format (gnu_printf, 2, 3)));
void swrite(const int sock, const void* value, const size_t size);
void *telnet_listening_thread_IPv4(void *args);
void *telnet_listening_thread_IPv6(void *args);

void *socket_listening_thread(void *args);
bool ipv6_available(void);
void bind_sockets(void);

void process_request(const char *client_message, int *sock);
bool command(const char *client_message, const char* cmd) __attribute__((pure));

// grep.c
int countlines(const char* fname);
int countlineswith(const char* str, const char* fname);
void check_blocking_status(void);

void check_setupVarsconf(void);
char * read_setupVarsconf(const char * key);
void getSetupVarsArray(const char * input);
void clearSetupVarsArray(void);
bool insetupVarsArray(const char * str);
bool getSetupVarsBool(const char * input) __attribute__((pure));

void parse_args(int argc, char* argv[]);

// setupVars.c
char* find_equals(const char* s) __attribute__((pure));
void trim_whitespace(char *string);

// config.c
void getLogFilePath(void);
void read_FTLconf(void);
void get_privacy_level(FILE *fp);
void get_blocking_mode(FILE *fp);
void read_debuging_settings(FILE *fp);

// gc.c
void *GC_thread(void *val);

// database.c
void db_init(void);
void *DB_thread(void *val);
int get_number_of_queries_in_DB(void);
void save_to_DB(void);
void read_data_from_DB(void);
bool db_set_FTL_property(const unsigned int ID, const int value);
bool dbquery(const char *format, ...);
bool dbopen(void);
void dbclose(void);
int db_query_int(const char*);
void SQLite3LogCallback(void *pArg, int iErrCode, const char *zMsg);

// memory.c
void memory_check(const int which);
char *FTLstrdup(const char *src, const char *file, const char *function, const int line) __attribute__((malloc));
void *FTLcalloc(size_t nmemb, size_t size, const char *file, const char *function, const int line) __attribute__((malloc)) __attribute__((alloc_size(1,2)));
void *FTLrealloc(void *ptr_in, size_t size, const char *file, const char *function, const int line) __attribute__((alloc_size(2)));
void FTLfree(void *ptr, const char* file, const char *function, const int line);

int main_dnsmasq(int argc, const char ** argv);

// signals.c
void handle_signals(void);

// resolve.c
void *DNSclient_thread(void *val);
void resolveClients(const bool onlynew);
void resolveForwardDestinations(const bool onlynew);

// regex.c
bool match_regex(const char *input);
void free_regex(void);
void free_whitelist_domains(void);
void read_regex_from_database(void);
void read_whitelist_from_database(void);
bool in_whitelist(const char *domain) __attribute__((pure));
void log_regex_whitelist(const double time);

// shmem.c
bool init_shmem(void);
void destroy_shmem(void);
size_t addstr(const char *str);
const char *getstr(const size_t pos);
void *enlarge_shmem_struct(const char type);

/**
 * Create a new overTime client shared memory block.
 * This also updates `overTimeClientData`.
 */
void newOverTimeClient(const int clientID);

/**
 * Add a new overTime slot to each overTime client shared memory block.
 * This also updates `overTimeClientData`.
 */
void addOverTimeClientSlot(void);

// overTime.c
void initOverTime(void);
unsigned int getOverTimeID(const time_t timestamp);

/**
 * Move the overTime slots so the oldest interval starts with mintime. The time
 * given will be aligned to OVERTIME_INTERVAL.
 *
 * @param mintime The start of the oldest interval
 */
void moveOverTimeMemory(const time_t mintime);

// capabilities.c
bool check_capabilities(void);

// networktable.c
bool create_network_table(void);
void parse_arp_cache(void);
void updateMACVendorRecords(void);

// gravity.c
bool gravityDB_getTable(unsigned char list);
const char* gravityDB_getDomain(void);
void gravityDB_finalizeTable(void);
int gravityDB_count(unsigned char list);
#endif // ROUTINES_H
