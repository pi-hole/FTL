/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Global prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

void go_daemon(void);
void timer_start(int i);
double timer_elapsed_msec(int i);
void sleepms(int milliseconds);
void savepid(void);
char * getUserName(void);
void removepid(void);

void open_FTL_log(bool test);
void logg(const char* str, ...);
void logg_struct_resize(const char* str, int to, int step);
void log_counter_info(void);
void format_memory_size(char *prefix, unsigned long int bytes, double *formated);
void log_FTL_version(void);

// datastructure.c
void gettimestamp(int *querytimestamp, int *overTimetimestamp);
void strtolower(char *str);
int findOverTimeID(int overTimetimestamp);
int findForwardID(const char * forward, bool count);
int findDomainID(const char *domain);
int findClientID(const char *client);
bool isValidIPv4(const char *addr);
bool isValidIPv6(const char *addr);
int detectStatus(const char *domain);

void close_telnet_socket(void);
void close_unix_socket(void);
void seom(int sock);
void ssend(int sock, const char *format, ...);
void swrite(int sock, void *value, size_t size);
void *telnet_listening_thread_IPv4(void *args);
void *telnet_listening_thread_IPv6(void *args);

void *socket_listening_thread(void *args);
bool ipv6_available(void);
void bind_sockets(void);

void process_request(char *client_message, int *sock);
bool command(char *client_message, const char* cmd);
bool matchesEndpoint(char *client_message, const char *cmd);

// grep.c
void readGravityFiles(void);
void freeWildcards(void);
int countlines(const char* fname);
int countlineswith(const char* str, const char* fname);
void check_blocking_status(void);

void check_setupVarsconf(void);
char * read_setupVarsconf(const char * key);
void getSetupVarsArray(char * input);
void clearSetupVarsArray(void);
bool insetupVarsArray(char * str);
bool getSetupVarsBool(char * input);

void parse_args(int argc, char* argv[]);

char* find_equals(const char* s);

// threads.c
void enable_thread_lock(void);
void disable_thread_lock(void);
void init_thread_lock(void);

// config.c
void read_FTLconf(void);
void get_privacy_level(FILE *fp);
void get_blocking_mode(FILE *fp);

// gc.c
void *GC_thread(void *val);

// database.c
void db_init(void);
void *DB_thread(void *val);
int get_number_of_queries_in_DB(void);
void save_to_DB(void);
void read_data_from_DB(void);

// memory.c
void memory_check(int which);
char *FTLstrdup(const char *src, const char *file, const char *function, int line);
void *FTLcalloc(size_t nmemb, size_t size, const char *file, const char *function, int line);
void *FTLrealloc(void *ptr_in, size_t size, const char *file, const char *function, int line);
void FTLfree(void *ptr, const char* file, const char *function, int line);
void validate_access(const char * name, int pos, bool testmagic, int line, const char * function, const char * file);
void validate_access_oTcl(int timeidx, int clientID, int line, const char * function, const char * file);

int main_dnsmasq(int argc, char **argv);

// signals.c
void handle_signals(void);

// resolve.c
void resolveNewClients(void);
void reresolveHostnames(void);

// regex.c
bool init_regex(char *regexin, int index);
bool match_regex(char *input);
void free_regex(void);
