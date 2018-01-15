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

void initial_log_parsing(void);
long int checkLogForChanges(void);
void open_pihole_log(void);
void handle_signals(void);
void process_pihole_log(int file);
void *pihole_log_thread(void *val);
void validate_access(const char * name, int pos, bool testmagic, int line, const char * function, const char * file);
void validate_access_oTfd(int timeidx, int pos, int line, const char * function, const char * file);
void validate_access_oTcl(int timeidx, int pos, int line, const char * function, const char * file);
void reresolveHostnames(void);

void pihole_log_flushed(bool message);

void memory_check(int which);

void close_telnet_socket(void);
void close_unix_socket(void);
void swrite(char server_message[], int sock);
void *telnet_listening_thread_IPv4(void *args);
void *telnet_listening_thread_IPv6(void *args);
void seom(int sock);
void ssend(int sock, const char *format, ...);

void *socket_listening_thread(void *args);
bool ipv6_available(void);
bool bind_sockets(void);

void process_request(char *client_message, int *sock);
bool command(char *client_message, const char* cmd);
void formatNumber(bool raw, int n, char* buffer);

void read_gravity_files(void);
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

void enable_thread_lock(const char *message);
void disable_thread_lock(const char *message);
void init_thread_lock(void);

void read_FTLconf(void);

void *GC_thread(void *val);

// database.c
void db_init(void);
void *DB_thread(void *val);
int get_number_of_queries_in_DB(void);
