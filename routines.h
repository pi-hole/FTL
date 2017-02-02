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
void timer_start(void);
float timer_elapsed_msec(void);
void savepid(pid_t sid);

void open_FTL_log(void);
void logg(const char* str);
void logg_int(const char* star, int i);
void logg_str(const char* str, char* str2);
void logg_struct_resize(const char* str, int from, int to);
void logg_str_str(const char* str, char* str2, char* str3);
void log_counter_info(void);

int checkLogForChanges(void);
void open_pihole_log(void);
void handle_signals(void);
void pihole_log_flushed(void);
void process_pihole_log(void);

void memory_check(int which);

void init_socket(void);
bool listen_socket(void);
bool check_socket(void);
void read_socket(void);
void close_sockets(void);
void seom(void);
void swrite(void);

void process_request(void);
bool command(const char* cmd);
void formatNumber(bool raw, int n, char* buffer);

void read_gravity_files(void);
int countlines(const char* fname);
int countlineswith(const char* str, const char* fname);

void check_setupVarsconf(void);
char * read_setupVarsconf(const char * key);
void getSetupVarsArray(char * input);
void clearSetupVarsArray(void);
bool insetupVarsArray(char * str);
bool getSetupVarsBool(char * input);
