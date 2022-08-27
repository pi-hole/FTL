/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Syscall prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef SYSCALLS_H
#define SYSCALLS_H

// Interrupt-safe memory routines
char *FTLstrdup(const char *src, const char *file, const char *func, const int line) __attribute__((malloc));
void *FTLcalloc(size_t n, size_t size, const char *file, const char *func, const int line) __attribute__((malloc)) __attribute__((alloc_size(1,2)));
void *FTLrealloc(void *ptr_in, size_t size, const char *file, const char *func, const int line) __attribute__((alloc_size(2)));
void FTLfree(void *ptr, const char*file, const char *func, const int line);
int FTLfallocate(const int fd, const off_t offset, const off_t len, const char *file, const char *func, const int line);


// Interrupt-safe printing routines
// printf() is derived from fprintf(stdout, ...)
// vprintf() is derived from vfprintf(stdout, ...)
int FTLfprintf(FILE *stream, const char*file, const char *func, const int line, const char *format, ...) __attribute__ ((format (gnu_printf, 5, 6)));
int FTLvfprintf(FILE *stream, const char*file, const char *func, const int line, const char *format, va_list args) __attribute__ ((format (gnu_printf, 5, 0)));

int FTLsprintf(const char *file, const char *func, const int line, char *__restrict__ buffer, const char *format, ...) __attribute__ ((format (gnu_printf, 5, 6)));
int FTLvsprintf(const char *file, const char *func, const int line, char *__restrict__ buffer, const char *format, va_list args) __attribute__ ((format (gnu_printf, 5, 0)));

int FTLasprintf(const char *file, const char *func, const int line, char **buffer, const char *format, ...) __attribute__ ((format (gnu_printf, 5, 6)));
int FTLvasprintf(const char *file, const char *func, const int line, char **buffer, const char *format, va_list args) __attribute__ ((format (gnu_printf, 5, 0)));

int FTLsnprintf(const char *file, const char *func, const int line, char *__restrict__ buffer, const size_t maxlen, const char *format, ...) __attribute__ ((format (gnu_printf, 6, 7)));
int FTLvsnprintf(const char *file, const char *func, const int line, char *__restrict__ buffer, const size_t maxlen, const char *format, va_list args) __attribute__ ((format (gnu_printf, 6, 0)));

// Interrupt-safe socket routines
ssize_t FTLwrite(int fd, const void *buf, size_t total, const char *file, const char *func, const int line);
int FTLaccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, const char *file, const char *func, const int line);
ssize_t FTLrecv(int sockfd, void *buf, size_t len, int flags, const char *file, const char *func, const int line);
ssize_t FTLrecvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen, const char *file, const char *func, const int line);
int FTLselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout, const char *file, const char *func, const int line);
ssize_t FTLsendto(int sockfd, void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen, const char *file, const char *func, const int line);

// Interrupt-safe thread routines
int FTLpthread_mutex_lock(pthread_mutex_t *__mutex, const char *file, const char *func, const int line);

// Interrupt-safe file routines
FILE *FTLfopen(const char *pathname, const char *mode, const char *file, const char *func, const int line) __attribute__ ((__malloc__));

// Syscall helpers
void syscalls_report_error(const char *error, FILE *stream, const int _errno, const char *format, const char *func, const char *file, const int line);

#endif //SYSCALLS_H
