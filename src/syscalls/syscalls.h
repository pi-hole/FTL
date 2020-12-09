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

char *FTLstrdup(const char *src, const char *file, const char *function, const int line) __attribute__((malloc));
void *FTLcalloc(size_t n, size_t size, const char *file, const char *function, const int line) __attribute__((malloc)) __attribute__((alloc_size(1,2)));
void *FTLrealloc(void *ptr_in, size_t size, const char *file, const char *function, const int line) __attribute__((alloc_size(2)));
void FTLfree(void *ptr, const char* file, const char *function, const int line);
int FTLfprintf(FILE *stream, const char *format, ...) __attribute__ ((format (gnu_printf, 2, 3)));
int FTLvfprintf(FILE *stream, const char *format, va_list args) __attribute__ ((format (gnu_printf, 2, 0)));
ssize_t FTLwrite(int fd, const void *buf, size_t total, const char * file, const char * function, const int line);
int FTLaccept(int sockfd, struct sockaddr *addr, socklen_t *addrlen, const char * file, const char * function, const int line);

#endif //SYSCALLS_H
