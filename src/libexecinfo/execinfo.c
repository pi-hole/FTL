/*
 * Copyright (c) 2003 Maxim Sobolev <sobomax@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: execinfo.c,v 1.3 2004/07/19 05:21:09 sobomax Exp $
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "execinfo.h"
#include "stacktraverse.h"

#define D10(x) ceil(log10(((x) == 0) ? 2 : ((x) + 1)))

inline static void *
realloc_safe(void *ptr, size_t size)
{
    void *nptr;

    nptr = realloc(ptr, size);
    if (nptr == NULL)
        free(ptr);
    return nptr;
}

int
backtrace(void **buffer, int size)
{
    int i;

    for (i = 1; i < 5 &&getframeaddr(i + 1) != NULL && i != size + 1; i++) {
        buffer[i - 1] = getreturnaddr(i);
        if (buffer[i - 1] == NULL)
            break;
    }

    return i - 1;
}

char **
backtrace_symbols(void *const *buffer, int size)
{
    size_t clen, alen;
    int i, offset;
    char **rval;
    char *cp;
    Dl_info info;

    clen = size * sizeof(char *);
    rval = malloc(clen);
    if (rval == NULL)
        return NULL;
    for (i = 0; i < size; i++) {
        if (dladdr(buffer[i], &info) != 0) {
            if (info.dli_sname == NULL)
                info.dli_sname = "???";
            if (info.dli_saddr == NULL)
                info.dli_saddr = buffer[i];
            offset = buffer[i] - info.dli_saddr;
            /* "0x01234567 <function+offset> at filename" */
            alen = 2 +                      /* "0x" */
                   (sizeof(void *) * 2) +   /* "01234567" */
                   2 +                      /* " <" */
                   strlen(info.dli_sname) + /* "function" */
                   1 +                      /* "+" */
                   10 +                     /* "offset */
                   5 +                      /* "> at " */
                   strlen(info.dli_fname) + /* "filename" */
                   1;                       /* "\0" */
            rval = realloc_safe(rval, clen + alen);
            if (rval == NULL)
                return NULL;
            snprintf((char *) rval + clen, alen, "%p <%s+%d> at %s",
              buffer[i], info.dli_sname, offset, info.dli_fname);
        } else {
            alen = 2 +                      /* "0x" */
                   (sizeof(void *) * 2) +   /* "01234567" */
                   1;                       /* "\0" */
            rval = realloc_safe(rval, clen + alen);
            if (rval == NULL)
                return NULL;
            snprintf((char *) rval + clen, alen, "%p", buffer[i]);
        }
        rval[i] = (char *) clen;
        clen += alen;
    }

    for (i = 0; i < size; i++)
        rval[i] += (long) rval;

    return rval;
}

void
backtrace_symbols_fd(void *const *buffer, int size, int fd)
{
    int i, len, offset;
    char *buf;
    Dl_info info;

    for (i = 0; i < size; i++) {
        if (dladdr(buffer[i], &info) != 0) {
            if (info.dli_sname == NULL)
                info.dli_sname = "???";
            if (info.dli_saddr == NULL)
                info.dli_saddr = buffer[i];
            offset = buffer[i] - info.dli_saddr;
            /* "0x01234567 <function+offset> at filename" */
            len = 2 +                      /* "0x" */
                  (sizeof(void *) * 2) +   /* "01234567" */
                  2 +                      /* " <" */
                  strlen(info.dli_sname) + /* "function" */
                  1 +                      /* "+" */
                  D10(offset) +            /* "offset */
                  5 +                      /* "> at " */
                  strlen(info.dli_fname) + /* "filename" */
                  2;                       /* "\n\0" */
            buf = alloca(len);
            if (buf == NULL)
                return;
            snprintf(buf, len, "%p <%s+%d> at %s\n",
              buffer[i], info.dli_sname, offset, info.dli_fname);
        } else {
            len = 2 +                      /* "0x" */
                  (sizeof(void *) * 2) +   /* "01234567" */
                  2;                       /* "\n\0" */
            buf = alloca(len);
            if (buf == NULL)
                return;
            snprintf(buf, len, "%p\n", buffer[i]);
        }
        write(fd, buf, strlen(buf));
    }
}
