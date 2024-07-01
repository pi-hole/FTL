/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Main prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef MAIN_H
#define MAIN_H

// setjmp, longjmp, jmp_buf
#include <setjmp.h>

extern int main_dnsmasq(int argc, char ** argv);

// defined in dnsmasq_interface.c
void FTL_fork_and_bind_sockets(struct passwd *ent_pw, bool dnsmasq_start);

extern char *username;
extern bool startup;
extern jmp_buf exit_jmp;

#endif //MAIN_H
