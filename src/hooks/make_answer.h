/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq server interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_MAKE_ANSWER_H
#define FTL_MAKE_ANSWER_H

#ifdef FTL_PRIVATE
  #if !defined(FTLDNS)
  #define FTLDNS
  #include "../dnsmasq/dnsmasq.h"
  #undef __USE_XOPEN
  #include "../FTL.h"
  #endif
#endif // FTL_PRIVATE

extern enum reply_type force_next_DNS_reply;
extern const char *blockingreason;

#define FTL_make_answer(header, limit, len, ede) _FTL_make_answer(header, limit, len, ede, __FILE__, __LINE__)
size_t _FTL_make_answer(struct dns_header *header, char *limit, const size_t len, int *ede,
                        const char *file, const int line);

#endif // FTL_MAKE_ANSWER_H
