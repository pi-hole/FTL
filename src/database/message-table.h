/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL.db -> message tables prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef MESSAGETABLE_H
#define MESSAGETABLE_H

#include "sqlite3.h"
#include "webserver/cJSON/cJSON.h"

int count_messages(const bool filter_dnsmasq_warnings);
bool format_messages(cJSON *array);
bool create_message_table(sqlite3 *db);
bool delete_message(cJSON *ids, int *deleted);
bool flush_message_table(void);
void logg_regex_warning(const char *type, const char *warning, const int dbindex, const char *regex);
void logg_subnet_warning(const char *ip, const int matching_count, const char *matching_ids,
                         const int matching_bits, const char *chosen_match_text,
                         const int chosen_match_id);
void logg_hostname_warning(const char *ip, const char *name, const unsigned int pos);
void logg_fatal_dnsmasq_message(const char *message);
void logg_rate_limit_message(const char *clientIP, const unsigned int rate_limit_count);
void logg_warn_dnsmasq_message(char *message);
void log_resource_shortage(const double load, const int nprocs, const int shmem, const int disk, const char *path, const char *msg);
void logg_inaccessible_adlist(const int dbindex, const char *address);
void log_certificate_domain_mismatch(const char *certfile, const char *domain);

#endif //MESSAGETABLE_H
