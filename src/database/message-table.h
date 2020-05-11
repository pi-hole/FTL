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

bool create_message_table(void);
bool flush_message_table(void);
void logg_regex_warning(const char *type, const char *warning, const int dbindex, const char *regex);
void logg_subnet_warning(const char *ip, const int matching_count, const char *matching_ids,
                         const int matching_bits, const char *chosen_match_text,
                         const int chosen_match_id);

enum message_type { REGEX_MESSAGE, SUBNET_MESSAGE, MAX_MESSAGE };

#endif //MESSAGETABLE_H
