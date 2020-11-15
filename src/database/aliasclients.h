/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL.db -> alias-clients tables prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef ALIASCLIENTS_TABLE_H
#define ALIASCLIENTS_TABLE_H

// type clientsData
#include "../datastructure.h"

void reset_aliasclient(clientsData *client);

bool create_aliasclients_table(void);
bool import_aliasclients(void);
void reimport_aliasclients(void);

int *get_aliasclient_list(const int aliasclientID);

#endif //ALIASCLIENTS_TABLE_H
