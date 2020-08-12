/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL.db -> super-clients tables prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef SUPERCLIENTS_TABLE_H
#define SUPERCLIENTS_TABLE_H

// type clientsData
#include "../datastructure.h"

void reset_superclient(clientsData *client);

bool create_superclients_table(void);
bool import_superclients(void);
void reimport_superclients(void);

int *get_superclient_list(const int superclientID);

#endif //SUPERCLIENTS_TABLE_H
