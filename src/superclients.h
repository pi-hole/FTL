/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Super-client handling prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef SUPERCLIENTS_H
#define SUPERCLIENTS_H

// type clientsData
#include "datastructure.h"

void reset_superclient(clientsData *client);

#endif //SUPERCLIENTS_H
