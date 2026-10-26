/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Client name history prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef NAME_HISTORY_H
#define NAME_HISTORY_H

#include "datastructure.h"

size_t client_name_at(const unsigned int clientID, const size_t current, const int64_t id) __attribute__((pure));
void rename_client(clientsData *client, const unsigned int clientID, const size_t namepos, const int64_t from_id);
void name_history_import(const unsigned int clientID, const int64_t id, const size_t namepos);
void name_history_gc(const int64_t oldest_id);

#endif //NAME_HISTORY_H
