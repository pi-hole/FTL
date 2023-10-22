/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Sessions table database prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef SESSION_TABLE_PRIVATE_H
#define SESSION_TABLE_PRIVATE_H

#include "sqlite3.h"
// struct session
#include "api/auth.h"

bool create_session_table(sqlite3 *db);
bool add_db_session(struct session *sess);
bool update_db_session(struct session *sess);
bool restore_db_sessions(struct session *sessions);
bool del_db_session(struct session *sess);
bool del_all_db_sessions(void);

#endif // SESSION_TABLE_PRIVATE_H