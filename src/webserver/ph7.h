/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  PH7 interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef PH7_H
#define PH7_H

void init_ph7(void);
void ph7_terminate(void);
int ph7_handler(struct mg_connection *conn, void *cbdata);

#endif // PH7_H