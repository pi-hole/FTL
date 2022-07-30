/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Telnet/Socket request prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef REQUEST_H
#define REQUEST_H

bool process_request(const char *client_message, const int sock, const bool istelnet);
bool command(const char *client_message, const char* cmd) __attribute__((pure));

#endif //REQUEST_H
