/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config inotify prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef CONFIG_INOTIFY_H
#define CONFIG_INOTIFY_H
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

void watch_config(bool watch);
bool check_inotify_event(void);

#endif //CONFIG_INOTIFY_H
