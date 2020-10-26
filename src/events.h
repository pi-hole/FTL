/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Event queue processing prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef EVENTS_H
#define EVENTS_H

// enum events
#include "enums.h"

#define set_event(event) _set_event(event, __LINE__, __FUNCTION__, __FILE__)
void _set_event(const enum events event, int line, const char *function, const char *file);
#define get_and_clear_event(event) _get_and_clear_event(event, __LINE__, __FUNCTION__, __FILE__)
bool _get_and_clear_event(const enum events event, int line, const char *function, const char *file);

#endif // EVENTS_H