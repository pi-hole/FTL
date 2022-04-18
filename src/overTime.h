/* Pi-hole: A black hole for Internet advertisements
*  (c) 2018 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Over Time data header
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#ifndef OVERTIME_H
#define OVERTIME_H

// TYPE_MAX
#include "datastructure.h"

void initOverTime(void);

#define getOverTimeID(timestamp) _getOverTimeID(timestamp, __FILE__, __LINE__)
unsigned int _getOverTimeID(const time_t timestamp, const char *file, const int line);

/**
 * Move the overTime slots so the oldest interval starts with mintime. The time
 * given will be aligned to OVERTIME_INTERVAL.
 *
 * @param mintime The start of the oldest interval
 */
void moveOverTimeMemory(const time_t mintime);

typedef struct {
	unsigned char magic;
	int total;
	int blocked;
	int cached;
	int forwarded;
	time_t timestamp;
} overTimeData;

extern overTimeData *overTime;

#endif //OVERTIME_H
