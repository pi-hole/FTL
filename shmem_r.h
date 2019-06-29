/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Shared memory prototypes
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef SHMEM_H
#define SHMEM_H

bool init_shmem(void);
void destroy_shmem(void);
size_t addstr(const char *str);
const char *getstr(const size_t pos);
void *enlarge_shmem_struct(const char type);

/**
 * Create a new overTime client shared memory block.
 * This also updates `overTimeClientData`.
 */
void newOverTimeClient(const int clientID);

/**
 * Add a new overTime slot to each overTime client shared memory block.
 * This also updates `overTimeClientData`.
 */
void addOverTimeClientSlot(void);

// overTime.c
void initOverTime(void);
unsigned int getOverTimeID(const time_t timestamp);

/**
 * Move the overTime slots so the oldest interval starts with mintime. The time
 * given will be aligned to OVERTIME_INTERVAL.
 *
 * @param mintime The start of the oldest interval
 */
void moveOverTimeMemory(const time_t mintime);

#endif //SHMEM_H
