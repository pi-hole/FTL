/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  MessagePack serialization
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
#include "overTime.h"
#include "shmem.h"
#include "config.h"
#include "log.h"
// data getter functions
#include "datastructure.h"

overTimeData *overTime = NULL;

/**
 * Initialize the overTime slot
 *
 * @param index The overTime slot index
 * @param timestamp The timestamp of the slot
 */
static void initSlot(const unsigned int index, const time_t timestamp)
{
	// Possible debug printing
	if(config.debug & DEBUG_OVERTIME)
	{
		logg("initSlot(%u, %llu): Zeroing overTime slot", index, (long long)timestamp);
	}

	// Initialize overTime entry
	overTime[index].magic = MAGICBYTE;
	overTime[index].timestamp = timestamp;
	overTime[index].total = 0;
	overTime[index].blocked = 0;
	overTime[index].cached = 0;
	overTime[index].forwarded = 0;

	// Zero overTime counter for all known clients
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		// Get client pointer
		clientsData* client = getClient(clientID, true);
		if(client != NULL)
		{
			// Set overTime data to zero
			client->overTime[index] = 0;
		}
	}

	// Zero overTime counter for all known upstream destinations
	for(int upstreamID = 0; upstreamID < counters->upstreams; upstreamID++)
	{
		// Get client pointer
		upstreamsData* upstream = getUpstream(upstreamID, true);
		if(upstream != NULL)
		{
			// Set overTime data to zero
			upstream->overTime[index] = 0;
		}
	}
}

void initOverTime(void)
{
	// Get current timestamp
	time_t now = time(NULL);

	// The last timestamp (overTime[149]) should be the last interval of this hour
	// If the current time is 09:35, the last interval is 09:50 - 10:00 (centered at 09:55)
	time_t timestamp = now - now % 3600 + 3600 - (OVERTIME_INTERVAL / 2);

	if(config.debug & DEBUG_OVERTIME)
		logg("initOverTime(): Initializing %i slots from %llu to %llu",
		     OVERTIME_SLOTS,
		     (long long)timestamp-OVERTIME_SLOTS*OVERTIME_INTERVAL,
		     (long long)timestamp);

	// Iterate over overTime
	for(int i = OVERTIME_SLOTS-1; i >= 0 ; i--)
	{
		// Initialize onerTime slot
		initSlot(i, timestamp);
		// Prepare for next iteration
		timestamp -= OVERTIME_INTERVAL;
	}
}

bool warned_about_hwclock = false;
unsigned int getOverTimeID(time_t timestamp)
{
	// Center timestamp in OVERTIME_INTERVAL
	timestamp -= timestamp % OVERTIME_INTERVAL;
	timestamp += OVERTIME_INTERVAL/2;

	// Get timestamp of first interval
	const time_t firstTimestamp = overTime[0].timestamp;

	// Compute overTime ID
	const int id = (int) ((timestamp - firstTimestamp) / OVERTIME_INTERVAL);

	// Check bounds manually
	if(id < 0)
	{
		// Return first timestamp in case negative timestamp was determined
		return 0;
	}
	else if(id > OVERTIME_SLOTS-1)
	{
		if(!warned_about_hwclock)
		{
			const time_t lastTimestamp = overTime[OVERTIME_SLOTS-1].timestamp;
			logg("WARN: Found database entries in the future (%llu, last: %llu). "
			     "Your over-time statistics may be incorrect",
			     (long long)timestamp, (long long)lastTimestamp);
			warned_about_hwclock = true;
		}
		// Return last timestamp in case a too large timestamp was determined
		return OVERTIME_SLOTS-1;
	}

	if(config.debug & DEBUG_OVERTIME)
	{
		// Debug output
		logg("getOverTimeID(%llu): %i", (long long)timestamp, id);
	}

	return (unsigned int) id;
}

// This routine is called by garbage collection to rearrange the overTime structure for the next hour
void moveOverTimeMemory(const time_t mintime)
{
	const time_t oldestOverTimeIS = overTime[0].timestamp;
	// Shift SHOULD timestamp into the future by the amount GC is running earlier
	time_t oldestOverTimeSHOULD = mintime;

	// Center in interval
	oldestOverTimeSHOULD -= oldestOverTimeSHOULD % OVERTIME_INTERVAL;
	oldestOverTimeSHOULD += OVERTIME_INTERVAL / 2;

	// Calculate the number of slots to be garbage collected, which is also the
	// ID of the slot to move to the zero position
	const unsigned int moveOverTime = (unsigned int) ((oldestOverTimeSHOULD - oldestOverTimeIS) / OVERTIME_INTERVAL);

	// The number of slots which will be moved (not garbage collected)
	const unsigned int remainingSlots = OVERTIME_SLOTS - moveOverTime;

	if(config.debug & DEBUG_OVERTIME)
	{
		logg("moveOverTimeMemory(): IS: %llu, SHOULD: %llu, MOVING: %u",
		     (long long)oldestOverTimeIS, (long long)oldestOverTimeSHOULD, moveOverTime);
	}

	// Check if the move over amount is valid. This prevents errors if the
	// function is called before GC is necessary.
	if(!(moveOverTime > 0 && moveOverTime < OVERTIME_SLOTS))
		return;

	// Move overTime memory
	if(config.debug & DEBUG_OVERTIME)
	{
		logg("moveOverTimeMemory(): Moving overTime %u - %u to 0 - %u",
			moveOverTime, moveOverTime+remainingSlots, remainingSlots);
	}

	// Move overTime memory forward to update data structure
	memmove(&overTime[0],
		&overTime[moveOverTime],
		remainingSlots*sizeof(*overTime));

	// Correct time indices of queries. This is necessary because we just moved the slot this index points to
	for(int queryID = 0; queryID < counters->queries; queryID++)
	{
		// Get query pointer
		queriesData* query = getQuery(queryID, true);
		if(query == NULL)
			continue;
	}

	// Move client-specific overTime memory
	for(int clientID = 0; clientID < counters->clients; clientID++)
	{
		clientsData *client = getClient(clientID, true);
		if(!client)
			continue;
		memmove(&(client->overTime[0]),
			&(client->overTime[moveOverTime]),
			remainingSlots*sizeof(int));
	}

	// Process upstream data
	for(int upstreamID = 0; upstreamID < counters->upstreams; upstreamID++)
	{
		upstreamsData *upstream = getUpstream(upstreamID, true);
		if(!upstream)
			continue;

		// Update upstream counters with overTime data we are going to move
		// This is necessary because we can store inly one upstream with each query
		// and garbage collection can only subtract this one when cleaning
		unsigned int sum = 0;
		for(unsigned int idx = 0; idx < moveOverTime; idx++)
		{
			sum += upstream->overTime[idx];
		}
		upstream->count -= sum;
		if(config.debug & DEBUG_GC)
			logg("Subtracted %d from total count of upstream %s:%d, new total is %d",
			     sum, getstr(upstream->ippos), upstream->port, upstream->count);

		// Move upstream-specific overTime memory
		memmove(&(upstream->overTime[0]),
			&(upstream->overTime[moveOverTime]),
			remainingSlots*sizeof(int));
	}

	// Iterate over new overTime region and initialize it
	for(unsigned int timeidx = remainingSlots; timeidx < OVERTIME_SLOTS ; timeidx++)
	{
		// This slot is OVERTIME_INTERVAL seconds after the previous slot
		const time_t timestamp = overTime[timeidx-1].timestamp + OVERTIME_INTERVAL;
		initSlot(timeidx, timestamp);
	}
}
