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

/**
 * Initialize the overTime slot
 *
 * @param index The overTime slot index
 * @param timestamp The timestamp of the slot
 */
static void initSlot(unsigned int index, time_t timestamp)
{
	// Possible debug printing
	if(debug) logg("initSlot(%u, %u): Zeroing overTIme slot", index, timestamp);

	overTime[index].magic = MAGICBYTE;
	overTime[index].timestamp = timestamp;
	overTime[index].total = 0;
	overTime[index].blocked = 0;
	overTime[index].cached = 0;
	overTime[index].forwarded = 0;

	// Zero all query types
	for(unsigned int queryType = 0; queryType < TYPE_MAX-1; queryType++)
		overTime[index].querytypedata[queryType] = 0;

	// Zero overTime counter for all known clients
	for(int clientID = 0; clientID < counters->clients; clientID++)
		clients[clientID].overTime[index] = 0;
}

void initOverTime(void)
{
	// Get current timestamp
	time_t now = time(NULL);

	// The last timestamp (overTime[149]) should be the last interval of this hour
	// If the current time is 09:35, the last interval is 09:50 - 10:00 (centered at 09:55)
	time_t timestamp = now - now % 3600 + 3600 - (OVERTIME_INTERVAL / 2);

	if(debug) logg("initOverTime(): Initializing %i slots from %u to %u", OVERTIME_SLOTS, timestamp-OVERTIME_SLOTS*OVERTIME_INTERVAL, timestamp);

	// Iterate over overTime and initialize it
	for(int i = OVERTIME_SLOTS-1; i >= 0 ; i--)
	{
		initSlot(i, timestamp);

		// Prepare for next iteration
		timestamp -= OVERTIME_INTERVAL;
	}
}

unsigned int getOverTimeID(time_t timestamp)
{
	// Center timestamp in OVERTIME_INTERVAL
	timestamp -= timestamp % OVERTIME_INTERVAL;
	timestamp += OVERTIME_INTERVAL/2;

	// Get timestamp of first interval
	time_t firstTimestamp = overTime[0].timestamp;

	// Compute overTime ID
	int id = (int) ((timestamp - firstTimestamp) / OVERTIME_INTERVAL);

	// Check bounds manually
	if(id < 0)
	{
		logg("WARN: getOverTimeID(%u): %u is negative: %u", timestamp, id, firstTimestamp);
		// Return first timestamp in case negative timestamp was determined
		return 0;
	}
	else if(id > OVERTIME_SLOTS-1)
	{
		logg("WARN: getOverTimeID(%u): %i is too large: %u", timestamp, id, firstTimestamp);
		// Return last timestamp in case a too large timestamp was determined
		return OVERTIME_SLOTS-1;
	}

	if(debug) logg("getOverTimeID(%u): %i", timestamp, id);

	return (unsigned int) id;
}

// This routine is called by garbage collection to rearrange the overTime structure for the next hour
void moveOverTimeMemory(time_t mintime)
{
	time_t oldestOverTimeIS = overTime[0].timestamp;
	// Shift SHOULD timestemp into the future by the amount GC is running earlier
	time_t oldestOverTimeSHOULD = mintime;

	// Center in interval
	oldestOverTimeSHOULD -= oldestOverTimeSHOULD % OVERTIME_INTERVAL;
	oldestOverTimeSHOULD += OVERTIME_INTERVAL / 2;

	// Calculate the number of slots to be garbage collected, which is also the
	// ID of the slot to move to the zero position
	unsigned int moveOverTime = (unsigned int) ((oldestOverTimeSHOULD - oldestOverTimeIS) / OVERTIME_INTERVAL);

	// The number of slots which will be moved (not garbage collected)
	unsigned int remainingSlots = OVERTIME_SLOTS - moveOverTime;

	if(debug) logg("moveOverTimeMemory(): IS: %u, SHOULD: %u, MOVING: %u", oldestOverTimeIS, oldestOverTimeSHOULD, moveOverTime);

	// Check if the move over amount is valid. This prevents errors if the
	// function is called before GC is necessary.
	if(moveOverTime > 0 && moveOverTime < OVERTIME_SLOTS)
	{
		// Move overTime memory
		if(debug) logg("moveOverTimeMemory(): Moving overTime %u - %u to 0 - %u", moveOverTime, moveOverTime+remainingSlots, remainingSlots);
		memmove(&overTime[0], &overTime[moveOverTime], remainingSlots*sizeof(*overTime));

		// Correct time indices of queries. This is necessary because we just moved the slot this index points to
		for(int queryID = 0; queryID < counters->queries; queryID++)
		{
			// Check if the index would become negative if we adjusted it
			if(((int)queries[queryID].timeidx - (int)moveOverTime) < 0)
			{
				// This should never happen, but we print a warning if it still happens
				// We don't do anything in this case
				logg("WARN: moveOverTimeMemory(): overTime time index correction failed (%i: %u / %u)", queryID, queries[queryID].timeidx, moveOverTime);
			}
			else
			{
				queries[queryID].timeidx -= moveOverTime;
			}
		}

		// Move client-specific overTime memory
		for(int clientID = 0; clientID < counters->clients; clientID++)
		{
			memmove(&clients[clientID].overTime[0], &clients[clientID].overTime[moveOverTime], remainingSlots*sizeof(int));
		}

		// Iterate over new overTime region and initialize it
		for(unsigned int timeidx = remainingSlots; timeidx < OVERTIME_SLOTS ; timeidx++)
		{
			// This slot is OVERTIME_INTERVAL seconds after the previous slot
			time_t timestamp = overTime[timeidx-1].timestamp + OVERTIME_INTERVAL;
			initSlot(timeidx, timestamp);
		}
	}
}
