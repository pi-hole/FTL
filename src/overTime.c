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
		char timestr[20];
		strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", localtime(&timestamp));
		logg("initSlot(%u, %llu): Zeroing overTime slot at %s", index, (long long)timestamp, timestr);
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

	// Get the centered timestamp of the end of the next garbage collection interval
	// This is necessary to construct all slots until the point where we are moving
	// the entire overTime structure into the future (i.e., generate "new" slots)
	//                    Get beginning of       Advance to   Center this interval at
	//                    previous GC interval   next GC int. 5 minutes less than full
	//                    vvvvvvvvvvvvvvvvvvvvvv vvvvvvvvvvvv vvvvvvvvvvvvvvvvvvvvvvvvv
	const time_t newest = now - now % GCinterval + GCinterval - (OVERTIME_INTERVAL / 2);
	// Oldest timestamp is (OVERTIME_SLOTS-1) times the OVERTIME_INTERVAL in the past
	const time_t oldest = newest - (OVERTIME_SLOTS-1) * OVERTIME_INTERVAL;

	if(config.debug & DEBUG_OVERTIME)
	{
		char first[20], last[20];
		strftime(first, 20, "%Y-%m-%d %H:%M:%S", localtime(&oldest));
		strftime(last, 20, "%Y-%m-%d %H:%M:%S", localtime(&newest));
		logg("initOverTime(): Initializing %i slots from %s (%llu) to %s (%llu)",
		     OVERTIME_SLOTS, first, (long long)oldest, last, (long long)newest);
	}

	// Iterate over overTime
	for(int i = 0; i < OVERTIME_SLOTS; i++)
	{
		time_t this_slot_ts = oldest + OVERTIME_INTERVAL * i;
		// Initialize overTime slot
		initSlot(i, this_slot_ts);
	}
}

bool warned_about_hwclock = false;
unsigned int _getOverTimeID(time_t timestamp, const char *file, const int line)
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
	else if(id == OVERTIME_SLOTS)
	{
		// Possible race-collision (moving of the timeslots is just about to
		// happen), silently add to the last bin because this is the correct
		// thing to do
		return OVERTIME_SLOTS-1;
	}
	else if(id > OVERTIME_SLOTS)
	{
		// This is definitely wrong. We warn about this (but only once)
		if(!warned_about_hwclock)
		{
			char timestampStr[84] = "";
			get_timestr(timestampStr, timestamp, false);

			const time_t lastTimestamp = overTime[OVERTIME_SLOTS-1].timestamp;
			char lastTimestampStr[84] = "";
			get_timestr(lastTimestampStr, lastTimestamp, false);

			logg("WARN: Found database entries in the future (%s (%llu), last timestamp for importing: %s (%llu)). "
			     "Your over-time statistics may be incorrect (found in %s:%d)",
			     timestampStr, (long long)timestamp,
			     lastTimestampStr, (long long)lastTimestamp,
			     short_path(file), line);
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
		        remainingSlots*sizeof(*client->overTime));
	}

	// Process upstream data
	for(int upstreamID = 0; upstreamID < counters->upstreams; upstreamID++)
	{
		upstreamsData *upstream = getUpstream(upstreamID, true);
		if(!upstream)
			continue;

		// Move upstream-specific overTime memory
		memmove(&(upstream->overTime[0]),
		        &(upstream->overTime[moveOverTime]),
		        remainingSlots*sizeof(*upstream->overTime));
	}

	// Iterate over new overTime region and initialize it
	for(unsigned int timeidx = remainingSlots; timeidx < OVERTIME_SLOTS ; timeidx++)
	{
		// This slot is OVERTIME_INTERVAL seconds after the previous slot
		const time_t timestamp = overTime[timeidx-1].timestamp + OVERTIME_INTERVAL;
		initSlot(timeidx, timestamp);
	}
}
