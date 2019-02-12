#include "FTL.h"

/**
 * Initialize the overTime slot
 *
 * @param index The overTime slot index
 * @param timestamp The timestamp of the slot
 */
static void initSlot(int index, time_t timestamp) {
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

	// Center in next interval. This makes room for the buffer overTime slot.
	time_t timestamp = now - now % OVERTIME_INTERVAL + (3 * OVERTIME_INTERVAL) / 2;

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
		logg("FATAL: getOverTimeID is negative: %u / %u ", timestamp, firstTimestamp);
		return 0;
	}
	else if(id > OVERTIME_INTERVAL-1)
	{
		logg("FATAL: getOverTimeID is too large: %u / %u ", timestamp, firstTimestamp);
		return OVERTIME_INTERVAL-1;
	}

	return (unsigned int) id;
}

// This routine is called by garbage collection to rearrange the overTime structure for the next hour
void moveOverTimeMemory(void)
{
	time_t oldestOverTimeIS = overTime[0].timestamp;
	time_t oldestOverTimeSHOULD = time(NULL) - MAXLOGAGE*3600;

	// Center in interval
	oldestOverTimeSHOULD -= oldestOverTimeSHOULD % OVERTIME_INTERVAL;
	oldestOverTimeSHOULD += OVERTIME_INTERVAL / 2;

	// Calculate the number of slots to be garbage collected, which is also the
	// ID of the slot to move to the zero position
	unsigned int moveOverTime = (unsigned int) ((oldestOverTimeSHOULD - oldestOverTimeIS) / OVERTIME_INTERVAL);

	// The number of slots which will be moved (not garbage collected)
	unsigned int remainingSlots = OVERTIME_SLOTS - moveOverTime;

	if(debug) logg("moveOverTimeMemory(): IS: %u, SHOULD: %i, MOVING: %i", oldestOverTimeIS, oldestOverTimeSHOULD, moveOverTime);

	// Check if the move over amount is valid. This prevents errors if the
	// function is called before GC is necessary.
	if(moveOverTime > 0 && moveOverTime < OVERTIME_SLOTS)
	{
		// Move overTime memory
		memmove(&overTime[0], &overTime[moveOverTime], remainingSlots*sizeof(*overTime));

		// Move client-specific overTime memory
		for(int clientID = 0; clientID < counters->clients; clientID++)
		{
			memmove(&clients[clientID].overTime[0], &clients[clientID].overTime[moveOverTime], remainingSlots*sizeof(int));
		}

		// Iterate over new overTime region and initialize it
		for(unsigned int i = remainingSlots; i < OVERTIME_SLOTS ; i++)
		{
			// This slot is OVERTIME_INTERVAL seconds after the previous slot
			time_t timestamp = overTime[i-1].timestamp + OVERTIME_INTERVAL;
			initSlot(i, timestamp);
		}
	}
}
