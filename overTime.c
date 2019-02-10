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

	for(int j = 0; j < TYPE_MAX; j++)
		overTime[index].querytypedata[j] = 0;
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

int getOverTimeID(time_t timestamp)
{
	// Center timestamp in OVERTIME_INTERVAL
	timestamp -= timestamp % OVERTIME_INTERVAL;
	timestamp += OVERTIME_INTERVAL/2;

	// Get timestamp of first interval
	time_t firstTimestamp = overTime[0].timestamp;

	return (int) ((timestamp - firstTimestamp) / OVERTIME_INTERVAL);
}

// This routine is called by garbage collection to rearrange the overTime structure for the next hour
void moveOverTimeMemory(void)
{
	time_t oldestOverTimeIS = overTime[0].timestamp;
	time_t oldestOverTimeSHOULD = time(NULL) - 24*3600;

	// Center in interval
	oldestOverTimeSHOULD -= oldestOverTimeSHOULD % OVERTIME_INTERVAL;
	oldestOverTimeSHOULD += OVERTIME_INTERVAL / 2;

	// Calculate the number of slots to be garbage collected, which is also the
	// ID of the slot to move to the zero position
	int moveOverTime = (int) ((oldestOverTimeSHOULD - oldestOverTimeIS) / OVERTIME_INTERVAL);

	// The number of slots which will be moved (not garbage collected)
	int remainingSlots = OVERTIME_SLOTS - moveOverTime;

	if(debug) logg("moveOverTimeMemory(): IS: %u, SHOULD: %i, MOVING: %i", oldestOverTimeIS, oldestOverTimeSHOULD, moveOverTime);

	// Check if the move over amount is valid. This prevents errors if the
	// function is called before GC is necessary.
	if(moveOverTime > 0 && moveOverTime < OVERTIME_SLOTS)
	{
		// Move overTime memory
		memmove(&overTime[0], &overTime[moveOverTime], remainingSlots*sizeof(*overTime));

		// Iterate over new overTime region and initialize it
		for(int i = remainingSlots; i < OVERTIME_SLOTS ; i++)
		{
			// This slot is OVERTIME_INTERVAL seconds after the previous slot
			time_t timestamp = overTime[i-1].timestamp + OVERTIME_INTERVAL;

			initSlot(i, timestamp);
		}

		// Move client-specific overTime counters
		for(int clientID = 0; clientID < counters->clients; clientID++)
			memmove(&clients[clientID].overTime[0], &clients[clientID].overTime[moveOverTime], remainingSlots*sizeof(clients[clientID].overTime[0]));
	}
}
