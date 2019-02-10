#include "FTL.h"

void initOverTime(void)
{
	// Get current timestamp
	time_t now = time(NULL);

	// Center in first interval of next full hour
	time_t timestamp = now - now % 3600 + 3600 - OVERTIME_INTERVAL/2;

	if(debug) logg("initOverTime(): Initializing %i slots from %u to %u", OVERTIME_SLOTS, timestamp-OVERTIME_SLOTS*OVERTIME_INTERVAL, timestamp);

	// Iterate over overTime and initialize it
	for(int i = OVERTIME_SLOTS-1; i >= 0 ; i--)
	{
		// Set magic byte
		overTime[i].magic = MAGICBYTE;

		// Set timestamp for this overTime slot
		// Center timestamp in interval
		overTime[i].timestamp = timestamp;
		logg("Writing %i = %u", i, timestamp);

		// Initialize counters
		overTime[i].total = 0;
		overTime[i].blocked = 0;
		overTime[i].cached = 0;
		overTime[i].forwarded = 0;
		for(int j; j < TYPE_MAX; j++)
			overTime[i].querytypedata[j] = 0;

		// Prepare for next iteration
		timestamp -= OVERTIME_INTERVAL;
	}
}

int getOverTimeID(time_t timestamp)
{
	// Get current timestamp
	time_t now = time(NULL);

	// Center in first interval of next full hour
	time_t nextHour = now - now % 3600 + 3600 + OVERTIME_INTERVAL/2;

	// Center timestamp in OVERTIME_INTERVAL
	timestamp -= timestamp % OVERTIME_INTERVAL;
	timestamp += OVERTIME_INTERVAL/2;

	// Use integer arithmetic here
	int overTimeID = OVERTIME_SLOTS - (nextHour - timestamp)/OVERTIME_INTERVAL;

	// Validity check
	if(overTimeID < 0 || overTimeID > OVERTIME_SLOTS)
	{
		logg("WARN: overTime ID invalid:\n%i = %i - (%u - %u)/%i\n now = %u", overTimeID, OVERTIME_SLOTS, nextHour, timestamp, OVERTIME_INTERVAL, now);
		return OVERTIME_NOT_AVAILABLE;
	}

	// Exact match check
	if(overTime[overTimeID].timestamp != timestamp)
	{
		// This might happen when we are already in a new hour but
		// GC didn't initialize the next hour already, we discard
		// this query in this case
		logg("WARN: overTime ID %i: %i != %i", overTimeID, overTime[overTimeID].timestamp, timestamp);
		return OVERTIME_NOT_AVAILABLE;
	}

	logg("Valid overTime: %i, %u", overTimeID, timestamp);

	return overTimeID;
}

// This routine is called by garbage collection to rearrange the overTime structure for the next hour
void moveOverTimeMemory(void)
{
	time_t oldestOverTimeIS = overTime[0].timestamp;
	time_t oldestOverTimeSHOULD = time(NULL) - 24*3600;
	int moveOverTime = (oldestOverTimeSHOULD - oldestOverTimeIS) / OVERTIME_INTERVAL;
	if(debug) logg("moveOverTimeMemory(): IS: %u, SHOULD: %i, MOVING: %i", oldestOverTimeIS, oldestOverTimeSHOULD, moveOverTime);
	if(moveOverTime > 0 && moveOverTime < OVERTIME_SLOTS)
	{
		// Move overTime memory
		memmove(&overTime[0], &overTime[moveOverTime], (OVERTIME_SLOTS-moveOverTime)*sizeof(*overTime));

		// Iterate over new overTime region and initialize it
		for(int i = OVERTIME_SLOTS-moveOverTime; i < OVERTIME_SLOTS ; i++)
		{
			// Set magic byte
			overTime[i].magic = MAGICBYTE;

			// Set timestamp for this overTime slot
			overTime[i].timestamp = overTime[i-1].timestamp + OVERTIME_INTERVAL;

			if(debug) logg("moveOverTimeMemory: %i is now timestamp %u", i, overTime[i].timestamp);

			// Initialize counters
			overTime[i].total = 0;
			overTime[i].blocked = 0;
			overTime[i].cached = 0;
			overTime[i].forwarded = 0;
			for(int j; j < TYPE_MAX; j++)
				overTime[i].querytypedata[j] = 0;
		}
		// Move client-specific overTime counters
		for(int clientID = 0; clientID < counters->clients; clientID++)
			memmove(&clients[clientID].overTime[0], &clients[clientID].overTime[moveOverTime], (OVERTIME_SLOTS-moveOverTime)*sizeof(clients[clientID].overTime[0]));
	}
}
