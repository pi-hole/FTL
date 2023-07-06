/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Event queue processing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */


#include "FTL.h"
// public prototypes
#include "events.h"
// atomic_flag_test_and_set()
#include <stdatomic.h>
// struct config
#include "config/config.h"
// logging
#include "log.h"

// Private prototypes
static const char *eventtext(const enum events event);

// Queue containing all possible events
static volatile atomic_flag eventqueue[EVENTS_MAX] = { ATOMIC_FLAG_INIT };

// Set/Request event
// We set the events atomically to ensure no race collisions can happen. If an
// event has already been requested, this has no consequences as event cannot be
// added multiple times
void _set_event(const enum events event, int line, const char *function, const char *file)
{
	bool is_set = false;
	// Set eventqueue bit
	if(atomic_flag_test_and_set(&eventqueue[event]))
		is_set = true;

	// Possible debug logging
	if(config.debug.events.v.b)
	{
		log_debug(DEBUG_EVENTS, "Event %s -> %s    called from %s() (%s:%i)",
		          eventtext(event),
		          is_set ? "was ALREADY SET" : "now SET",
		          function, file, line);
	}
}

// Get and clear event
// Unfortunately, we cannot read the value of an atomic_flag without setting it
// either to true or false. This is by design. Hence, we implement testing by
// first trying to set the the flag to true. If this "fails", we know the flag
// has already been set.
// On x86_64 and i686 CPUs, these atomic instrictions are implemented using the
// XCHG asm instruction, which simply exchanges the content of two registers or,
// in this case, a register and a memory location (the respective eventqueue
// pointer). This is guaranteed to happen atomically by automatically
// implementing the processor's locking protocol during the operation.
// On other architecture, similar instructions are used to reassemble the same
// effect (but typically with a few more instructions). ARM64, for instance,
// uses LDAXRB (Load-aquire exclusive register byte) and STAXRB (Store-release
// exclusive register byte) to implement the same thing with a few more
// instructions.
bool _get_and_clear_event(const enum events event, int line, const char *function, const char *file)
{
	bool is_set = false;
	if(atomic_flag_test_and_set(&eventqueue[event]))
		is_set = true;

	// Possible debug logging only for SET status, to avoid log file flooding with NOT SET messages
	if(is_set && config.debug.events.v.b)
	{
		log_debug(DEBUG_EVENTS, "Event %s -> was SET, now CLEARED    called from %s() (%s:%i)",
		          eventtext(event), function, file, line);
	}

	// Clear eventqueue bit (we set it above) ...
	atomic_flag_clear(&eventqueue[event]);

	// ... and return status
	return is_set;
}

// Output human-readable version event text representation
static const char *eventtext(const enum events event)
{
	switch(event)
	{
		case RELOAD_GRAVITY:
			return "RELOAD_GRAVITY";
		case RERESOLVE_HOSTNAMES:
			return "RERESOLVE_HOSTNAMES";
		case RERESOLVE_HOSTNAMES_FORCE:
			return "RERESOLVE_HOSTNAMES_FORCE";
		case REIMPORT_ALIASCLIENTS:
			return "REIMPORT_ALIASCLIENTS";
		case PARSE_NEIGHBOR_CACHE:
			return "PARSE_NEIGHBOR_CACHE";
		case RESOLVE_NEW_HOSTNAMES:
			return "RESOLVE_NEW_HOSTNAMES";
		case EVENTS_MAX: // fall through
		default:
			return "UNKNOWN";
	}
}
