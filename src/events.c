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
// atomic_exchange()
#include <stdatomic.h>
// struct config
#include "config/config.h"
// logging
#include "log.h"

// Private prototypes
static const char *eventtext(const enum events event);

// Queue containing all possible events
// An atomic_bool rather than an atomic_flag: a flag cannot be read without
// setting it, which is what used to lose events (see below). RELOAD_GRAVITY is
// raised from the SIGRTMIN handler, so the type has to be lock-free for the
// exchange to be async-signal-safe
static _Atomic bool eventqueue[EVENTS_MAX];
static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "Event queue must be lock-free, it is used from a signal handler");

// Set/Request event
// We set the events atomically to ensure no race collisions can happen. If an
// event has already been requested, this has no consequences as event cannot be
// added multiple times
void _set_event(const enum events event, int line, const char *function, const char *file)
{
	// Set eventqueue bit, learning what it was in the same operation
	const bool is_set = atomic_exchange(&eventqueue[event], true);

	// Possible debug logging
	if(config.debug.events.v.b)
	{
		log_debug(DEBUG_EVENTS, "Event %s -> %s    called from %s() (%s:%i)",
		          eventtext(event),
		          is_set ? "was ALREADY SET" : "now SET",
		          function, file, line);
	}
}

// Raise an event from a signal handler
// SIGRT_handler() already states that nothing async-signal-unsafe may run in
// it, but set_event() reaches log_debug() and from there _FTL_log(), which
// formats with printf and can take the SHM lock. Neither is allowed to happen
// with a signal interrupting arbitrary code, so the signal path gets the
// exchange on its own: the event is logged where it is processed anyway
void set_event_from_signal(const enum events event)
{
	atomic_exchange(&eventqueue[event], true);
}

// Get and clear event
// Reading and clearing happen in one exchange, so there is no window in which
// the queue holds a value neither side owns. This used to be an atomic_flag,
// which cannot be read without setting it: the consumer set the flag to learn
// its value and cleared it a few lines later, and any producer that ran in
// between saw a flag that was already set, treated its own event as a duplicate
// and dropped it. A lost RELOAD_GRAVITY means a list edit or `pihole reloaddns`
// reports success and never takes effect. Debug logging sits inside that window
// and widens it considerably.
// The exchange compiles to XCHG on x86_64 and i686, and to the LDAXRB/STLXRB
// pair on ARM64, the same instructions the flag used.
bool _get_and_clear_event(const enum events event, int line, const char *function, const char *file)
{
	// Read the bit and clear it in the same operation
	const bool is_set = atomic_exchange(&eventqueue[event], false);

	// Possible debug logging only for SET status, to avoid log file flooding with NOT SET messages
	if(is_set && config.debug.events.v.b)
	{
		log_debug(DEBUG_EVENTS, "Event %s -> was SET, now CLEARED    called from %s() (%s:%i)",
		          eventtext(event), function, file, line);
	}

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
		case SEARCH_LOOKUP_HASH_COLLISIONS:
			return "SEARCH_LOOKUP_HASH_COLLISIONS";
		case EVENTS_MAX: // fall through
		default:
			return "UNKNOWN";
	}
}
