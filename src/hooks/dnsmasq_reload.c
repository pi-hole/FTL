
/* Pi-hole: A black hole for Internet advertisements
*  (c) 2021 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq interfacing routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define FTL_PRIVATE
#include "dnsmasq_reload.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), etc.
#include "../shmem.h"
// set_event()
#include "../events.h"
// check_capabilities()
#include "../capabilities.h"
// resolver_ready
#include "../daemon.h"

void FTL_dnsmasq_reload(void)
{
	// This function is called by the dnsmasq code on receive of SIGHUP
	// *before* clearing the cache and rereading the lists
	log_info("Reloading DNS cache");
	lock_shm();

	// Request reload the privacy level
	set_event(RELOAD_PRIVACY_LEVEL);

	// Reread pihole-FTL.conf to see which blocking mode the user wants to use
	// It is possible to change the blocking mode here as we anyhow clear the
	// cache and reread all blocking lists
	// Passing NULL to this function means it has to open the config file on
	// its own behalf (on initial reading, the config file is already opened)
	getBlockingMode();

	// Reread pihole-FTL.conf to see which debugging flags are set
	readDebugSettings();

	// Gravity database updates
	// - (Re-)open gravity database connection
	// - Get number of blocked domains
	// - Read and compile regex filters (incl. per-client)
	// - Flush FTL's DNS cache
	set_event(RELOAD_GRAVITY);

	// Print current set of capabilities if requested via debug flag
	if(config.debug & DEBUG_CAPS)
		check_capabilities();

	unlock_shm();

	// Set resolver as ready
	resolver_ready = true;
}