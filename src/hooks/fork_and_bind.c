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
#include "fork_and_bind.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// daemonmode
#include "../args.h"
// threads array
#include "../daemon.h"
// thread routines
#include "../database/database-thread.h"
#include "../gc.h"
#include "../resolve.h"
// handle_realtime_signals()
#include "../signals.h"
// http_init()
#include "../webserver/webserver.h"
// init_pihole_PTR()
#include "pihole_PTR.h"

void FTL_fork_and_bind_sockets(struct passwd *ent_pw)
{
	// Going into daemon mode involves storing the
	// PID of the generated child process. If FTL
	// is asked to stay in foreground, we just save
	// the PID of the current process in the PID file
	if(daemonmode)
		go_daemon();
	else
		savepid();

	// Handle real-time signals in this process (and its children)
	// Helper processes are already split from the main instance
	// so they will not listen to real-time signals
	handle_realtime_signals();

	// We will use the attributes object later to start all threads in
	// detached mode
	pthread_attr_t attr;
	// Initialize thread attributes object with default attribute values
	pthread_attr_init(&attr);

	// Start database thread if database is used
	if(pthread_create( &threads[DB], &attr, DB_thread, NULL ) != 0)
	{
		log_crit("Unable to open database thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until garbage
	// collection needs to be done
	if(pthread_create( &threads[GC], &attr, GC_thread, NULL ) != 0)
	{
		log_crit("Unable to open GC thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Start thread that will stay in the background until host names
	// needs to be resolved
	if(pthread_create( &threads[DNSclient], &attr, DNSclient_thread, NULL ) != 0)
	{
		log_crit("Unable to open DNS client thread. Exiting...");
		exit(EXIT_FAILURE);
	}

	// Chown files if FTL started as user root but a dnsmasq config
	// option states to run as a different user/group (e.g. "nobody")
	if(getuid() == 0)
	{
		// Only print this and change ownership of shmem objects when
		// we're actually dropping root (user/group my be set to root)
		if(ent_pw != NULL && ent_pw->pw_uid != 0)
		{
			log_info("FTL is going to drop from root to user %s (UID %d)",
			         ent_pw->pw_name, (int)ent_pw->pw_uid);
			if(chown(config.files.log, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
				log_warn("Setting ownership (%i:%i) of %s failed: %s (%i)",
				ent_pw->pw_uid, ent_pw->pw_gid, config.files.log, strerror(errno), errno);
			if(chown(config.files.database, ent_pw->pw_uid, ent_pw->pw_gid) == -1)
				log_warn("Setting ownership (%i:%i) of %s failed: %s (%i)",
				ent_pw->pw_uid, ent_pw->pw_gid, config.files.database, strerror(errno), errno);
			chown_all_shmem(ent_pw);
		}
		else
		{
			log_info("FTL is running as root");
		}
	}
	else
	{
		uid_t uid;
		struct passwd *current_user;
		if ((current_user = getpwuid(uid = geteuid())) != NULL)
			log_info("FTL is running as user %s (UID %d)",
			         current_user->pw_name, (int)current_user->pw_uid);
		else
			log_info("Failed to obtain information about FTL's owner");
	}

	// Obtain DNS port from dnsmasq daemon
	config.dns_port = daemon->port;

	// Initialize FTL HTTP server
	http_init();

	// Initialize Pi-hole PTR pointer
	init_pihole_PTR();
}
