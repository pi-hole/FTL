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
#include "tcp_workers.h"
// struct queriesData, etc.
#include "../datastructure.h"
// struct config
#include "../config/config.h"
// logging routines
#include "../log.h"
// lock_shm(), addstr(), etc.
#include "../shmem.h"
// gravityDB_forked()
#include "../database/gravity-db.h"
// atomic_flag_test_and_set()
#include <stdatomic.h>
// dnsmasq_debug
#include "../args.h"
// next_iface
#include "iface.h"
// main_pid()
#include "../signals.h"

// Pointer to the privacy level to be used in a special dnsmasq TXT record
unsigned char *pihole_privacylevel = &config.privacylevel;

// Called when a (forked) TCP worker is terminated by receiving SIGALRM
// We close the dedicated database connection this client had opened
// to avoid dangling database locks
volatile atomic_flag worker_already_terminating = ATOMIC_FLAG_INIT;
void FTL_TCP_worker_terminating(bool finished)
{
	if(dnsmasq_debug)
	{
		// Nothing to be done here, forking does not happen in debug mode
		return;
	}

	if(atomic_flag_test_and_set(&worker_already_terminating))
	{
		log_debug(DEBUG_ANY, "TCP worker already terminating!");
		return;
	}

	// Possible debug logging
	if(config.debug != 0)
	{
		const char *reason = finished ? "client disconnected" : "timeout";
		log_debug(DEBUG_ANY, "TCP worker terminating (%s)", reason);
	}

	if(main_pid() == getpid())
	{
		// If this is not really a fork (e.g. in debug mode), we don't
		// actually close gravity here
		return;
	}

	// First check if we already locked before. This can happen when a fork
	// is running into a timeout while it is still processing something and
	// still holding a lock.
	if(!is_our_lock())
		lock_shm();

	// Close dedicated database connections of this fork
	gravityDB_close();
	unlock_shm();
}

// Called when a (forked) TCP worker is created
// FTL forked to handle TCP connections with dedicated (forked) workers
// SQLite3's mentions that carrying an open database connection across a
// fork() can lead to all kinds of locking problems as SQLite3 was not
// intended to work under such circumstances. Doing so may easily lead
// to ending up with a corrupted database.
void FTL_TCP_worker_created(const int confd)
{
	if(dnsmasq_debug)
	{
		// Nothing to be done here, TCP worker forking does not happen
		// in debug mode
		return;
	}

	// Print this if any debug setting is enabled
	if(config.debug != 0)
	{
		// Get peer IP address (client)
		char peer_ip[ADDRSTRLEN] = { 0 };
		union mysockaddr peer_sockaddr = {{ 0 }};
		socklen_t peer_len = sizeof(union mysockaddr);
		if (getpeername(confd, (struct sockaddr *)&peer_sockaddr, &peer_len) != -1)
		{
			union all_addr peer_addr = {{ 0 }};
			if (peer_sockaddr.sa.sa_family == AF_INET6)
				peer_addr.addr6 = peer_sockaddr.in6.sin6_addr;
			else
				peer_addr.addr4 = peer_sockaddr.in.sin_addr;
			inet_ntop(peer_sockaddr.sa.sa_family, &peer_addr, peer_ip, ADDRSTRLEN);
		}

		// Get local IP address (interface)
		char local_ip[ADDRSTRLEN] = { 0 };
		union mysockaddr iface_sockaddr = {{ 0 }};
		socklen_t iface_len = sizeof(union mysockaddr);
		if(getsockname(confd, (struct sockaddr *)&iface_sockaddr, &iface_len) != -1)
		{
			union all_addr iface_addr = {{ 0 }};
			if (iface_sockaddr.sa.sa_family == AF_INET6)
				iface_addr.addr6 = iface_sockaddr.in6.sin6_addr;
			else
				iface_addr.addr4 = iface_sockaddr.in.sin_addr;
			inet_ntop(iface_sockaddr.sa.sa_family, &iface_addr, local_ip, ADDRSTRLEN);
		}

		// Print log
		log_debug(DEBUG_ANY, "TCP worker forked for client %s on interface %s with IP %s",
		          peer_ip, next_iface.name, local_ip);
	}

	if(main_pid() == getpid())
	{
		// If this is not really a fork (e.g. in debug mode), we don't
		// actually re-open gravity or close sockets here
		return;
	}

	// Reopen gravity database handle in this fork as the main process's
	// handle isn't valid here
	log_debug(DEBUG_ANY, "Reopening Gravity database for this fork");
	gravityDB_forked();
}