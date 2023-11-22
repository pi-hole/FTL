/* Pi-hole: A black hole for Internet advertisements
*  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Config inotify routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "config/inotify.h"
#include "log.h"
#include <sys/inotify.h>
// NAME_MAX
#include <limits.h>

#define WATCHDIR "/etc/pihole"

static int inotify_fd = -1;
static int inotify_wd = -1;

static bool create_inotify_watcher(void)
{
	// Create inotify instance
	inotify_fd = inotify_init1(IN_NONBLOCK);
	if(inotify_fd == -1)
	{
		log_warn("Cannot create inotify instance: %s", strerror(errno));
		return false;
	}

	// Add watch to inotify instance
	// We are interested in the following events:
	// - IN_CREATE: File was created
	// - IN_CLOSE_WRITE: File was closed after writing
	// - IN_MOVE: File was moved
	// - IN_DELETE: File was deleted
	// - IN_ONLYDIR: Race-free check of ensuring that the monitored object is a directory
	inotify_wd = inotify_add_watch(inotify_fd, WATCHDIR, IN_CREATE | IN_CLOSE_WRITE | IN_MOVE | IN_DELETE | IN_ONLYDIR);
	if(inotify_wd == -1)
	{
		log_warn("Cannot add watching of "WATCHDIR" to inotify instance: %s", strerror(errno));
		return false;
	}

	log_debug(DEBUG_INOTIFY, "Created inotify watcher for "WATCHDIR);
	return true;
}

static void close_inotify_watcher(void)
{
	// Harmless no-op, this happens at the first refresh of dnsmasq
	if(inotify_fd == -1 && inotify_wd == -1)
		return;

	// Remove watch from inotify instance
	if(inotify_rm_watch(inotify_fd, inotify_wd) == -1)
		log_warn("Cannot remove watch from inotify instance: %s", strerror(errno));
	inotify_wd = -1;

	// Close inotify instance
	if(close(inotify_fd) == -1)
		log_warn("Cannot close inotify instance: %s", strerror(errno));
	inotify_fd = -1;

	log_debug(DEBUG_INOTIFY, "Closed inotify watcher");
}

void watch_config(bool watch)
{
	// Set global variable
	if(watch)
		create_inotify_watcher();
	else
		close_inotify_watcher();
}

bool check_inotify_event(void)
{
	// Check if we are watching for changes
	if(inotify_fd == -1 || inotify_wd == -1)
		return false;

	// Read inotify events (if any)
	// The buffer size is chosen to be large enough to read at least ten events
	char buf[10*(sizeof(struct inotify_event) + NAME_MAX + 1)];
	const ssize_t len = read(inotify_fd, buf, sizeof(buf));
	if(len == -1 && errno != EAGAIN)
	{
		log_err("Cannot read inotify events: %s", strerror(errno));
		return false;
	}

	// Process all events
	void *ptr;
	bool config_changed = false;
	const struct inotify_event *event;
	for (ptr = buf; ptr < (void*)buf + len; ptr += sizeof(struct inotify_event) + event->len)
	{
		event = (const struct inotify_event *) ptr;

		// Check if this is the correct watch descriptor
		if(event->wd != inotify_wd)
			continue;

		// Check if this is the event we are looking for
		if(event->mask & IN_CLOSE_WRITE)
		{
			// File opened for writing was closed
			log_debug(DEBUG_INOTIFY, "File written: "WATCHDIR"/%s", event->name);
			if(strcmp(event->name, "pihole.toml") == 0)
				config_changed = true;
		}
		else if(event->mask & IN_CREATE)
		{
			// File was created
			log_debug(DEBUG_INOTIFY, "File created: "WATCHDIR"/%s", event->name);
		}
		else if(event->mask & IN_MOVED_FROM)
		{
			// File was moved (source)
			log_debug(DEBUG_INOTIFY, "File moved from: "WATCHDIR"/%s", event->name);
		}
		else if(event->mask & IN_MOVED_TO)
		{
			// File was moved (target)
			log_debug(DEBUG_INOTIFY, "File moved to: "WATCHDIR"/%s", event->name);
			if(strcmp(event->name, "pihole.toml") == 0)
				config_changed = true;
		}
		else if(event->mask & IN_DELETE)
		{
			// File was deleted
			log_debug(DEBUG_INOTIFY, "File deleted: "WATCHDIR"/%s", event->name);
		}
		else if(event->mask & IN_IGNORED)
		{
			// Watch descriptor was removed
			log_warn("Inotify watch descriptor for "WATCHDIR" was removed (directory deleted or unmounted?)");
		}
		else
			log_debug(DEBUG_INOTIFY, "Unknown event (%X) on watched file: "WATCHDIR"/%s", event->mask, event->name);
	}

	return config_changed;
}
