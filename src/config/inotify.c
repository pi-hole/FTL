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
#include "FTL.h"
#include "log.h"
#include <sys/inotify.h>
// NAME_MAX
#include <linux/limits.h>
// FILE
#include <stdio.h>
// sleepms()
#include "timers.h"
// select()
#include <sys/select.h>
#include <sys/time.h>
// free()
#include <stdlib.h>

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

// Scan a FILE stream for a target substring appended since the last scan.
static bool scan_file(FILE *file, const char *string, long *last_size, size_t *len, char **line)
{
	// File was modified, get new filesize
	fseek(file, 0, SEEK_END);
	const long newsize = ftell(file);

	// If file has grown (or is larger than initial position), read new
	// lines
	if(newsize > *last_size)
	{
		// Seek to previous scan position
		fseek(file, *last_size, SEEK_SET);
		// Read new lines
		bool found = false;
		while(getline(line, len, file) != -1)
		{
			// Check for target string
			log_debug(DEBUG_INOTIFY, "Read new line: \"%s\"", *line);
			if(strstr(*line, string) != NULL)
			{
				found = true;
				break;
			}
		}
		if(found)
			return true;

		// Update last_size position
		*last_size = ftell(file);
	}

	return false;
}

/**
 * @brief Waits for a specific string to appear in a file, scanning the last N
 * lines and monitoring for new content.
 *
 * This function uses inotify to monitor the file for modifications and checks
 * any new lines appended to the file for the target string, waiting up to the
 * specified timeout.
 *
 * @param filename The path to the file to be monitored.
 * @param string The string to search for within the file.
 * @param timeout The maximum time to wait (in seconds) for the string to appear
 * in the file.
 * @param initial_filesize The initial size of the file to start reading from.
 * If set to 0, the function will start reading from the end of the file.
 * @return true if the string is found within the timeout period, false otherwise.
 */
bool wait_for_string_in_file(const char *filename, const char *string, unsigned int timeout, long initial_filesize)
{
	// Open the file for reading
	FILE *file = fopen(filename, "r");
	if(file == NULL)
	{
		// Return false if file cannot be opened
		log_err("Cannot open file %s: %s", filename, strerror(errno));
		return false;
	}

	// Get current file size if initial_filesize is < 0
	if (initial_filesize < 0)
	{
		log_debug(DEBUG_INOTIFY, "Determining filesize at invocation time");
		if(fseek(file, 0, SEEK_END) != 0)
		{
			// Return false if seek fails
			fclose(file);
			log_err("Cannot seek in file %s: %s", filename, strerror(errno));
			return false;
		}
		// Get the current file size
		initial_filesize = ftell(file);
	}
	log_debug(DEBUG_INOTIFY, "Starting to read file %s from byte offset %ld", filename, initial_filesize);

	// Perform initial read
	size_t len = 0;
	char *line = NULL;
	bool found = false;
	long scan_start = initial_filesize;
	if(scan_file(file, string, &scan_start, &len, &line))
	{
		// String found in initial scan
		log_info("Found string \"%s\" in file %s (initial scan)", string, filename);
		if(line != NULL)
			free(line);
		fclose(file);
		return true;
	}
	
	// Use inotify to wait for new lines appended to the file
	// Create inotify instance (non-blocking)
	const int fd = inotify_init1(IN_NONBLOCK);
	if(fd == -1)
	{
		log_err("Cannot create inotify instance: %s", strerror(errno));
		fclose(file);
		return false;
	}

	// Add watch for file modifications
	const int wd = inotify_add_watch(fd, filename, IN_CLOSE_WRITE | IN_MODIFY);
	if(wd == -1)
	{
		log_err("Cannot add inotify watch for %s: %s", filename, strerror(errno));
		close(fd);
		fclose(file);
		return false;
	}

	// Initialize time tracking
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);

	// Loop until we found the string or timeout reached
	while(!found && time_diff(ts, now) < timeout)
	{
		// Set up select() for waiting on inotify events with a timeout.
		// These need to be reset before each call to select()
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		struct timeval tv = { .tv_sec = 0, .tv_usec = 25000 };

		// Wait for inotify event or timeout
		const int retval = select(fd + 1, &rfds, NULL, NULL, &tv);

		// Check if inotify event is available
		if(retval < 1 || !FD_ISSET(fd, &rfds))
		{
			// No inotify event, just continue waiting
			clock_gettime(CLOCK_REALTIME, &now);
			continue;
		}

		// Inotify event available, read it
		char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
		// Read event from inotify fd
		ssize_t len_ev = read(fd, buf, sizeof(buf));
		if(len_ev > 0)
		{
			struct inotify_event event;
			memcpy(&event, buf, sizeof(struct inotify_event));
			if(event.wd != wd || !(event.mask & (IN_MODIFY | IN_CLOSE_WRITE)))
			{
				// Not the event we are looking for, continue waiting
				clock_gettime(CLOCK_REALTIME, &now);
				continue;
			}
		}
		else
		{
			// Read error, continue waiting
			clock_gettime(CLOCK_REALTIME, &now);
			continue;
		}

		found = scan_file(file, string, &scan_start, &len, &line);

		// Update current time
		clock_gettime(CLOCK_REALTIME, &now);
	}

	// Clean up
	inotify_rm_watch(fd, wd);
	close(fd);
	if(line != NULL)
		free(line);
	fclose(file);

	if(found)
		log_info("Found string \"%s\" in file %s", string, filename);
	else
		log_info("Did not find string \"%s\" in file %s within %u seconds", string, filename, timeout);

	return found;
}
