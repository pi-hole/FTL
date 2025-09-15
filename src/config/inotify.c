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

/**
 * @brief Waits for a specific string to appear in a file, scanning the last N
 * lines and monitoring for new content.
 *
 * This function searches for a given string in the last MAX_LINES lines of the
 * specified file. If the string is not found, it uses inotify to monitor the
 * file for modifications and checks any new lines appended to the file for the
 * target string, waiting up to the specified timeout.
 *
 * @param filename The path to the file to be monitored.
 * @param string The string to search for within the file.
 * @param timeout The maximum time to wait (in seconds) for the string to appear
 * in the file.
 * @return true if the string is found within the timeout period, false otherwise.
 */
bool wait_for_string_in_file(const char *filename, const char *string, unsigned int timeout)
{
	// Open the file for reading
	FILE *file = fopen(filename, "r");
	if(file == NULL)
	{
		// Return false if file cannot be opened
		printf("Cannot open file %s: %s\n", filename, strerror(errno));
		return false;
	}

	// Seek to the end of the file to determine its size
	if(fseek(file, 0, SEEK_END) != 0)
	{
		// Return false if seek fails
		fclose(file);
		printf("Cannot seek in file %s: %s\n", filename, strerror(errno));
		return false;
	}
	// Get the current file size
	const long initial_filesize = ftell(file);

	// Scan backwards for the last X lines in the file
	// Maximum number of lines to scan backwards
	#define MAX_LINES 100
	// Size of buffer chunk for reading
	#define CHUNK_SIZE 4096
	long pos = initial_filesize;
	int lines_found = 0;
	size_t len = CHUNK_SIZE;
	char *line = calloc(len, sizeof(char));
	long scan_start = initial_filesize;

	// Loop until X lines found or start of file reached
	while(pos > 0 && lines_found < MAX_LINES)
	{
		// Determine how much to read (either CHUNK_SIZE or remaining bytes)
		size_t to_read = (pos >= CHUNK_SIZE) ? CHUNK_SIZE : pos;
		// Move position backwards
		pos -= to_read;
		// Seek to new position
		fseek(file, pos, SEEK_SET);
		// Read chunk into buffer
		size_t read = fread(line, 1, to_read, file);
		// Scan line backwards for newlines
		for(int i = read - 1; i >= 0; i--)
		{
			if(line[i] == '\n')
			{
				// Newline found, increment line counter
				lines_found++;
				if(lines_found == MAX_LINES)
				{
					// Found enough lines, set scan_start position
					scan_start = pos + i + 1;
					break;
				}
			}
		}
	}

	// Start reading from the scan_start position
	fseek(file, scan_start, SEEK_SET);
	// Check if line contains target string
	bool found = false;
	while(getline(&line, &len, file) != -1)
	{
		if(strstr(line, string) != NULL)
		{
			found = true;
			break;
		}
	}
	if(found)
	{
		// String found during initial scan
		free(line);
		fclose(file);
		printf("Found string \"%s\" in file %s\n", string, filename);
		return true;
	}

	// Use inotify to wait for new lines appended to the file
	// Create inotify instance (non-blocking)
	const int fd = inotify_init1(IN_NONBLOCK);
	if(fd == -1)
	{
		printf("Cannot create inotify instance: %s\n", strerror(errno));
		free(line);
		fclose(file);
		return false;
	}

	// Add watch for file modifications
	const int wd = inotify_add_watch(fd, filename, IN_MODIFY);
	if(wd == -1)
	{
		printf("Cannot add inotify watch for %s: %s\n", filename, strerror(errno));
		close(fd);
		free(line);
		fclose(file);
		return false;
	}

	// Counter for wait iterations
	unsigned int waited = 0;

	// Loop until timeout reached (25ms * 40 = 1s) or string found
	while(waited < timeout * 40)
	{
		// Set up select() for waiting on inotify events with a timeout.
		// These need to be reset before each call to select()
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		struct timeval tv = { .tv_sec = 0, .tv_usec = 25000 };

		// Wait for inotify event or timeout
		const int retval = select(fd + 1, &rfds, NULL, NULL, &tv);

		// Increment wait counter
		waited++;

		// Check if inotify event is available
		if(retval < 1 || !FD_ISSET(fd, &rfds))
			// No inotify event, just continue waiting
			continue;

		// Inotify event available, read it
		char buf[sizeof(struct inotify_event) + NAME_MAX + 1];
		// Read event from inotify fd
		ssize_t len_ev = read(fd, buf, sizeof(buf));
		if(len_ev > 0)
		{
			struct inotify_event event;
			memcpy(&event, buf, sizeof(struct inotify_event));
			if(event.wd != wd || !(event.mask & IN_MODIFY))
			{
				// Not the event we are looking for, continue waiting
				continue;
			}
		}
		else
		{
			// Read error, continue waiting
			continue;
		}
		// File was modified, get new filesize
		fseek(file, 0, SEEK_END);
		const long newsize = ftell(file);

		// If file has grown, read new lines
		if(newsize > scan_start)
		{
			// Seek to previous scan position
			fseek(file, scan_start, SEEK_SET);
			// Read new lines
			while(getline(&line, &len, file) != -1)
			{
				// Check for target string
				if(strstr(line, string) != NULL)
				{
					found = true;
					break;
				}
			}
			if(found)
				break;
			// Update scan_start position
			scan_start = ftell(file);
		}
	}

	// Clean up
	inotify_rm_watch(fd, wd);
	close(fd);
	free(line);
	fclose(file);

	if(found)
		printf("Found string \"%s\" in file %s\n", string, filename);
	else
		printf("Did not find string \"%s\" in file %s within %u seconds\n", string, filename, timeout);

	return found;
}