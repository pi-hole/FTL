/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  dnsmasq FIFO log for Pi-hole's API
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "fifo.h"
// {un,}lock_shm()
#include "shmem.h"

void add_to_dnsmasq_log_fifo_buffer(const char *payload, const int length)
{
	// Lock SHM
	lock_shm();

	unsigned int idx = fifo_log->next_id++;
	if(idx >= LOG_SIZE)
	{
		// Log is full, move everything one slot forward to make space for a new record at the end
		// This pruges the oldest message from the list (it is overwritten by the second message)
		memmove(fifo_log->message[0], fifo_log->message[1], (LOG_SIZE - 1u) * MAX_MESSAGE);
		memmove(&fifo_log->timestamp[0], &fifo_log->timestamp[1], (LOG_SIZE - 1u) * sizeof(time_t));
		idx = LOG_SIZE - 1u;
	}

	// Copy relevant string into temporary buffer
	size_t copybytes = length < MAX_MESSAGE ? length : MAX_MESSAGE;
	memcpy(fifo_log->message[idx], payload, copybytes);

	// Zero-terminate buffer, truncate newline if found
	if(fifo_log->message[idx][copybytes - 1u] == '\n')
	{
		fifo_log->message[idx][copybytes - 1u] = '\0';
	}
	else
	{
		fifo_log->message[idx][copybytes] = '\0';
	}

	// Set timestamp
	fifo_log->timestamp[idx] = time(NULL);

	// Unlock SHM
	unlock_shm();
}