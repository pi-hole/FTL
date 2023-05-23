/* Pi-hole: A black hole for Internet advertisements
*  (c) 2020 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Pi-hole syscall implementation for sendto
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "../FTL.h"
//#include "syscalls.h" is implicitly done in FTL.h
#include "../log.h"

#include <sys/types.h>
#include <sys/socket.h>

#undef sendto
ssize_t FTLsendto(int sockfd, void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen, const char *file, const char *func, const int line)
{
	ssize_t ret = 0;
	do
	{
		// Reset errno before trying to write
		errno = 0;
		ret = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	}
	// Try again if the last accept() call failed due to an interruption by an
	// incoming signal
	while(ret < 0 && errno == EINTR);

	// Backup errno value
	const int _errno = errno;

	// Final error checking (may have failed for some other reason then an
	// EINTR = interrupted system call), also ignore EPROTONOSUPPORT (ARP scanning)
	// and EPERM + ENOKEY (DHCP probing)
	if(ret < 0 && errno != EPROTONOSUPPORT && errno != EPERM && errno != ENOKEY)
		log_warn("Could not sendto() in %s() (%s:%i): %s",
		         func, file, line, strerror(errno));

	// Restore errno value
	errno = _errno;

	return ret;
}