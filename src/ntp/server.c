/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  NTP server routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
// exit(0)
#include <stdlib.h>
// memcpy()
#include <string.h>
// close()
#include <unistd.h>
// fork(), wait()
#include <signal.h>
// clock_gettime()
#include <sys/time.h>
//#include <sys/types.h>
#include <sys/wait.h>
// wait()
#include <sys/socket.h>
// htonl(), etc.
#include <arpa/inet.h>
// errno
#include <errno.h>
// ctime()
#include <time.h>
// log2()
#include <math.h>
// pthread_create
#include <pthread.h>
// PR_SET_NAME
#include <sys/prctl.h>

#include "ntp/ntp.h"
#include "log.h"
#include "config/config.h"

// Retrieves the current system time, adjusts it to a 1900 epoch, converts it to
// a 32-bit fraction of a second, and optionally converts it to network byte
// order.
void gettime32(uint32_t tv[], const bool netorder)
{
	struct timespec ts;
	// CLOCK_REALTIME is the system-wide realtime clock.
	// It is both affected by discontinuous jumps in the system time (e.g.,
	// if the system administrator manually changes the clock), and by the
	// incremental adjustments performed by adjtime(3) and NTP.
	clock_gettime(CLOCK_REALTIME, &ts);

	// Set the epoch to 1900 (add seconds from 1900 to 1970)
	tv[0] = ts.tv_sec + 2208988800ULL;
	// Convert microseconds to 32 bit fraction of a second
	tv[1] = (ts.tv_nsec * 0x100000000ULL) / 1000000000ULL;

	if (netorder)
	{
		tv[0] = htonl(tv[0]);
		tv[1] = htonl(tv[1]);
	}
}

// Create and send an NTP reply to the client
static int ntp_reply(const int socket_fd, const struct sockaddr *saddr_p, const socklen_t saddrlen,
                     const unsigned char recv_buf[], const uint32_t recv_time[2])
{
	// Buffer for the response
	unsigned char send_buf[48];
	memset(send_buf, 0, sizeof(send_buf));

	// DWORD-aligned pointer to the send buffer
	uint32_t *u32p = (uint32_t*)((void*)&send_buf[0]);
	// DWORD-aligned read-only pointer to the receive buffer
	const uint32_t *u32r = (uint32_t*)((void*)&recv_buf[0]);

//      NTP Packet Header Format (RFC 5905), page 18
//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 	// Check if the first byte is valid: mode is expected to be 3 ("client")
	if ((recv_buf[0] & 0x07) != 0x3) {
		log_warn("Received invalid NTP request: not from an NTP client, ignoring");
		return 1;
	}

	// set LI = 0 (no warning about leap seconds), set version-number to
	// 4 and set mode = 4 ("server")
	send_buf[0] = (0x04 << 3) + 0x04;

	// Set stratum to "secondary server" as we have derived time via
	// external NTP as well. May be set to 1 if we want to be a primary
	// server (synchronized by a hardware clock with GPS, etc.)
	send_buf[1] = 0x02;

	// Copy Poll value from client
	send_buf[2] = recv_buf[2];

	// Precision in Nanoseconds from CLOCK_REALTIME
	struct timespec ts;
	clock_getres(CLOCK_REALTIME, &ts);
	// Precision in log2 seconds
	signed char precision = (signed char)(1.0*log2(1e-9*ts.tv_nsec));
	// Precision in log2 seconds
	send_buf[3] = precision;

	// Advance 32 bit pointer to the next field
	u32p++;

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                         Root Delay                            |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                         Root Dispersion                       |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	/* zur Vereinfachung , Root Delay = 0, Root Dispersion = 0 */
	*u32p++ = 0;
	*u32p++ = 0;

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                          Reference ID                         |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// Reference ID = 'LOCL" (LOCAL CLOCK)
	// A four-octet, left-justified, zero-padded ASCII string assigned to
	// the reference clock
	memcpy(u32p++, "LOCL", 4);

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                     Reference Timestamp (64)                  +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// Time when the system clock was last set or corrected, in NTP
	// timestamp format. As this is not a stratum 1 server, we don't have
	// a hardware clock to set this value.
#ifdef MOCK_REFTIME
	// Mock this timestamp with the current time of the server minus 1
	// minute.
	uint32_t ref_time[2];
	gettime32(ref_time, true);
	ref_time[0] = ref_time[0] - htonl(60);  // subtract 60 seconds
	memcpy(u32p, ref_time, 2 * sizeof(uint32_t));
	u32p += 2;
#else
	// A stateless server copies T3 and T4 from the client packet to T1 and
	// T2 of the server packet and tacks on the transmit timestamp T3 before
	// sending it to the client.
	*u32p++ = u32r[8];
	*u32p++ = u32r[9];
#endif
//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                      Origin Timestamp (64)                    +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// Time at the client when the request departed for the server, in NTP
	// timestamp format. (this is the client's transmit time)
	*u32p++ = u32r[10];
	*u32p++ = u32r[11];

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                      Receive Timestamp (64)                   +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// Time at the server when the request arrived from the client, in NTP
	// timestamp format. (this is the server's receive time)
	memcpy(u32p, recv_time, 2 * sizeof(uint32_t));
	u32p += 2;

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                      Transmit Timestamp (64)                  +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	// Time at the server when the response left for the client, in NTP
	// timestamp format. (this is the server's transmit time)
	uint32_t transmit_time[2];
	gettime32(transmit_time, true);
	memcpy(u32p, transmit_time, 2 * sizeof(uint32_t));
	u32p += 2;

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      .                                                               .
//      .                    Extension Field 1 (variable)               .
//      .                                                               .
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      .                                                               .
//      .                    Extension Field 2 (variable)               .
//      .                                                               .
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                          Key Identifier                       |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      |                            dgst (128)                         |
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                      Figure 8: Packet Header Format

	// Send the response
	errno = 0;
	if(sendto(socket_fd, send_buf, sizeof(send_buf), 0, saddr_p, saddrlen) < 48)
	{
		log_err("NTP send error: %s", strerror(errno));
		return 1;
	}

	return 0;
}

// Process incoming NTP requests
static void request_process_loop(int fd, const char *ipstr, const int protocol)
{
	log_info("NTP server listening on %s:123 (%s)", ipstr, protocol == AF_INET ? "IPv4" : "IPv6");
	while (true)
	{
		unsigned char buf[48];
		struct sockaddr src_addr;
		socklen_t src_addrlen = sizeof(src_addr);
		while(recvfrom(fd, buf, sizeof(buf), 0, &src_addr, &src_addrlen) < 48);  // ignore invalid requests

		// Get the current time in NTP format
		uint32_t recv_time[2];
		gettime32(recv_time, true);

		struct sockaddr_in sin;
		memcpy(&sin, &src_addr, sizeof(sin));
		// printf("Request from %s\n", inet_ntoa(sin.sin_addr));

		const pid_t pid = fork();
		if (pid == 0) {
			/* Child */
			ntp_reply(fd, &src_addr , src_addrlen, buf, recv_time);
			exit(0);
		} else if (pid == -1) {
			log_err("fork() error");
			return;
		}
		// return to parent
	}
}
/*
// Wait for a child process to exit
static void wait_wrapper(int _a)
{
	int s;
	wait(&s);
}*/

// Start the NTP server
static void *ntp_bind_and_listen(void *param)
{
//	signal(SIGCHLD, wait_wrapper);
	const int protocol = param == 0 ? AF_INET : AF_INET6;

  	// Create a socket
	errno = 0;
	const int s = socket(protocol, SOCK_DGRAM, IPPROTO_UDP);
	if(s == -1)
	{
		log_warn("Cannot create NTP socket (%s), IPv%i NTP server not available",
		         strerror(errno), protocol == AF_INET ? 4 : 6);
		return NULL;
	}

	// Bind the socket to the NTP port
	char ipstr[INET6_ADDRSTRLEN + 1];
	memset(ipstr, 0, sizeof(ipstr));
	if(protocol == AF_INET)
	{
		// IPv4 - set thread name
		prctl(PR_SET_NAME, "NTP (IPv4)", 0, 0, 0);

		// Prepare the bind address
		struct sockaddr_in bind_addr;
		memset(&bind_addr, 0, sizeof(bind_addr));
		bind_addr.sin_family = AF_INET; // IPv4
		bind_addr.sin_port = htons(123); // NTP port
		memcpy(&bind_addr.sin_addr, &config.ntp.ipv4.address.v.in_addr, sizeof(bind_addr.sin_addr));
		inet_ntop(AF_INET, &bind_addr.sin_addr, ipstr, sizeof(ipstr) - 1);

		// Bind the socket
		errno = 0;
		if(bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0)
		{
			log_warn("Cannot bind to IPv4 address %s:123 (%s), IPv4 NTP server not available",
			         ipstr, strerror(errno));
			return NULL;
		}
	}
	else
	{
		// IPv6 - set thread name
		prctl(PR_SET_NAME, "NTP (IPv6)", 0, 0, 0);

		// Set socket options to allow IPv6 only, otherwise it will bind
		// to both IPv4 and IPv6 and show IPv4 addresses as
		// v4-mapped-on-v6 addresses
		int opt = 1;
		if(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) != 0)
		{
			log_warn("Cannot set socket option IPV6_V6ONLY (%s), IPv6 NTP server not available", strerror(errno));
			return NULL;
		}

		// Prepare the bind address
		struct sockaddr_in6 bind_addr;
		memset(&bind_addr, 0, sizeof(bind_addr));
		bind_addr.sin6_family = AF_INET6; // IPv6
		bind_addr.sin6_port = htons(123); // NTP port
		memcpy(&bind_addr.sin6_addr, &config.ntp.ipv6.address.v.in6_addr, sizeof(bind_addr.sin6_addr));
		inet_ntop(AF_INET6, &bind_addr.sin6_addr, ipstr, sizeof(ipstr) - 1);

		// Bind the socket
		errno = 0;
		if(bind(s, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) != 0)
		{
			log_warn("Cannot bind to IPv6 address %s:123 (%s), IPv6 NTP server not available",
			         ipstr, strerror(errno));
			return NULL;
		}
	}

	request_process_loop(s, ipstr, protocol);
	close(s);

	return NULL;
}

// Start the NTP server
bool ntp_server_start(void)
{
	// Spawn two pthreads, one for IPv4 and one for IPv6

	// IPv4
	if(config.ntp.ipv4.active.v.b)
	{
		// Create a thread for the IPv4 NTP server
		pthread_t thread;
		if (pthread_create(&thread, NULL, ntp_bind_and_listen, (void *)0) != 0)
		{
			log_err("Can not create NTP server thread for IPv4");
			return false;
		}
	}

	// IPv6
	if(config.ntp.ipv6.active.v.b)
	{
		// Create a thread for the IPv6 NTP server
		pthread_t thread;
		if (pthread_create(&thread, NULL, ntp_bind_and_listen, (void *)1) != 0)
		{
			log_err("Can not create NTP server thread for IPv6");
			return false;
		}
	}

	sleep(10);

	return true;
}
