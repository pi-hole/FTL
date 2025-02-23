/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  NTP server routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "ntp/ntp.h"
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
#include <sys/wait.h>
// wait()
#include <sys/socket.h>
// htonl(), etc.
#include <arpa/inet.h>
// errno
#include <errno.h>
// ctime()
#include <time.h>
// pthread_create
#include <pthread.h>
// PR_SET_NAME
#include <sys/prctl.h>
// config struct
#include "config/config.h"
// PRIi64
#include <inttypes.h>
// log_ntp_message()
#include "database/message-table.h"
// NTP_SERVER_IPV4,6
#include "enums.h"
// threads
#include "signals.h"
// sleepms()
#include "timers.h"

uint64_t ntp_last_sync = 0u;
uint32_t ntp_root_delay = 0u;
uint32_t ntp_root_dispersion = 0u;

// RFC 5905 Appendix A.4: Kernel System Clock Interface
uint64_t gettime64(void)
{
	struct timeval unix_time;
	gettimeofday(&unix_time, NULL);
	return (U2LFP(unix_time));
}

// Create and send an NTP reply to the client
static bool ntp_reply(const int socket_fd, const struct sockaddr *saddr_p, const socklen_t saddrlen,
                      const unsigned char recv_buf[], const uint64_t *recv_time)
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
		return false;
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

	// Precision: the precision of the  local clock, in seconds to the
	// nearest power of two.
	// log2(1 usec = 1e-6 s) = -19.931568569324174
	send_buf[3] = (signed char)(-20);

	// Advance 32 bit pointer to the next field
	u32p++;

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                         Root Delay                            |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                         Root Dispersion                       |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// Set Root Delay (total roundtrip delay to the primary reference
	// source) and Root Dispersion (the nominal error relative to the
	// primary reference source) to the values obtained from the upstream
	// NTP server.
	*u32p++ = htonl(ntp_root_delay);
	*u32p++ = htonl(ntp_root_dispersion);

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                          Reference ID                         |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// Reference ID = 'LOCL" (LOCAL CLOCK)
	// A four-octet, left-justified, zero-padded ASCII string assigned to
	// the reference clock
	memcpy(u32p++, "LOCL", sizeof(uint32_t));

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                     Reference Timestamp (64)                  +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// Time when the system clock was last set or corrected, in NTP
	// timestamp format.
	const uint64_t last_sync = hton64(ntp_last_sync);
	memcpy(u32p, &last_sync, sizeof(uint64_t));
	if(config.debug.ntp.v.b)
		print_debug_time("Reference Timestamp", u32p, 0);
	u32p += 2;

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                      Origin Timestamp (64)                    +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// Time at the client when the request departed for the server, in NTP
	// timestamp format. (this is the client's transmit time)
	memcpy(u32p, &u32r[10], sizeof(uint64_t));
	if(config.debug.ntp.v.b)
		print_debug_time("Origin Timestamp", u32p, 0);
	u32p += 2;

//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                      Receive Timestamp (64)                   +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	// Time at the server when the request arrived from the client, in NTP
	// timestamp format. (this is the server's receive time)
	const uint64_t net_recv_time = hton64(*recv_time);
	memcpy(u32p, &net_recv_time, sizeof(uint64_t));
	if(config.debug.ntp.v.b)
		print_debug_time("Receive Timestamp", u32p, 0);
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
	const uint64_t transmit_time = gettime64();
	const uint64_t net_transmit_time = hton64(transmit_time);
	memcpy(u32p, &net_transmit_time, sizeof(uint64_t));
	if(config.debug.ntp.v.b)
		print_debug_time("Transmit Timestamp", u32p, 0);
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
		return false;
	}

	return true;
}

// Process incoming NTP requests
static void request_process_loop(const int fd, const char *ipstr, const int protocol)
{
	log_info("NTP server listening on %s:123 (%s)", ipstr, protocol == AF_INET ? "IPv4" : "IPv6");
	while (true)
	{
		unsigned char buf[48];
		struct sockaddr src_addr;
		socklen_t src_addrlen = sizeof(src_addr);
		while(recvfrom(fd, buf, sizeof(buf), 0, &src_addr, &src_addrlen) < 48);  // ignore invalid requests

		// Get the current time in NTP format directly after receiving
		// the request
		const uint64_t recv_time = gettime64();

		// Print the request
		if(config.debug.ntp.v.b)
		{
			if(protocol == AF_INET6)
			{
				struct sockaddr_in6 sin6;
				memcpy(&sin6, &src_addr, sizeof(sin6));

				char ip[INET6_ADDRSTRLEN];
				const in_port_t port = ntohs(sin6.sin6_port);
				inet_ntop(protocol, &sin6.sin6_addr, ip, sizeof(ip));
				log_debug(DEBUG_NTP, "Received NTP request from [%s]:%u", ip, port);
			}
			else
			{
				struct sockaddr_in sin;
				memcpy(&sin, &src_addr, sizeof(sin));

				char ip[INET6_ADDRSTRLEN];
				const in_port_t port = ntohs(sin.sin_port);
				inet_ntop(protocol, &sin.sin_addr, ip, sizeof(ip));
				log_debug(DEBUG_NTP, "Received NTP request from %s:%u", ip, port);
			}
		}

		// Handle the request
		ntp_reply(fd, &src_addr, src_addrlen, buf, &recv_time);
		log_debug(DEBUG_NTP, "NTP reply sent");

		// Sleep for 100 msec, this allows no more than 10 requests per
		// second
		sleepms(100);
	}
}

// Start the NTP server
static void *ntp_bind_and_listen(void *param)
{
	// Set thread name
	const unsigned int thread_id = param == 0 ? NTP_SERVER4 : NTP_SERVER6;
	prctl(PR_SET_NAME, thread_names[thread_id], 0, 0, 0);

  	// Create a socket
	const int protocol = param == 0 ? AF_INET : AF_INET6;
	errno = 0;
	const int s = socket(protocol, SOCK_DGRAM, IPPROTO_UDP);
	if(s == -1)
	{
		char errbuf[1024];
		snprintf(errbuf, sizeof(errbuf),
		         "Cannot create NTP socket (%s), IPv%i NTP server not available",
		         strerror(errno), protocol == AF_INET ? 4 : 6);
		errbuf[sizeof(errbuf) - 1] = '\0';
		log_ntp_message(true, true, errbuf);
		return NULL;
	}

#ifdef SO_REUSEPORT
	// Set socket option to allow multiple sockets to bind to the same port
	// (SO_REUSEPORT). This is necessary to ensure pihole-FTL can rebind to
	// the NTP port after a restart without waiting for the kernel to release
	// the port. This feature is available since Linux 3.9.
	int optval = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
#endif

	// Set socket receive buffer to 1 KB to avoid (near) endless queueing of
	// NTP requests
	const int recvbuf = 1024;
	setsockopt(s, SOL_SOCKET, SO_RCVBUF, &recvbuf, sizeof(recvbuf));

	// Bind the socket to the NTP port
	char ipstr[INET6_ADDRSTRLEN + 1];
	memset(ipstr, 0, sizeof(ipstr));
	if(protocol == AF_INET)
	{
		// IPv4 NTP server

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
			char errbuf[1024];
			snprintf(errbuf, sizeof(errbuf),
			         "Cannot bind to IPv4 address %s:123 (%s), IPv4 NTP server not available",
			         ipstr, strerror(errno));
			errbuf[sizeof(errbuf) - 1] = '\0';
			log_ntp_message(true, true, errbuf);
			return NULL;
		}
	}
	else
	{
		// IPv6 NTP server

		// Set socket options to allow IPv6 only, otherwise it will bind
		// to both IPv4 and IPv6 and show IPv4 addresses as
		// v4-mapped-on-v6 addresses
		int opt = 1;
		if(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) != 0)
		{
			char errbuf[1024];
			strncpy(errbuf, "Cannot set socket option IPV6_V6ONLY, IPv6 NTP server not available: ", sizeof(errbuf));
			strncat(errbuf, strerror(errno), sizeof(errbuf) - strlen(errbuf) - 1);
			errbuf[sizeof(errbuf) - 1] = '\0';
			log_ntp_message(true, true, errbuf);
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
			char errbuf[1024];
			snprintf(errbuf, sizeof(errbuf),
			         "Cannot bind to IPv6 address %s:123 (%s), IPv6 NTP server not available",
			         ipstr, strerror(errno));
			errbuf[sizeof(errbuf) - 1] = '\0';
			log_ntp_message(true, true, errbuf);
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
			log_ntp_message(true, true, "Cannot create NTP server thread for IPv4");
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
			log_ntp_message(true, true, "Cannot create NTP server thread for IPv6");
			return false;
		}
	}

	return true;
}
