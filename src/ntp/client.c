/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  NTP client routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "FTL.h"
// close()
#include <unistd.h>
// clock_gettime()
#include <sys/time.h>
// socket(), connect(), send(), recv(), AF_INET, SOCK_DGRAM, IPPROTO_UDP
#include <sys/socket.h>
// getaddrinfo(), freeaddrinfo(), struct addrinfo
#include <netdb.h>
// memcpy()
#include <string.h>
// pow()
#include <math.h>
// ctime()
#include <time.h>
// errno
#include <errno.h>

#include "ntp.h"
#include "log.h"

// Create minimal NTP request, see server implementation for details about the
// packet structure
static bool request(int fd, uint32_t org[2])
{
	// NTP Packet buffer
	unsigned char buf[48] = {0};

	// LI = 0, VN = 4 (current version), Mode = 3 (Client)
	buf[0] = 0x23;

	// Set Origin Timestamp
	gettime32(org, true);
	memcpy(&buf[40], &org[0], 2 * sizeof(uint32_t));

	// Send request
	if(send(fd, buf, 48, 0) != 48)
	{
		log_warn("Failed to send data to NTP server: %s", strerror(errno));
		return false;
	}

	return true;
}

static bool get_reply(int fd, uint32_t org_[2])
{
	// NTP Packet buffer
	unsigned char buf[48];
	// NTP Packet buffer as uint32_t
	uint32_t *pt = (uint32_t *)((void*)&buf[24]);;

	// Receive reply
	if(recv(fd, buf, 48, 0) < 48)
	{
		log_warn("Failed to receive data from NTP server: %s", strerror(errno));
		return false;
	}

	// Extract precision of server clock
	signed char rho = (signed char)buf[3];
	if(rho < -32 || rho > 0)
	{
		// Accepted limits are 2^-32 (~ 0.2 nanoseconds)
		// to 2^0 (= 1 second)
		log_warn("Received NTP reply has invalid precision: 2^(%i), assuming microsecond accuracy", rho);
		rho = -19;
	}
	// Compute precision of server clock in seconds 2^rho
	const double s_rho = pow(2, rho);

	// Extract Transmit Timestamp
	// org = Origin Timestamp (Transmit Timestamp @ Client)
	uint32_t org[2];
	org[0] = ntohl(*pt++);
	org[1] = ntohl(*pt++);
	// rec = Receive Timestamp (Receive Timestamp @ Server)
	uint32_t rec[2];
	rec[0] = ntohl(*pt++);
	rec[1] = ntohl(*pt++);
	// xmt = Transmit Timestamp (Transmit Timestamp @ Server)
	uint32_t xmt[2];
	xmt[0] = ntohl(*pt++);
	xmt[1] = ntohl(*pt++);

	// dst = Destination Timestamp (Receive Timestamp @ Client)
	uint32_t dst[2];
	gettime32(dst, false);

	// Check org_ and org are identical (otherwise, the reply corresponds to
	// a different request and should be ignored), note that the byte order
	// of the received packet is already converted while org_ is still in
	// network byte order
	if(ntohl(org_[0]) != org[0] || ntohl(org_[1]) != org[1])
	{
		log_warn("Received NTP reply does not match request");
		return false;
	}

	// Check stratum, mode, version, etc.
	if((buf[0] & 0x07) != 4)
	{
		log_warn("Received NTP reply has invalid version");
		return false;
	}

	// Calculate delay and offset
	const double tfrac = 4294967296.0; // 2^32 as double
	const double T1 = org[0] + org[1] / tfrac;
	const double T2 = rec[0] + rec[1] / tfrac;
	const double T3 = xmt[0] + xmt[1] / tfrac;
	const double T4 = dst[0] + dst[1] / tfrac;

	// RFC 5905, Section 8: On-wire protocol
	// It is recommended to use double precision floating point arithmetic
	// for the calculations to allow unambiguous interpretation of the
	// results within the maximum adjustment range of 68 years.

	// Compute offset of client clock relative to server clock
	const double theta = ( ( T2 - T1 ) + ( T3 - T4 ) ) / 2;
	// Compute round-trip delay
	double delta = ( T4 - T1 ) - ( T3 - T2 );

	// In some scenarios where the initial frequency offset of the client is
	// relatively large and the actual propagation time small, it is
	// possible for the delay computation to become negative.  For instance,
	// if the frequency difference is 100 ppm and the interval T4-T1 is 64
	// s, the apparent delay is -6.4 ms.  Since negative values are
	// misleading in subsequent computations, the value of delta should be
	// clamped not less than s.rho, where s.rho is the system precision
	// described in Section 11.1, expressed in seconds.
	if(delta < s_rho)
	{
		log_warn("Negative delay detected, clamping to 0");
		delta = 0;
	}

	// Print current time at client
	char client_time_str[26];
	const time_t client_time = dst[0];
	strncpy(client_time_str, ctime(&client_time), sizeof(client_time_str) -1);
	// Remove trailing newline
	client_time_str[24] = '\0';
	log_info("Current time at client: %s", client_time_str);

	// Print current time at server
	char server_time_str[26];
	const time_t server_time = xmt[0];
	strncpy(server_time_str, ctime(&server_time), sizeof(server_time_str) -1);
	// Remove trailing newline
	server_time_str[24] = '\0';
	log_info("Current time at server: %s", server_time_str);

	// Print offset and delay
	log_info("Time offset: %e s", theta);
	log_info("Round-trip delay: %e s", delta);

	// Offset and delay larger than 0.1 seconds are considered as invalid
	// during local testing
	return theta < 0.1 && delta < 0.1;
}

bool ntp_client(const char *server)
{
	const int protocol = strchr(server, ':') != NULL ? AF_INET6 : AF_INET;

	// Create UDP socket
	const int s = socket(protocol, SOCK_DGRAM, IPPROTO_UDP);
	if(s == -1)
	{
		log_err("Cannot create UDP socket");
		return false;
	}

	// Set socket timeout to 2 seconds
	struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
	{
		log_err("Cannot set socket timeout");
		close(s);
		return false;
	}

	// Resolve server address
	struct addrinfo *saddr;
	if(getaddrinfo(server, "123", NULL, &saddr) != 0)
	{
		log_err("Cannot resolve NTP server address");
		close(s);
		return false;
	}

	// Set address to send to/receive from
	if(connect(s, saddr->ai_addr, saddr->ai_addrlen) != 0)
	{
		log_err("Cannot connect to NTP server");
		close(s);
		return false;
	}
	freeaddrinfo(saddr);

	// Send request
	uint32_t org[2];
	if(!request(s, org))
	{
		close(s);
		return false;
	}

	// Get reply
	const bool status = get_reply(s, org);
	close(s);

	return status;
}
