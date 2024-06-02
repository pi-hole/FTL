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
// PRIi64
#include <inttypes.h>

#include "ntp/ntp.h"
#include "log.h"

// Create minimal NTP request, see server implementation for details about the
// packet structure
static bool request(int fd, uint64_t *org)
{
	// NTP Packet buffer
	unsigned char buf[48] = {0};

	// LI = 0, VN = 4 (current version), Mode = 3 (Client)
	buf[0] = 0x23;

	// Minimum poll interval (2^6 = 64 seconds)
	buf[2] = 0x06;

	// Set Origin Timestamp
	*org = gettime64();
	//memcpy(&buf[40], &org[0], 2 * sizeof(uint32_t));
	const uint64_t norg = hton64(*org);
	memcpy(&buf[40], &norg, sizeof(norg));

	// Send request
	if(send(fd, buf, 48, 0) != 48)
	{
		log_warn("Failed to send data to NTP server: %s", strerror(errno));
		return false;
	}

	return true;
}

static bool reply(int fd, uint64_t *org_, const bool settime)
{
	// NTP Packet buffer
	unsigned char buf[48];

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
	uint64_t netbuffer;
	memcpy(&netbuffer, &buf[24], sizeof(netbuffer));
	const uint64_t org = ntoh64(netbuffer);
	// rec = Receive Timestamp (Receive Timestamp @ Server)
	memcpy(&netbuffer, &buf[32], sizeof(netbuffer));
	const uint64_t rec = ntoh64(netbuffer);
	// xmt = Transmit Timestamp (Transmit Timestamp @ Server)
	memcpy(&netbuffer, &buf[40], sizeof(netbuffer));
	const uint64_t xmt = ntoh64(netbuffer);

	// dst = Destination Timestamp (Receive Timestamp @ Client)
	uint64_t dst = gettime64();

	// Check org_ and org are identical (otherwise, the reply corresponds to
	// a different request and should be ignored), note that the byte order
	// of the received packet is already converted while org_ is still in
	// network byte order
	if(*org_ != org)
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
	const double T1 = org / FRAC;
	const double T2 = rec / FRAC;
	const double T3 = xmt / FRAC;
	const double T4 = dst / FRAC;

	// RFC 5905, Section 8: On-wire protocol
	// It is recommended to use double precision floating point arithmetic
	// for the calculations to allow unambiguous interpretation of the
	// results within the maximum adjustment range of 68 years.

	// Compute offset of client clock relative to server clock
	const double theta = ( ( T2 - T1 ) + ( T3 - T4 ) ) / 2;
	// Compute round-trip delay, which represents the delay of the packet
	// passing through the network, which can be due switches and network
	// technologies are highly variable
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
		delta = 0;

	// Print current time at client
	char client_time_str[128];
	struct timeval client_time;
	client_time.tv_sec = NTPtoSEC(dst);
	client_time.tv_usec = NTPtoUSEC(dst);
	struct tm *client_tm = localtime(&client_time.tv_sec);
	snprintf(client_time_str, sizeof(client_time_str), "%04i-%02i-%02i %02i:%02i:%02i.%06"PRIi64" %s",
		client_tm->tm_year + 1900, client_tm->tm_mon + 1, client_tm->tm_mday,
		client_tm->tm_hour, client_tm->tm_min, client_tm->tm_sec, client_time.tv_usec,
		client_tm->tm_zone);
	client_time_str[sizeof(client_time_str) - 1] = '\0';
	log_info("Current time at client: %s", client_time_str);

	// Print current time at server
	char server_time_str[128];
	struct timeval server_time;
	server_time.tv_sec = NTPtoSEC(xmt);
	server_time.tv_usec = NTPtoUSEC(xmt);
	struct tm *server_tm = localtime(&server_time.tv_sec);
	snprintf(server_time_str, sizeof(server_time_str), "%04i-%02i-%02i %02i:%02i:%02i.%06"PRIi64" %s",
		server_tm->tm_year + 1900, server_tm->tm_mon + 1, server_tm->tm_mday,
		server_tm->tm_hour, server_tm->tm_min, server_tm->tm_sec, server_time.tv_usec,
		server_tm->tm_zone);
	server_time_str[sizeof(server_time_str) - 1] = '\0';
	log_info("Current time at server: %s", server_time_str);

	// Print offset and delay
	log_info("Time offset: %e s", theta);
	log_info("Round-trip delay: %e s", delta);

	// Set time if requested
	if(settime)
	{
		// Get current time
		struct timeval unix_time;
		gettimeofday(&unix_time, NULL);

		// Convert from double to native format (signed) and add to the
		// current time.  Note the addition is done in native format to
		// avoid overflow or loss of precision.
		const uint64_t ntp_time = D2LFP(theta) + U2LFP(unix_time);

		// Convert NTP to native format
		unix_time.tv_sec = NTPtoSEC(ntp_time);
		unix_time.tv_usec = NTPtoUSEC(ntp_time);

		// Print new time
		char new_time_str[128];
		struct tm *new_time_tm = localtime(&unix_time.tv_sec);
		snprintf(new_time_str, sizeof(new_time_str), "%04i-%02i-%02i %02i:%02i:%02i.%06"PRIi64" %s",
			new_time_tm->tm_year + 1900, new_time_tm->tm_mon + 1, new_time_tm->tm_mday,
			new_time_tm->tm_hour, new_time_tm->tm_min, new_time_tm->tm_sec, unix_time.tv_usec,
			new_time_tm->tm_zone);
		new_time_str[sizeof(new_time_str) - 1] = '\0';

		// Set time
		if(settimeofday(&unix_time, NULL) != 0)
		{
			log_warn("Failed to set time to %s: %s", new_time_str, strerror(errno));
			return false;
		}
		log_info("Updated time at client: %s", new_time_str);
	}

	// Offset and delay larger than 0.1 seconds are considered as invalid
	// during local testing
	return theta < 0.1 && delta < 0.1;
}

bool ntp_client(const char *server, const bool settime)
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
	uint64_t org;
	if(!request(s, &org))
	{
		close(s);
		return false;
	}

	// Get reply
	const bool status = reply(s, &org, settime);
	close(s);

	return status;
}
