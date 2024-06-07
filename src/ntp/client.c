/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  NTP client routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "ntp/ntp.h"
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
// config struct
#include "config/config.h"
// adjtime()
#include <sys/time.h>
// threads[]
#include "daemon.h"
// thread_names[]
#include "signals.h"
// adjtimex()
#include <sys/timex.h>
struct ntp_sync
{
	uint64_t org;
	uint64_t xmt;
	double theta;
	double delta;
	double precision;
};

// Create minimal NTP request, see server implementation for details about the
// packet structure
static bool request(int fd, struct ntp_sync *ntp)
{
	// NTP Packet buffer
	unsigned char buf[48] = {0};

	// LI = 0, VN = 4 (current version), Mode = 3 (Client)
	buf[0] = 0x23;

	// Minimum poll interval (2^6 = 64 seconds)
	buf[2] = 0x06;

	// Set Reference Timestamp (ref) to 0
	// This is the time at which the local clock was last set or corrected.
	memset(&buf[8], 0, sizeof(uint64_t));

	// Set Origin Timestamp (org) in NTP format
	ntp->org = gettime64();
	const uint64_t norg = hton64(ntp->org);
	memcpy(&buf[40], &norg, sizeof(norg));

	// Send request
	if(send(fd, buf, 48, 0) != 48)
	{
		log_err("Failed to send data to NTP server: %s",
		        errno == EAGAIN ? "Timeout" : strerror(errno));
		return false;
	}

	return true;
}

// Display NTP time in human-readable format
// This function is similar to get_timestr() in src/log.c but differs in that it
// includes microseconds whereas get_timestr() only includes milliseconds
static void format_NTP_time(char time_str[TIMESTR_SIZE], const uint64_t ntp_time)
{
	struct timeval client_time;
	client_time.tv_sec = NTPtoSEC(ntp_time);
	client_time.tv_usec = NTPtoUSEC(ntp_time);
	struct tm *client_tm = localtime(&client_time.tv_sec);
	snprintf(time_str, TIMESTR_SIZE, "%04i-%02i-%02i %02i:%02i:%02i.%06"PRIi64" %s",
	         client_tm->tm_year + 1900, client_tm->tm_mon + 1, client_tm->tm_mday,
	         client_tm->tm_hour, client_tm->tm_min, client_tm->tm_sec, client_time.tv_usec,
	         client_tm->tm_zone);
	time_str[TIMESTR_SIZE - 1] = '\0';
}

// Print NTP timestamp in human-readable form for debugging
void print_debug_time(const char *label, const uint32_t *u32p, const uint64_t ntp_time)
{
	// Get the time from the appropriate buffer
	uint64_t timevar;
	if(u32p != NULL)
	{
		memcpy(&timevar, u32p, sizeof(uint64_t));
		// Convert to host byte order
		timevar = ntoh64(timevar);
	}
	else
	{
		// Use the provided time (already in host byte order)
		timevar = ntp_time;
	}


	// Format the time
	char time_str[TIMESTR_SIZE];
	format_NTP_time(time_str, timevar);

	// Print the time
	log_debug(DEBUG_NTP, "%s: %08"PRIx64".%08"PRIx64" = %s", label,
	          (timevar >> 32) & 0xFFFFFFFF, timevar & 0xFFFFFFFF, time_str);
}

static bool settime_step(const double offset)
{
	// Get current time
	struct timeval unix_time;
	gettimeofday(&unix_time, NULL);

	// Convert from double to native format (signed) and add to the
	// current time.  Note the addition is done in native format to
	// avoid overflow or loss of precision.
	const uint64_t ntp_time = U2LFP(unix_time) + D2LFP(offset);

	// Convert NTP to native format
	unix_time.tv_sec = NTPtoSEC(ntp_time);
	unix_time.tv_usec = NTPtoUSEC(ntp_time);
	log_debug(DEBUG_NTP, "Stepping system time by %e s", offset);

	// Set time immediately
	if(settimeofday(&unix_time, NULL) != 0)
	{
		log_err("Failed to set time: %s",
		        errno == EPERM ? "Insufficient permissions, try running with sudo" : strerror(errno));
		return false;
	}

	return true;
}

static bool settime_skew(const double offset)
{
	// This function gradually adjusts the system clock.
	//
	// Linux uses David L. Mills' clock adjustment algorithm (see RFC 5905).
	// If the adjustment in delta is positive, then the system clock is
	// speeded up by some small percentage (i.e., by adding a small amount
	// of time to the clock value in each second) until the adjustment has
	// been completed. If the adjustment in delta is negative, then the
	// clock is slowed down in a similar fashion.
	//
	// If a clock adjustment from an earlier adjtime() call is already in
	// progress at the time of a later adjtime() call, and delta is not NULL
	// for the later call, then the earlier adjustment is stopped, but any
	// already completed part of that adjustment is not undone.
	//
	// The adjustment that adjtimex() makes to the clock is carried out in
	// such a manner that the clock is always monotonically increasing.
	// Using adjtimex() to adjust the time prevents the problems that can be
	// caused for certain applications (e.g., make(1)) by abrupt positive or
	// negative jumps in the system time.
	//
	// adjtimex() is intended to be used to make small adjustments to the
	// system time. The actual time adjustment rate is implementation-specific
	// but is typically on the order of 500 ppm, i.e., 0.5 ms/s.
	//
	// man rtc(4) adds:
	// When the kernel's system time is synchronized with an external
	// reference using adjtimex() it will update a designated RTC
	// periodically every 11 minutes.

	struct timex tx = { 0 };
	tx.offset = 1000000 * offset;
	tx.modes = ADJ_OFFSET_SINGLESHOT;

	log_debug(DEBUG_NTP, "Gradually adjusting system time by %ld us", tx.offset);

	if(adjtimex(&tx) < 0)
	{
		log_err("Failed to adjust time: %s",
		        errno == EPERM ? "Insufficient permissions, try running with sudo" : strerror(errno));
		return false;
	}

	return true;
}

static bool reply(int fd, struct ntp_sync *ntp, const bool verbose)
{
	// NTP Packet buffer
	unsigned char buf[48];

	// Receive reply
	if(recv(fd, buf, 48, 0) < 48)
	{
		log_err("Failed to receive data from NTP server: %s",
		        errno == EAGAIN ? "Timeout" : strerror(errno));
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
	ntp->precision = pow(2, rho);

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
	ntp->xmt = ntoh64(netbuffer);

	// dst = Destination Timestamp (Receive Timestamp @ Client)
	uint64_t dst = gettime64();

	// Check org_ and org are identical (otherwise, the reply corresponds to
	// a different request and should be ignored), note that the byte order
	// of the received packet is already converted while org_ is still in
	// network byte order
	if(ntp->org != org)
	{
		log_warn("Received NTP reply does not match request (request %"PRIx64", reply %"PRIx64"), ignoring",
		         ntp->org, org);
		return false;
	}

	// Check stratum, mode, version, etc.
	if((buf[0] & 0x07) != 4)
	{
		log_warn("Received NTP reply has invalid version, ignoring");
		return false;
	}

	// Calculate delay and offset
	const double T1 = ntp->org / FRAC;
	const double T2 = rec / FRAC;
	const double T3 = ntp->xmt / FRAC;
	const double T4 = dst / FRAC;

	// RFC 5905, Section 8: On-wire protocol
	// It is recommended to use double precision floating point arithmetic
	// for the calculations to allow unambiguous interpretation of the
	// results within the maximum adjustment range of 68 years.

	// Compute offset of client clock relative to server clock
	ntp->theta = ( ( T2 - T1 ) + ( T3 - T4 ) ) / 2;
	// Compute round-trip delay, which represents the delay of the packet
	// passing through the network, which can be due switches and network
	// technologies are highly variable
	ntp->delta = ( T4 - T1 ) - ( T3 - T2 );

	// In some scenarios where the initial frequency offset of the client is
	// relatively large and the actual propagation time small, it is
	// possible for the delay computation to become negative.  For instance,
	// if the frequency difference is 100 ppm and the interval T4-T1 is 64
	// s, the apparent delay is -6.4 ms.  Since negative values are
	// misleading in subsequent computations, the value of delta should be
	// clamped not less than s.rho, where s.rho is the system precision
	// described in Section 11.1, expressed in seconds.
	if(ntp->delta < ntp->precision)
		ntp->delta = 0;

	// Return early if not verbose
	if(!config.debug.ntp.v.b)
		return true;

	// Print current time at client
	print_debug_time("Current time at client", NULL, dst);

	// Print current time at server
	print_debug_time("Current time at server", NULL, ntp->xmt);

	// Print offset and delay
	log_debug(DEBUG_NTP, "Time offset: %e s", ntp->theta);
	log_debug(DEBUG_NTP, "Round-trip delay: %e s", ntp->delta);

	return true;
}

bool ntp_client(const char *server, const bool settime, const bool print)
{
	const int protocol = strchr(server, ':') != NULL ? AF_INET6 : AF_INET;

	// Create UDP socket
	const int s = socket(protocol, SOCK_DGRAM, IPPROTO_UDP);
	if(s == -1)
	{
		log_err("Cannot create UDP socket");
		return false;
	}

	// Set socket timeout to 5 seconds
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
	{
		log_err("Cannot set socket timeout");
		close(s);
		return false;
	}

	// Resolve server address
	struct addrinfo *saddr;
	if(getaddrinfo(server, "ntp", NULL, &saddr) != 0)
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

	// Send and receive NTP packets
	const unsigned int count = config.ntp.sync.count.v.ui;
	struct ntp_sync *ntp = calloc(count, sizeof(struct ntp_sync));
	if(ntp == NULL)
	{
		log_err("Cannot allocate memory for NTP client");
		close(s);
		return false;
	}
	memset(ntp, 0, count*sizeof(*ntp));
	for(unsigned int i = 0; i < count; i++)
	{
		// Send request
		if(!request(s, &ntp[i]))
		{
			close(s);
			free(ntp);
			return false;
		}
		// Get reply
		if(!reply(s, &ntp[i], false))
			continue;

		// Sleep for some time to avoid flooding the server
		if(print)
			printf(".");
		fflush(stdout);
		usleep(NTP_DELAY);
	}
	if(print)
		printf("\n");

	// Close socket
	close(s);

	// Compute average and standard deviation
	unsigned int valid = 0;
	double theta_avg = 0.0, theta_stdev = 0.0;
	double delta_avg = 0.0, delta_stdev = 0.0;
	for(unsigned int i = 0; i < count; i++)
	{
		// Skip invalid values
		if(fabs(ntp[i].theta) < ntp[i].precision ||
		   fabs(ntp[i].delta) < ntp[i].precision)
			continue;

		theta_avg += ntp[i].theta;
		delta_avg += ntp[i].delta;
		valid++;
	}

	if(valid == 0)
	{
		log_warn("No valid NTP replies received, check server and network connectivity");
		free(ntp);
		return false;
	}
	log_info("Received %u/%u valid NTP replies", valid, count);

	theta_avg /= valid;
	delta_avg /= valid;
	for(unsigned int i = 0; i < count; i++)
	{
		// Skip invalid values
		if(fabs(ntp[i].theta) < ntp[i].precision ||
		   fabs(ntp[i].delta) < ntp[i].precision)
			continue;

		theta_stdev += pow(ntp[i].theta - theta_avg, 2);
		delta_stdev += pow(ntp[i].delta - delta_avg, 2);
	}
	theta_stdev = sqrt(theta_stdev / valid);
	delta_stdev = sqrt(delta_stdev / valid);

	log_info("Average time offset: (%e +/- %e s)", theta_avg, theta_stdev);
	log_info("Average round-trip delay: (%e +/- %e s)", delta_avg, delta_stdev);

	// Reject synchronization if the standard deviation of the time offset
	// or round-trip delay is larger than 1 second
	if(theta_stdev > 1.0 || delta_stdev > 1.0)
	{
		log_warn("Standard deviation of time offset is too large, rejecting synchronization");
		free(ntp);
		return false;
	}

	// Compute trimmed mean (average excluding outliers)
	double theta_trim = 0.0, delta_trim = 0.0;
	unsigned int trim = 0;
	for(unsigned int i = 0; i < count; i++)
	{
		// Skip invalid values
		if(fabs(ntp[i].theta) < ntp[i].precision ||
		   fabs(ntp[i].delta) < ntp[i].precision)
			continue;

		// Skip outliers
		// We consider values > 2 standard deviations from the mean as
		// outliers
		if(fabs(ntp[i].theta - theta_avg) > 2 * theta_stdev ||
		   fabs(ntp[i].delta - delta_avg) > 2 * delta_stdev)
			continue;

		theta_trim += ntp[i].theta;
		delta_trim += ntp[i].delta;
		trim++;
	}

	// Free allocated memory
	free(ntp);

	if(trim == 0)
	{
		log_warn("No valid NTP replies after outlier removal, check server and network connectivity");
		return false;
	}
	theta_trim /= trim;
	delta_trim /= trim;

	log_info("Trimmed mean time offset: %e s (excluded %u outliers)", theta_trim, count - trim);
	log_info("Trimmed mean round-trip delay: %e s (excluded %u outliers)", delta_trim, count - trim);

	// Set time if requested
	if(settime)
	{
		// If the clock deviates more than 0.5 seconds from the NTP server,
		// the time is updated immediately.  Otherwise, the time is updated
		// gradually to avoid sudden jumps in the system clock.
		// The threshold of 0.5 seconds is hard-wired into the kernel
		// since Linux 2.6.26, see man ntp_adjtime(2) for details.
		bool success;
		if(fabs(theta_trim) > 0.5)
			success = settime_step(theta_trim);
		else
			success = settime_skew(theta_trim);

		// Return early if time could not be set
		if(!success)
			return false;

		// Finally, adjust RTC if configured
		if(config.ntp.rtc.set.v.b)
			ntp_sync_rtc();
	}

	// Offset and delay larger than 0.1 seconds are considered as invalid
	// during local testing (e.g., when the server is on the same machine)
	return theta_avg < 0.1 && delta_avg < 0.1;
}

static void *ntp_client_thread(void *arg)
{
	// Set thread name
	thread_names[NTP] = "ntp-client";
	thread_running[NTP] = true;
	prctl(PR_SET_NAME, thread_names[DB], 0, 0, 0);
	pthread_setname_np(pthread_self(), "NTP sync");

	// Run NTP client
	while(!killed)
	{
		// Run NTP client
		ntp_client(config.ntp.sync.server.v.s, true, false);

		// Intermediate cancellation-point
		BREAK_IF_KILLED();

		// Sleep before retrying
		thread_sleepms(NTP, 1000 * config.ntp.sync.interval.v.ui);
	}

	log_info("Terminating NTP thread");
	thread_running[NTP] = false;

	return NULL;
}

bool ntp_start_sync_thread(pthread_attr_t *attr)
{
	// Return early if NTP client is disabled
	if(config.ntp.sync.server.v.s == NULL ||
	   strlen(config.ntp.sync.server.v.s) == 0 ||
	   config.ntp.sync.interval.v.ui == 0)
		return false;

	// Create thread
	if(pthread_create(&threads[NTP], attr, ntp_client_thread, NULL) != 0)
	{
		log_err("Cannot create NTP client thread");
		return false;
	}

	return true;
}
