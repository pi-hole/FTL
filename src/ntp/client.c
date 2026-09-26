/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  NTP client routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "ntp.h"
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
// PRId64
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
// log_ntp_message()
#include "database/message-table.h"
// check_capability()
#include "capabilities.h"
// search_proc()
#include "procps.h"
// get_secure_randomness()
#include "config/password.h"

// Required accuracy of the NTP sync in seconds in order to start the NTP server
// thread. If the NTP sync is less accurate than this value, the NTP server
// thread will only be started after later NTP syncs have reached this accuracy.
// Default: 0.5 (seconds)
#define ACCURACY 0.5

// Interval between successive NTP sync attempts in seconds in case of
// not-yet-sufficient accuracy of the NTP sync
// Default: 600 (seconds) = 10 minutes
#define RETRY_INTERVAL 600
// Maximum number of NTP syncs to attempt before giving up
#define RETRY_ATTEMPTS 5

// Panic threshold (in seconds) for stepping the system clock. If a sync would
// require stepping the clock by more than this amount, the step is refused to
// prevent a consistent malicious/spoofed server from moving the clock by an
// arbitrary magnitude (the offset math allows +/- 68 years). This mirrors
// ntpd's default panic threshold. The very first synchronization after boot is
// exempt because devices without an RTC (e.g. Raspberry Pi) start with a
// wildly wrong clock and would otherwise never be able to synchronize.
#define NTP_MAX_STEP_SECS 1000

// Whether the next clock step is the first synchronization after boot. Until
// the first successful sync, a large initial step is permitted; afterwards the
// panic threshold above is enforced.
static bool ntp_first_sync = true;

struct ntp_sync
{
	bool valid;
	uint64_t org;
	uint64_t t1;
	uint64_t xmt;
	uint8_t stratum;
	double theta;
	double delta;
	double precision;
};

// Kiss codes as defined in RFC 5905, Section 7.4
static struct {
	const char *code;
	const char *meaning;
} kiss_codes[] =
{
	{ "ACST", "The association belongs to a unicast server." },
	{ "AUTH", "Server authentication failed." },
	{ "AUTO", "Autokey sequence failed." },
	{ "BCST", "The association belongs to a broadcast server." },
	{ "CRYP", "Cryptographic authentication or identification failed." },
	{ "DENY", "Access denied by remote server." },
	{ "DROP", "Lost peer in symmetric mode." },
	{ "RSTR", "Access denied due to local policy." },
	{ "INIT", "The association has not yet synchronized for the first time." },
	{ "MCST", "The association belongs to a dynamically discovered server." },
	{ "NKEY", "No key found. Either the key was never installed or is not trusted." },
	{ "RATE", "Rate exceeded. The server has temporarily denied access because the client exceeded the rate threshold." },
	{ "RMOT", "Alteration of association from a remote host running ntpdc." },
	{ "STEP", "A step change in system time has occurred, but the association has not yet resynchronized." },
	{ NULL, NULL }
};

// Create minimal NTP request, see server implementation for details about the
// packet structure
static bool request(int fd, const char *server, struct addrinfo *saddr, struct ntp_sync *ntp)
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

	// Set Origin Timestamp (org) to an unpredictable random 64-bit nonce
	// instead of the real wall-clock transmit time. RFC 5905 servers echo
	// this value back into the origin field of the reply, so it acts as an
	// interoperable anti-spoof token (chrony does the same). Using the real,
	// predictable clock here would let an off-path attacker guess the value
	// and forge replies. On RNG failure we fail the request rather than send
	// a predictable value.
	do {
		if(!get_secure_randomness((uint8_t *)&ntp->org, sizeof(ntp->org)))
		{
			log_err("Failed to generate NTP anti-spoof nonce, aborting request");
			return false;
		}
	} while(ntp->org == 0);
	const uint64_t norg = hton64(ntp->org);
	memcpy(&buf[40], &norg, sizeof(norg));

	// Capture the REAL transmit time (T1) right before sending. The on-wire
	// origin timestamp is now a random nonce, but the offset/delay math still
	// needs the actual send time, so it is kept separately here.
	ntp->t1 = gettime64();

	// Send request
	if(send(fd, buf, 48, 0) != 48)
	{
		// Get IP address of server
		char ip[INET6_ADDRSTRLEN] = { 0 };
		if(getnameinfo(saddr->ai_addr, saddr->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST) != 0)
			strncpy(ip, server, sizeof(ip) - 1);

		log_err("Failed to send data to NTP server %s (%s): %s",
		        server, ip, errno == EAGAIN ? "Timeout" : strerror(errno));
		return false;
	}

	return true;
}

// Display NTP time in human-readable format
// This function is similar to get_timestr() in src/log.c but always prints
// microseconds, where get_timestr() does so only when debug.extra is set
static void format_NTP_time(char time_str[TIMESTR_SIZE], const uint64_t ntp_time)
{
	struct timeval client_time;
	client_time.tv_sec = NTPtoSEC(ntp_time);
	client_time.tv_usec = NTPtoUSEC(ntp_time);
	struct tm client_tm = {0};
	localtime_r(&client_time.tv_sec, &client_tm);
	snprintf(time_str, TIMESTR_SIZE, "%04i-%02i-%02i %02i:%02i:%02i.%06li %s",
	         client_tm.tm_year + 1900, client_tm.tm_mon + 1, client_tm.tm_mday,
	         client_tm.tm_hour, client_tm.tm_min, client_tm.tm_sec,
	         (long int)client_time.tv_usec, client_tm.tm_zone);
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

static uint64_t get_new_time(struct timeval *unix_time, const double offset)
{
	// Get current time
	gettimeofday(unix_time, NULL);

	// Convert from double to native format (signed) and add to the
	// current time.  Note the addition is done in native format to
	// avoid overflow or loss of precision.
	const uint64_t ntp_time = U2LFP(*unix_time) + D2LFP(offset);

	// Convert NTP to native format
	unix_time->tv_sec = NTPtoSEC(ntp_time);
	unix_time->tv_usec = NTPtoUSEC(ntp_time);

	return ntp_time;
}

static bool settime_step(struct timeval *unix_time, const double offset)
{
	log_debug(DEBUG_NTP, "Stepping system time by %e s", offset);

	// Set time immediately
	if(settimeofday(unix_time, NULL) != 0)
	{
		char errbuf[1024];
		strncpy(errbuf, "Failed to set time during NTP sync: ", sizeof(errbuf));
		strncat(errbuf, errno == EPERM ? "Insufficient permissions" : strerror(errno), sizeof(errbuf) - strlen(errbuf) - 1);
		errbuf[sizeof(errbuf) - 1] = '\0';
		log_ntp_message(true, false, errbuf);
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

	log_debug(DEBUG_NTP, "Gradually adjusting system time by %"PRId64" us", (int64_t)tx.offset);

	if(adjtimex(&tx) < 0)
	{
		char errbuf[1024];
		strncpy(errbuf, "Failed to adjust time during NTP sync: ", sizeof(errbuf));
		strncat(errbuf, errno == EPERM ? "Insufficient permissions" : strerror(errno), sizeof(errbuf) - strlen(errbuf) - 1);
		errbuf[sizeof(errbuf) - 1] = '\0';
		log_ntp_message(true, false, errbuf);
		return false;
	}

	return true;
}

// The system precision, RFC 5905's s.rho: what our own clock can resolve, not
// anything a server reports about its own. T1 and T4 come from gettime64(),
// which reads gettimeofday(), so a measurement cannot be finer than one
// microsecond however fine the kernel claims its clock to be
#define NTP_TIMESTAMP_RESOLUTION 1e-6
static double system_precision(void)
{
	struct timespec res;
	if(clock_getres(CLOCK_REALTIME, &res) != 0)
		return NTP_TIMESTAMP_RESOLUTION;

	const double rho = res.tv_sec + res.tv_nsec * 1e-9;
	return rho > NTP_TIMESTAMP_RESOLUTION ? rho : NTP_TIMESTAMP_RESOLUTION;
}

static bool reply(const int fd, const char *server, struct addrinfo *saddr, struct ntp_sync *ntp)
{
	// NTP Packet buffer
	unsigned char buf[48];

	// Receive reply
	if(recv_nowarn(fd, buf, 48, 0) < 48)
	{
		// Get IP address of server
		char ip[INET6_ADDRSTRLEN] = { 0 };
		if(getnameinfo(saddr->ai_addr, saddr->ai_addrlen, ip, sizeof(ip), NULL, 0, NI_NUMERICHOST) != 0)
			strncpy(ip, server, sizeof(ip) - 1);

		log_err("Failed to receive data from NTP server %s (%s): %s",
		        server, ip, errno == EAGAIN ? "Timeout" : strerror(errno));
		return false;
	}

	// Extract precision of server clock
	signed char rho = (signed char)buf[3];
	if(rho < -32 || rho > 0)
	{
		// Accepted limits are 2^-32 (~ 0.2 nanoseconds)
		// to 2^0 (= 1 second)
		char errbuf[1024];
		snprintf(errbuf, sizeof(errbuf), "Received NTP reply has invalid precision: 2^(%i), assuming microsecond accuracy", rho);
		errbuf[sizeof(errbuf) - 1] = '\0';
		log_ntp_message(false, false, errbuf);
		rho = -19;
	}
	// Compute precision of server clock in seconds 2^rho
	ntp->precision = pow(2, rho);

	// Extract root delay and root dispersion of server clock
	uint32_t srv_root_delay, srv_root_dispersion;
	memcpy(&srv_root_delay, &buf[4], sizeof(srv_root_delay));
	memcpy(&srv_root_dispersion, &buf[8], sizeof(srv_root_dispersion));

	// Extract reference ID (Kiss code)
	char kiss_code[4];
	memcpy(kiss_code, &buf[12], sizeof(kiss_code));

	// Extract Transmit Timestamp
	uint64_t netbuffer;
	// ref = Reference Timestamp (Time at which the clock was last set or corrected)
	memcpy(&netbuffer, &buf[16], sizeof(netbuffer));
	const uint64_t ref = ntoh64(netbuffer);
	// Validate ref timestamp is non-zero (server has been synchronized at least once)
	if (ref == 0) {
		log_warn("Received NTP reply has zero reference timestamp, server is not synchronized, ignoring");
		return false;
	}
	// org = Origin Timestamp (Transmit Timestamp @ Client)
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
		// Check for possible Kiss code
		for(size_t i = 0; kiss_codes[i].code != NULL; i++)
		{
			if(memcmp(kiss_code, kiss_codes[i].code, sizeof(kiss_code)) == 0)
			{
				log_warn("Received NTP reply has Kiss code %s: %s, ignoring",
				         kiss_codes[i].code, kiss_codes[i].meaning);
				return false;
			}
		}
		// else:
		log_warn("Received NTP reply has invalid mode, ignoring");
		return false;
	}
	// Check if the request is NTP version 4
	if(((buf[0] >> 3) & 0x07) != 4)
	{
		log_warn("Received NTP reply has unsupported version, ignoring");
		return false;
	}

	// Check and increment stratum
	// Stratum 16 indicates unsynchronised source, and strata 0 // and > 16
	// are reserved. (RFC 5905 fig 11)
	// Primary servers are assigned stratum one; secondary servers at each
	// lower level are assigned stratum numbers one greater than the
	// preceding level. (RFC 5905 s3)

	if (buf[1] < 1 || buf[1] > 15)
	{
		log_warn("Received NTP reply has invalid or unsynchronised stratum, ignoring");
		return false;
	}

	// Store the stratum per-sample. It is only committed to the global
	// ntp_stratum on the success path once the whole round has been
	// validated (see ntp_client()), so a single spoofed reply cannot set it.
	ntp->stratum = buf[1] + 1;

	// Calculate delay and offset
	// T1 is the REAL transmit time captured in request(), not the on-wire
	// origin timestamp (which is now a random anti-spoof nonce).
	const double T1 = ntp->t1 / FRAC;
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

	// This reply is valid
	ntp->valid = true;

	// In some scenarios where the initial frequency offset of the client is
	// relatively large and the actual propagation time small, it is
	// possible for the delay computation to become negative.  For instance,
	// if the frequency difference is 100 ppm and the interval T4-T1 is 64
	// s, the apparent delay is -6.4 ms.  Since negative values are
	// misleading in subsequent computations, the value of delta should be
	// clamped not less than s.rho, where s.rho is the system precision
	// described in Section 11.1, expressed in seconds.
	const double sys_rho = system_precision();
	if(ntp->delta < sys_rho)
		ntp->delta = sys_rho;

	// Return early if not verbose
	if(!config.debug.ntp.v.b)
		return true;

	// Print current time at server
	print_debug_time("Server reference time", NULL, ref);

	// Print current time at client
	print_debug_time("Current time at client", NULL, dst);

	// Print current time at server
	print_debug_time("Current time at server", NULL, ntp->xmt);

	// Print offset and delay
	log_debug(DEBUG_NTP, "Time offset: %e s", ntp->theta);
	log_debug(DEBUG_NTP, "Round-trip delay: %e s", ntp->delta);
	log_debug(DEBUG_NTP, "Server precision: %e s, system precision: %e s",
	          ntp->precision, sys_rho);
	const uint32_t root_delay = ntohl(srv_root_delay);
	log_debug(DEBUG_NTP, "Root delay: %e s", FP2D(root_delay));
	const uint32_t root_dispersion = ntohl(srv_root_dispersion);
	log_debug(DEBUG_NTP, "Root dispersion: %e s", FP2D(root_dispersion));

	return true;
}

static int getsock(const struct addrinfo *saddr)
{
	// Create UDP socket
	const int protocol = saddr->ai_addrlen == sizeof(struct sockaddr_in6) ? AF_INET6 : AF_INET;
	const int s = socket(protocol, SOCK_DGRAM, IPPROTO_UDP);
	if(s == -1)
	{
		char errbuf[1024];
		strncpy(errbuf, "Cannot create UDP socket: ", sizeof(errbuf));
		strncat(errbuf, strerror(errno), sizeof(errbuf) - strlen(errbuf) - 1);
		errbuf[sizeof(errbuf) - 1] = '\0';
		log_ntp_message(true, false, errbuf);
		return -1;
	}

	// Set socket timeout to 5 seconds
	struct timeval tv;
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	if(setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
	{
		char errbuf[1024];
		strncpy(errbuf, "Cannot set socket timeout: ", sizeof(errbuf));
		strncat(errbuf, strerror(errno), sizeof(errbuf) - strlen(errbuf) - 1);
		errbuf[sizeof(errbuf) - 1] = '\0';
		log_ntp_message(true, false, errbuf);
		close(s);
		return -1;
	}

	// Set address to send to/receive from
	if(connect(s, saddr->ai_addr, saddr->ai_addrlen) != 0)
	{
		char errbuf[1024];
		strncpy(errbuf, "Cannot connect to NTP server: ", sizeof(errbuf));
		strncat(errbuf, strerror(errno), sizeof(errbuf) - strlen(errbuf) - 1);
		errbuf[sizeof(errbuf) - 1] = '\0';
		log_ntp_message(true, false, errbuf);
		close(s);
		return -1;
	}

	// Return socket
	return s;
}

bool ntp_client(const char *server, const bool settime, const bool print)
{
	// Resolve server address
	int eai;
	struct addrinfo *saddr = NULL;
	// Resolve server address, port 123 is used for NTP
	if((eai = getaddrinfo(server, "123", NULL, &saddr)) != 0)
	{
		char errbuf[1024];
		strncpy(errbuf, "Cannot resolve NTP server address: ", sizeof(errbuf));
		strncat(errbuf, errno == EAI_SYSTEM ? strerror(errno) : gai_strerror(eai),
		        sizeof(errbuf) - strlen(errbuf) - 1);
		if(eai == EAI_NONAME || eai == EAI_NODATA)
		{
			strncat(errbuf, " \"", sizeof(errbuf) - strlen(errbuf) - 1);
			strncat(errbuf, server, sizeof(errbuf) - strlen(errbuf) - 1);
			strncat(errbuf, "\"", sizeof(errbuf) - strlen(errbuf) - 1);
		}
		errbuf[sizeof(errbuf) - 1] = '\0';
		log_ntp_message(true, false, errbuf);
		if(saddr != NULL)
			freeaddrinfo(saddr);
		return false;
	}

	const unsigned int count = config.ntp.sync.count.v.ui;
	struct ntp_sync *ntp = calloc(count, sizeof(struct ntp_sync));
	if(ntp == NULL)
	{
		log_err("Cannot allocate memory for NTP client");
		if(saddr != NULL)
			freeaddrinfo(saddr);
		return false;
	}

	// Send and receive NTP packets
	for(unsigned int i = 0; i < count; i++)
	{
		// Create socket
		const int s = getsock(saddr);
		if(s == -1)
			continue;

		// Send request
		if(!request(s, server, saddr, &ntp[i]))
		{
			close(s);
			free(ntp);
			if(saddr != NULL)
				freeaddrinfo(saddr);
			return false;
		}
		// Get reply
		if(!reply(s, server, saddr, &ntp[i]))
		{
			close(s);
			continue;
		}

		// Close socket
		close(s);

		// Sleep for some time to avoid flooding the server
		if(print)
			printf(".");
		fflush(stdout);
		usleep(NTP_DELAY);
	}
	if(print)
		printf("\n");

	// Free allocated memory
	if(saddr != NULL)
		freeaddrinfo(saddr);
	saddr = NULL;

	// Compute average and standard deviation
	unsigned int valid = 0;
	double theta_avg = 0.0, theta_stdev = 0.0;
	double delta_avg = 0.0, delta_stdev = 0.0;
	for(unsigned int i = 0; i < count; i++)
	{
		// Skip invalid values
		if(!ntp[i].valid)
			continue;

		theta_avg += ntp[i].theta;
		delta_avg += ntp[i].delta;
		valid++;
	}

	if(valid == 0)
	{
		log_ntp_message(false, false, "No valid NTP replies received, check server and network connectivity");
		free(ntp);
		return false;
	}
	log_info("Received %u/%u valid NTP replies from %s", valid, count, server);

	theta_avg /= valid;
	delta_avg /= valid;
	for(unsigned int i = 0; i < count; i++)
	{
		// Skip invalid values
		if(!ntp[i].valid)
			continue;

		theta_stdev += pow(ntp[i].theta - theta_avg, 2);
		delta_stdev += pow(ntp[i].delta - delta_avg, 2);
	}
	theta_stdev = sqrt(theta_stdev / valid);
	delta_stdev = sqrt(delta_stdev / valid);

	log_debug(DEBUG_NTP, "Average time offset: (%e +/- %e) s", theta_avg, theta_stdev);
	log_debug(DEBUG_NTP, "Average round-trip delay: (%e +/- %e) s", delta_avg, delta_stdev);

	// Reject synchronization if the standard deviation of the time offset
	// or round-trip delay is larger than 1 second
	if(theta_stdev > 1.0 || delta_stdev > 1.0)
	{
		log_ntp_message(false, false, "Standard deviation of time offset is too large, rejecting synchronization");
		free(ntp);
		return false;
	}

	// Compute trimmed mean (average excluding outliers)
	double theta_trim = 0.0, delta_trim = 0.0;
	unsigned int trim = 0;
	// Track the largest stratum among the samples that survive trimming.
	// Choosing the maximum is conservative: a single surviving spoofed
	// low-stratum reply cannot inflate the perceived clock quality.
	uint8_t trim_stratum = 0;
	for(unsigned int i = 0; i < count; i++)
	{
		// Skip invalid values
		if(!ntp[i].valid)
			continue;

		// Skip outliers
		// We consider values > 2 standard deviations from the mean as
		// outliers
		if(fabs(ntp[i].theta - theta_avg) > 2 * theta_stdev ||
		   fabs(ntp[i].delta - delta_avg) > 2 * delta_stdev)
			continue;

		theta_trim += ntp[i].theta;
		delta_trim += ntp[i].delta;
		if(ntp[i].stratum > trim_stratum)
			trim_stratum = ntp[i].stratum;
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

	log_info("NTP time offset: %e ms (excluded %u outliers)", 1e3*theta_trim, count - trim);
	log_info("NTP round-trip delay: %e ms (excluded %u outliers)", 1e3*delta_trim, count - trim);

	// Set time if requested
	if(settime)
	{
		// Calculate corrected time
		struct timeval unix_time;
		const uint64_t ntp_time = get_new_time(&unix_time, theta_trim);

		// If the clock deviates more than 0.5 seconds from the NTP server,
		// the time is updated immediately.  Otherwise, the time is updated
		// gradually to avoid sudden jumps in the system clock.
		// The threshold of 0.5 seconds is hard-wired into the kernel
		// since Linux 2.6.26, see man ntp_adjtime(2) for details.
		bool success;
		if(fabs(theta_trim) > 0.5)
		{
			// Panic threshold: refuse to step the clock by an
			// implausibly large amount. This blocks a consistent
			// spoofed/malicious server from moving the clock by an
			// arbitrary magnitude. The very first sync after boot is
			// exempt so RTC-less devices can set their initial time.
			if(!ntp_first_sync && fabs(theta_trim) > NTP_MAX_STEP_SECS)
			{
				char errbuf[256];
				snprintf(errbuf, sizeof(errbuf),
				         "Refusing to step system clock by %.0f s (exceeds %d s panic threshold) - possible malicious NTP server. If this device has no RTC, restart FTL to permit the initial large step.",
				         theta_trim, NTP_MAX_STEP_SECS);
				errbuf[sizeof(errbuf) - 1] = '\0';
				log_ntp_message(true, false, errbuf);
				return false;
			}
			success = settime_step(&unix_time, theta_trim);
		}
		else
			success = settime_skew(theta_trim);

		// Return early if time could not be set
		if(!success)
			return false;

		// The initial post-boot synchronization is complete; enforce the
		// panic threshold on all subsequent clock steps.
		ntp_first_sync = false;

		// Update last NTP sync time
		ntp_last_sync = ntp_time;

		// Finally, adjust RTC if configured
		if(config.ntp.sync.rtc.set.v.b)
			ntp_sync_rtc();
	}

	// Set our server's root delay and dispersion
	// Following RFC5905, Scn. 4, the root delay (total round-trip delay to
	// the reference clock) is DELTA while the root dispersion (total
	// dispersion to the reference clock) is EPSILON. The synchronization
	// distance (the maximum error due to all causes) may be calculated as
	// (DELTA / 2) + EPSILON.
	// Note that the root dispersion should increase over time due to clock
	// drift, but we do not model this here. Instead, we update the root
	// dispersion after each successful NTP sync to reflect the current
	// dispersion of our reference clock.
	ntp_root_delay = D2FP(delta_trim);
	ntp_root_dispersion = D2FP(theta_stdev);

	// Commit the stratum only now that the whole round has been validated,
	// using the most conservative (largest) surviving stratum.
	ntp_stratum = trim_stratum;

	// Offset and delay larger than ACCURACY seconds are considered as invalid
	// during local testing (e.g., when the server is on the same machine).
	// The offset is signed, so compare its magnitude - a large negative
	// offset is just as inaccurate as a large positive one.
	return fabs(theta_trim) < ACCURACY && delta_trim < ACCURACY;
}

static void *ntp_client_thread(void *arg)
{
	(void)arg;
	// Set thread name
	prctl(PR_SET_NAME, thread_names[NTP_CLIENT], 0, 0, 0);

	// Artificial initial delay to allow DNS server to become available
	thread_sleepms(NTP_CLIENT, 1000 * 10);
	log_debug(DEBUG_NTP, "Starting NTP client");

	// Run NTP client
	unsigned int retry_count = 0;
	bool ntp_server_started = false;
	bool first_run = true;
	while(!killed)
	{
		// Get time before NTP sync
		const double before = double_time();

		// Run NTP client
		const bool success = ntp_client(config.ntp.sync.server.v.s, true, false);

		// Get time after NTP sync
		const double after = double_time();

		// If the time was updated by more than ten minutes, restart FTL
		// to import recent data. This is relevant when the system time
		// was set to an incorrect value (e.g., due to a dead CMOS
		// battery or overall missing RTC) and the time was off.
		double time_delta = fabs(after - before);
		if(first_run && time_delta > 600)
		{
			log_info("System time was updated by %.1f seconds", time_delta);
			restart_ftl("System time updated");
		}

		// Calculate time to sleep. Clamp to zero when the sync itself took
		// longer than the configured interval, otherwise the unsigned
		// subtraction would underflow into an effectively infinite sleep.
		const unsigned int interval = config.ntp.sync.interval.v.ui;
		unsigned int sleep_time = time_delta >= interval ? 0 : interval - (unsigned int)time_delta;

		// Set first run to false
		first_run = false;

		if(!ntp_server_started)
		{
			if(success)
			{
				// Initialize NTP server only after first high
				// accuracy NTP synchronization to ensure that
				// the time is set correctly
				ntp_server_started = ntp_server_start();
			}
			else
			{

				// Reduce retry time if the time is not accurate enough
				if(retry_count++ < RETRY_ATTEMPTS &&
				   sleep_time > RETRY_INTERVAL)
				   sleep_time = RETRY_INTERVAL;
					log_info("Local time is too inaccurate, retrying in %u seconds before launching NTP server", sleep_time);
			}
		}

		// Intermediate cancellation-point
		BREAK_IF_KILLED();

		// Sleep before retrying
		thread_sleepms(NTP_CLIENT, 1000 * sleep_time);
	}

	log_info("Terminating NTP thread");

	return NULL;
}

bool ntp_start_sync_thread(pthread_attr_t *attr)
{
	// Return early if NTP client is disabled
	if(config.ntp.sync.active.v.b == false ||
	   config.ntp.sync.server.v.s == NULL ||
	   strlen(config.ntp.sync.server.v.s) == 0 ||
	   config.ntp.sync.interval.v.ui == 0)
	{
		log_info("NTP sync is disabled");
		ntp_server_start();
		return false;
	}
	// Return early if a clock disciplining NTP client is detected
	// Checks chrony, the ntp family (ntp, ntpsec and openntpd), and ntpd-rs
	const int chronyd_found = search_proc("chronyd");
	const int ntpd_found = search_proc("ntpd");
	const int ntp_daemon_found = search_proc("ntp-daemon");
	if(chronyd_found > 0 || ntpd_found > 0 || ntp_daemon_found > 0)
	{
		log_info("Clock disciplining NTP client detected ( %s%s%s), not starting embedded NTP client/server",
		         chronyd_found > 0 ? "chronyd " : "",
		         ntpd_found > 0 ? "ntpd " : "",
		         ntp_daemon_found > 0 ? "ntp-daemon " : "");
		return false;
	}

	// Check if we have the ambient capabilities to set the system time.
	// Without CAP_SYS_TIME, we cannot set the system time and the NTP
	// client will not be able to synchronize the time so there is no point
	// in starting the thread.
	if(!check_capability(CAP_SYS_TIME))
	{
		log_warn("Insufficient permissions to set system time (CAP_SYS_TIME required), NTP client not available");
		ntp_server_start();
		return false;
	}

	// Create thread
	if(pthread_create(&threads[NTP_CLIENT], attr, ntp_client_thread, NULL) != 0)
	{
		log_err("Cannot create NTP client thread");
		ntp_server_start();
		return false;
	}

	return true;
}
