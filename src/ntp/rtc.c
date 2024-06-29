/* Pi-hole: A black hole for Internet advertisements
*  (c) 2024 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Real Time Clock (RTC) functions
*  The routines in this file have been inspired by man pages
*  and the source of the hwclock which is part of the util-linux
*  project (https://github.com/util-linux/util-linux/)
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include "ntp/ntp.h"

// ioctl()
#include <sys/ioctl.h>
// RTC
#include <linux/rtc.h>
// O_WRONLY
#include <fcntl.h>
// struct config
#include "config/config.h"

// List of RTC devices from
// https://github.com/util-linux/util-linux/blob/41e7686c9ad1ea7892b9d8941c266869bf6a28dd/sys-utils/hwclock-rtc.c#L85-L93
static const char * const rtc_devices[] = {
#ifdef __ia64__
	"/dev/efirtc",
	"/dev/misc/efirtc",
#endif
	"/dev/rtc0",
	"/dev/rtc",
	"/dev/misc/rtc"
};

static void print_tm_time(const char *label, const struct tm *tm)
{
	char timestr[TIMESTR_SIZE] = { 0 };
	strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tm);
	log_info("%s %s", label, timestr);
}

// Try to find the RTC device and open it
static int open_rtc(void)
{
	int rtc_fd = -1;

	// Get current user's UID and GID
	const uid_t uid = getuid();
	const gid_t gid = getgid();

	// If the user has specified an RTC device, try to open it
	if(config.ntp.rtc.device.v.s != NULL &&
	   strlen(config.ntp.rtc.device.v.s) > 0)
	{
		// Open the RTC device
		rtc_fd = open(config.ntp.rtc.device.v.s, O_RDONLY);
		if (rtc_fd != -1)
		{
			log_debug(DEBUG_NTP, "Successfully opened RTC at \"%s\"",
			          config.ntp.rtc.device.v.s);
			return rtc_fd;
		}

		// If the open failed because of permissions, try to change them
		// momentarily. On some embedded systems, the RTC device is owned by
		// root exclusively and users do not have permission to even open it.
		// Without being able to access the RTC, the capability to set the
		// time (CAP_SYS_TIME) is useless.
		if(errno == EACCES)
		{
			// Get current owner of the device
			struct stat st = { 0 };
			if(stat(config.ntp.rtc.device.v.s, &st) == -1)
			{
				log_debug(DEBUG_NTP, "stat(\"%s\") failed: %s",
				          config.ntp.rtc.device.v.s, strerror(errno));
				return -1;
			}

			if(chown(config.ntp.rtc.device.v.s, uid, gid) == -1)
			{
				log_debug(DEBUG_NTP, "chown(\"%s\", %u, %u) failed: %s",
				          config.ntp.rtc.device.v.s, uid, gid, strerror(errno));
				return -1;
			}

			rtc_fd = open(config.ntp.rtc.device.v.s, O_RDONLY);
			if (rtc_fd != -1)
			{
				log_debug(DEBUG_NTP, "Successfully opened RTC at \"%s\"",
				          config.ntp.rtc.device.v.s);
			}

			// Chown the device back to the original owner
			if(chown(config.ntp.rtc.device.v.s, st.st_uid, st.st_gid) == -1)
			{
				log_debug(DEBUG_NTP, "chown(\"%s\", %u, %u) failed: %s",
						config.ntp.rtc.device.v.s, st.st_uid, st.st_gid, strerror(errno));
				return -1;
			}

			// Return the RTC file descriptor (can be -1)
			return rtc_fd;
		}

		log_debug(DEBUG_NTP, "Failed to open RTC at \"%s\": %s",
		          config.ntp.rtc.device.v.s, strerror(errno));

		return -1;
	}

	// If the user has not specified an RTC device, try to open the default
	// ones
	for(size_t i = 0; i < ArraySize(rtc_devices); i++)
	{
		rtc_fd = open(rtc_devices[i], O_RDONLY);
		if (rtc_fd != -1)
		{
			log_debug(DEBUG_NTP, "Successfully opened RTC at \"%s\"",
			          rtc_devices[i]);
			break;
		}

		// If the open failed because of permissions, try to change them
		// momentarily
		if(errno == EACCES)
		{
			// Get current owner of the device
			struct stat st = { 0 };
			if(stat(rtc_devices[i], &st) == -1)
			{
				log_debug(DEBUG_NTP, "stat(\"%s\") failed: %s",
				          rtc_devices[i], strerror(errno));
				return -1;
			}

			if(chown(rtc_devices[i], uid, gid) == -1)
			{
				log_debug(DEBUG_NTP, "chown(\"%s\", %u, %u) failed: %s",
				          rtc_devices[i], uid, gid, strerror(errno));
				return -1;
			}

			rtc_fd = open(rtc_devices[i], O_RDONLY);
			if (rtc_fd != -1)
			{
				log_debug(DEBUG_NTP, "Successfully opened RTC at \"%s\"",
				          rtc_devices[i]);
			}

			// Chown the device back to the original owner
			if(chown(rtc_devices[i], st.st_uid, st.st_gid) == -1)
			{
				log_debug(DEBUG_NTP, "chown(\"%s\", %u, %u) failed: %s",
						rtc_devices[i], st.st_uid, st.st_gid, strerror(errno));
				return -1;
			}

			// Return the RTC file descriptor (can be -1)
			return rtc_fd;
		}

		log_debug(DEBUG_NTP, "Failed to open RTC at \"%s\": %s",
		          rtc_devices[i], strerror(errno));
	}

	return rtc_fd;
}

static bool read_rtc(struct tm *tm)
{
	// Open the RTC device
	const int rtc_fd = open_rtc();
	if(rtc_fd == -1)
		return false;

	// Read the RTC time
	struct rtc_time rtc_tm = { 0 };
	const int rc = ioctl(rtc_fd, RTC_RD_TIME, &rtc_tm);
	if(rc == -1)
	{
		log_debug(DEBUG_NTP, "ioctl(RTC_RD_NAME) failed: %s",
		          strerror(errno));
		close(rtc_fd);
		return false;
	}

	// Convert the kernel's struct tm to the standard struct tm
	tm->tm_sec   = rtc_tm.tm_sec;
	tm->tm_min   = rtc_tm.tm_min;
	tm->tm_hour  = rtc_tm.tm_hour;
	tm->tm_mday  = rtc_tm.tm_mday;
	tm->tm_mon   = rtc_tm.tm_mon;
	tm->tm_year  = rtc_tm.tm_year;
	tm->tm_wday  = rtc_tm.tm_wday;
	tm->tm_yday  = rtc_tm.tm_yday;
	tm->tm_isdst = -1; // the RTC does not provide this information
	print_tm_time("Current RTC time is", tm);

	// Close the RTC device
	close(rtc_fd);

	return true;
}

// Set the Hardware Clock to the broken down time <new_time>.
// Use ioctls to "rtc" device to set the time.
static bool set_rtc(const struct tm *new_time)
{
	// Open the RTC device
	const int rtc_fd = open_rtc();
	if(rtc_fd == -1)
		return false;

	// Set the RTC time from the broken down time
	struct rtc_time rtc_tm = { 0 };
	rtc_tm.tm_sec   = new_time->tm_sec;
	rtc_tm.tm_min   = new_time->tm_min;
	rtc_tm.tm_hour  = new_time->tm_hour;
	rtc_tm.tm_mday  = new_time->tm_mday;
	rtc_tm.tm_mon   = new_time->tm_mon;
	rtc_tm.tm_year  = new_time->tm_year;
	rtc_tm.tm_wday  = new_time->tm_wday;
	rtc_tm.tm_yday  = new_time->tm_yday;
	rtc_tm.tm_isdst = new_time->tm_isdst;

	// Set the RTC time
	const int rc = ioctl(rtc_fd, RTC_SET_TIME, &rtc_tm);
	if(rc == -1)
	{
		log_debug(DEBUG_NTP, "ioctl(RTC_SET_TIME) failed: %s",
		          strerror(errno));
		close(rtc_fd);
		return false;
	}
	print_tm_time("RTC time set to", new_time);

	// Close the RTC device
	close(rtc_fd);
	return true;
}

bool ntp_sync_rtc(void)
{
	// Wait until the beginning of the next second as the RTC only has a
	// resolution of one second
	struct timespec ts = { 0 };
	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec++;
	ts.tv_nsec = 0;
	clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL);

	// Time to which we will set Hardware Clock, in broken down format
	struct tm new_time = { 0 };
	const time_t newtime = time(NULL);
	if(config.ntp.rtc.utc.v.b)
		// UTC
		gmtime_r(&newtime, &new_time);
	else
		// Local time
		localtime_r(&newtime, &new_time);

	// Read the current time from the RTC
	struct tm rtc_time = { 0 };
	if(!read_rtc(&rtc_time))
	{
		log_debug(DEBUG_NTP, "Failed to read RTC time");
		return false;
	}

	// If the RTC time is the same as the current time, we don't need to set
	// it. We don't use memcmp() here because the tm struct may contain
	// additional fields that are not filled in by the RTC (e.g. tm_isdst).
	if(rtc_time.tm_sec  == new_time.tm_sec  &&
	   rtc_time.tm_min  == new_time.tm_min  &&
	   rtc_time.tm_hour == new_time.tm_hour &&
	   rtc_time.tm_mday == new_time.tm_mday &&
	   rtc_time.tm_mon  == new_time.tm_mon  &&
	   rtc_time.tm_year == new_time.tm_year)
	{
		// The RTC time is already correct, return early
		log_debug(DEBUG_NTP, "RTC time is already correct");
		return true;
	}

	// Set the RTC time
	if(!set_rtc(&new_time))
	{
		log_debug(DEBUG_NTP, "Failed to set RTC time");
		return false;
	}

	return true;
}
