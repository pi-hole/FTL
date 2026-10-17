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
// opendir(), readdir()
#include <dirent.h>
// major(), minor()
#include <sys/sysmacros.h>
// PATH_MAX
#include <limits.h>
// use_capability()
#include "capabilities.h"
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

// Is this device number one of the kernel's RTCs? /sys/class/rtc/<name>/dev
// holds "major:minor" for each of them
static bool is_rtc_device(const dev_t rdev)
{
	DIR *dir = opendir("/sys/class/rtc");
	if(dir == NULL)
		return false;

	bool found = false;
	struct dirent *ent;
	while(!found && (ent = readdir(dir)) != NULL)
	{
		if(ent->d_name[0] == '.')
			continue;

		char devpath[PATH_MAX];
		snprintf(devpath, sizeof(devpath), "/sys/class/rtc/%s/dev", ent->d_name);
		FILE *fp = fopen(devpath, "r");
		if(fp == NULL)
			continue;

		unsigned int maj = 0, min = 0;
		if(fscanf(fp, "%u:%u", &maj, &min) == 2 &&
		   maj == major(rdev) && min == minor(rdev))
			found = true;
		fclose(fp);
	}
	closedir(dir);

	return found;
}

// Open one RTC device, momentarily taking ownership if the current permissions
// do not allow it. On some embedded systems the RTC device is owned by root
// exclusively and the FTL user cannot even open it; without access to the RTC,
// the capability to set the time (CAP_SYS_TIME) is useless.
//
// The path can come from configuration (ntp.sync.rtc.device), so the escalation
// must not be usable to touch anything but an actual RTC device. Everything past
// the initial open therefore acts on a single O_PATH|O_NOFOLLOW handle to the
// exact path entry, referenced through /proc/self/fd: a final symlink is not
// followed, the entry must be a character device, and the target cannot be
// swapped for another file between the check and the chown. Returns a readable
// file descriptor on success, -1 otherwise.
static int open_rtc_device(const char *path)
{
	// Fast path: the device is already openable
	int rtc_fd = open(path, O_RDONLY | O_CLOEXEC);
	if(rtc_fd != -1)
		return rtc_fd;

	// Only a permission problem is worth escalating for
	if(errno != EACCES)
		return -1;

	// Pin the exact path entry without following a final symlink and without
	// needing any access right to it. All following operations use this handle.
	const int path_fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	if(path_fd == -1)
	{
		log_debug(DEBUG_NTP, "open(\"%s\", O_PATH) failed: %s", path, strerror(errno));
		return -1;
	}

	// It has to be an RTC - not a regular file or another device whose
	// ownership someone wants handed to the FTL user.
	struct stat st = { 0 };
	if(fstat(path_fd, &st) == -1 || !S_ISCHR(st.st_mode) || !is_rtc_device(st.st_rdev))
	{
		log_debug(DEBUG_NTP, "\"%s\" is not an RTC device, refusing", path);
		close(path_fd);
		return -1;
	}

	// The ownership changes act on the pinned handle itself. An O_PATH handle
	// cannot be read from, so the reopen goes through /proc/self/fd, which
	// resolves to the very same file
	char procpath[32] = { 0 };
	snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", path_fd);

	// CAP_CHOWN is kept out of use, raise it for the ownership changes only
	const bool raised = use_capability(CAP_CHOWN, true);

	// Take ownership momentarily
	const uid_t uid = getuid();
	const gid_t gid = getgid();
	if(fchownat(path_fd, "", uid, gid, AT_EMPTY_PATH) == -1)
	{
		log_debug(DEBUG_NTP, "chown(\"%s\", %u, %u) failed: %s", path, uid, gid,
		          errno == EPERM ? "Insufficient permissions (CAP_CHOWN required)" : strerror(errno));
		if(raised)
			use_capability(CAP_CHOWN, false);
		close(path_fd);
		return -1;
	}

	// Open it for reading now that we own it
	rtc_fd = open(procpath, O_RDONLY | O_CLOEXEC);

	// Restore the original owner regardless of whether the reopen succeeded.
	// A device left with the FTL user is not one to go on working with
	if(fchownat(path_fd, "", st.st_uid, st.st_gid, AT_EMPTY_PATH) == -1)
	{
		log_warn("Cannot restore the owner of \"%s\": %s", path, strerror(errno));
		if(rtc_fd != -1)
			close(rtc_fd);
		rtc_fd = -1;
	}

	if(raised)
		use_capability(CAP_CHOWN, false);
	close(path_fd);
	return rtc_fd;
}

// Try to find the RTC device and open it
static int open_rtc(void)
{
	// If the user has specified an RTC device, use exactly that one
	if(config.ntp.sync.rtc.device.v.s != NULL &&
	   strlen(config.ntp.sync.rtc.device.v.s) > 0)
	{
		const int rtc_fd = open_rtc_device(config.ntp.sync.rtc.device.v.s);
		log_debug(DEBUG_NTP, "%s RTC at \"%s\"",
		          rtc_fd != -1 ? "Successfully opened" : "Failed to open",
		          config.ntp.sync.rtc.device.v.s);
		return rtc_fd;
	}

	// Otherwise, try the well-known device paths in turn
	for(size_t i = 0; i < ArraySize(rtc_devices); i++)
	{
		const int rtc_fd = open_rtc_device(rtc_devices[i]);
		if(rtc_fd != -1)
		{
			log_debug(DEBUG_NTP, "Successfully opened RTC at \"%s\"", rtc_devices[i]);
			return rtc_fd;
		}
		log_debug(DEBUG_NTP, "Failed to open RTC at \"%s\"", rtc_devices[i]);
	}

	return -1;
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
	if(config.ntp.sync.rtc.utc.v.b)
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
