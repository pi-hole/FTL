/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Linux capability check routines
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// Definition of LINUX_CAPABILITY_VERSION_*
#define FTLDNS
#include "dnsmasq/dnsmasq.h"
#undef __USE_XOPEN
#include "FTL.h"
#include "capabilities.h"
#include "config/config.h"
// DOT_PORT
#include "dotdoh/server.h"
#include "log.h"

static const unsigned int capabilityIDs[]   = { CAP_CHOWN ,  CAP_DAC_OVERRIDE ,  CAP_DAC_READ_SEARCH ,  CAP_FOWNER ,  CAP_FSETID ,  CAP_KILL ,  CAP_SETGID ,  CAP_SETUID ,  CAP_SETPCAP ,  CAP_LINUX_IMMUTABLE ,  CAP_NET_BIND_SERVICE ,  CAP_NET_BROADCAST ,  CAP_NET_ADMIN ,  CAP_NET_RAW ,  CAP_IPC_LOCK ,  CAP_IPC_OWNER ,  CAP_SYS_MODULE ,  CAP_SYS_RAWIO ,  CAP_SYS_CHROOT ,  CAP_SYS_PTRACE ,  CAP_SYS_PACCT ,  CAP_SYS_ADMIN ,  CAP_SYS_BOOT ,  CAP_SYS_NICE ,  CAP_SYS_RESOURCE ,  CAP_SYS_TIME ,  CAP_SYS_TTY_CONFIG ,  CAP_MKNOD ,  CAP_LEASE ,  CAP_AUDIT_WRITE ,  CAP_AUDIT_CONTROL ,  CAP_SETFCAP };
static const char*        capabilityNames[] = {"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE", "CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP"};

/**
 * @brief Retrieves the capabilities of the current process.
 *
 * This function determines the capabilities version used by the current kernel
 * and retrieves the current capabilities of the process.
 *
 * @param data Pointer to a cap_user_data_t structure where the capabilities
 *             will be stored. The memory for this structure is allocated within
 *             the function and should be freed by the caller.
 */
static bool get_caps(cap_user_data_t *data)
{
	cap_user_header_t hdr = calloc(1, sizeof(*hdr));

	// Determine capabilities version used by the current kernel
	if(capget(hdr, NULL) != 0)
	{
		log_err("Failed to retrieve capabilities header: %s", strerror(errno));
		free(hdr);
		return false;
	}

	// Get size of capabilities
	int capsize = 1; // VFS_CAP_U32_1
	if (hdr->version != LINUX_CAPABILITY_VERSION_1)
	{
		// If unknown version, use largest supported version (3)
		// Version 2 is deprecated according to linux/capability.h
		if (hdr->version != LINUX_CAPABILITY_VERSION_2)
		{
			hdr->version = LINUX_CAPABILITY_VERSION_3;
			capsize = 2; // VFS_CAP_U32_3
		}
		else
		{
			// Use version 2
			capsize = 2; // VFS_CAP_U32_2
		}
	}

	// Get current capabilities
	*data = calloc(capsize, sizeof(**data));
	if(capget(hdr, *data) != 0)
	{
		log_err("Failed to retrieve capabilities data: %s", strerror(errno));
		free(hdr);
		free(*data);
		return false;
	}

	// Free allocated memory
	free(hdr);

	return true;
}

/**
 * @brief Checks if a specific capability is available.
 *
 * This function retrieves the current capabilities of the process and checks if
 * the specified capability is both permitted and effective.
 *
 * @param cap The capability to check.
 * @return true if the capability is available, false otherwise.
 */
bool check_capability(const unsigned int cap)
{
	cap_user_data_t data = NULL;
	if(!get_caps(&data))
		return false;

	// Check if the capability is available
	const bool available = ((data->permitted & (1 << cap)) && (data->effective & (1 << cap)));

	// Free memory
	free(data);

	return available;
}

/**
 * @brief Checks the required Linux capabilities for the application.
 *
 * This function retrieves the current Linux capabilities and logs the status of
 * each capability. It then checks if the necessary capabilities for the
 * application are available and logs warnings if any required capability is
 * missing.
 *
 * @return true if all required capabilities are available, false otherwise.
 */
// Does anything in this configuration want a port below 1024? 1024 itself is
// the first unprivileged one (net.ipv4.ip_unprivileged_port_start). dns.port,
// the DoT listener on DOT_PORT and every entry of webserver.port count, the
// last being a list like "80o,443os,[::]:80o", so the port is what follows the
// final colon, if any. DoH needs nothing extra, it rides on a webserver port
static bool binds_privileged_port(void)
{
	if(config.dns.port.v.u16 != 0 && config.dns.port.v.u16 < 1024)
		return true;

	if(config.dns.dot.v.b && DOT_PORT < 1024)
		return true;

	const char *list = config.webserver.port.v.s;
	if(list == NULL)
		return false;

	char *copy = strdup(list);
	if(copy == NULL)
		return false;

	bool privileged = false;
	char *save = NULL;
	for(char *tok = strtok_r(copy, ",", &save); tok != NULL && !privileged; tok = strtok_r(NULL, ",", &save))
	{
		// Skipped through a separate pointer so the loop variable itself
		// is not modified in the body
		const char *ent = tok;
		while(*ent == ' ')
			ent++;

		// An entry may carry an address, so the port follows the last colon
		const char *port = strrchr(ent, ':');
		port = port != NULL ? port + 1 : ent;

		const long p = strtol(port, NULL, 10);
		if(p > 0 && p < 1024)
			privileged = true;
	}

	free(copy);
	return privileged;
}

// Warn when a capability this configuration needs is missing. Returns false
// only in that case: a capability the running configuration does not use is
// not reported at all
static bool warn_missing_cap(const cap_user_data_t data, const unsigned int capid,
                             const char *name, const bool needed, const char *what)
{
	if(!needed)
		return true;

	if((data->permitted & (1u << capid)) && (data->effective & (1u << capid)))
		return true;

	log_warn("Linux capability %s is not available, needed for %s", name, what);
	return false;
}

bool check_capabilities(void)
{
	cap_user_data_t data = NULL;
	if(!get_caps(&data))
		return false;

	log_debug(DEBUG_CAPS, "***************************************");
	log_debug(DEBUG_CAPS, "* Linux capability debugging enabled  *");
	for(unsigned int i = 0u; i < ArraySize(capabilityIDs); i++)
	{
		const unsigned int capid = capabilityIDs[i];
		log_debug(DEBUG_CAPS, "* %-24s (%02u) = %s%s%s *",
			capabilityNames[capid], capid,
			((data->permitted   & (1 << capid)) ? "P":"-"),
			((data->inheritable & (1 << capid)) ? "I":"-"),
			((data->effective   & (1 << capid)) ? "E":"-"));
	}
	log_debug(DEBUG_CAPS, "***************************************");

	// Warn only about what this configuration actually uses. A container
	// started without a capability it does not need is a deliberate choice,
	// not a fault to report on every start
	bool capabilities_okay = true;
	capabilities_okay &= warn_missing_cap(data, CAP_NET_ADMIN, "CAP_NET_ADMIN",
	                                      config.dhcp.active.v.b,
	                                      "ARP injection while acting as the DHCP server");
	capabilities_okay &= warn_missing_cap(data, CAP_NET_BIND_SERVICE, "CAP_NET_BIND_SERVICE",
	                                      binds_privileged_port(),
	                                      "binding a privileged port");
	capabilities_okay &= warn_missing_cap(data, CAP_SYS_NICE, "CAP_SYS_NICE",
	                                      config.misc.nice.v.i < 0,
	                                      "raising the process priority set in misc.nice");
	capabilities_okay &= warn_missing_cap(data, CAP_SYS_TIME, "CAP_SYS_TIME",
	                                      config.ntp.sync.active.v.b,
	                                      "setting the system time from the NTP client");

	// Always needed: FTL chowns the files it creates to the pihole user
	capabilities_okay &= warn_missing_cap(data, CAP_CHOWN, "CAP_CHOWN", true,
	                                      "taking ownership of the files FTL creates");

	// Free allocated memory
	free(data);

	// Return whether capabilities are all okay
	return capabilities_okay;
}
