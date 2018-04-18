/* Pi-hole: A black hole for Internet advertisements
*  (c) 2017 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  subroutines that handle new events
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

void FTL_dnsmasq_reload(void *attr)
{
	enable_thread_lock();

	disable_thread_lock();
	return NULL;
}
