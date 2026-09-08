/* Pi-hole: A black hole for Internet advertisements
*  (c) 2019 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  Compile-time installation paths
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef INSTALL_PATHS_H
#define INSTALL_PATHS_H

// Base directory holding Pi-hole's configuration and state (pihole.toml,
// dnsmasq.conf, the databases, ...). It is baked in at compile time and can be
// overridden by packagers that install Pi-hole into a different prefix, e.g.
//   cmake -DPIHOLE_INSTALL_DIR=/opt/pihole/etc ...
// This is a build-time knob only; it deliberately does not expose a runtime
// override (see GHSA-6w8x-p785-6pm4 for why some paths must stay fixed).
#ifndef PIHOLE_INSTALL_DIR
#define PIHOLE_INSTALL_DIR "/etc/pihole"
#endif

#endif // INSTALL_PATHS_H
