#!/usr/bin/env bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2017 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# Simple speed test bench for FTL
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

function GetFTLData {
    # Open connection to FTL
    exec 3<>/dev/tcp/localhost/"$(cat /var/run/pihole-FTL.port)"

    # Test if connection is open
    if { >&3; } 2> /dev/null; then
       # Send command to FTL
       echo -e ">$1" >&3
       echo -e ">quit" >&3

       # Read all input
       cat <&3 &> /dev/null

       # Close connection
       exec 3>&-
       exec 3<&-
   fi
}

echo "Getting statistics data"
time GetFTLData "stats"

echo "Getting over time data"
time GetFTLData "overTime"

echo "Getting all queries (get all queries)"
time GetFTLData "getallqueries"
