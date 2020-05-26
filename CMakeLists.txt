# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

cmake_minimum_required(VERSION 3.1)
project(PIHOLE_FTL C)

set(DNSMASQ_VERSION pi-hole-2.81)

add_subdirectory(src)
