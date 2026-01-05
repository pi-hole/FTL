# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# /CMakeList.txt
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

# C17 supports requires minimum CMake version 3.21
# GCC 8.1.0
# LLVM Clang 7.0.0
cmake_minimum_required(VERSION 3.21)
set(CMAKE_C_STANDARD 17)

project(PIHOLE_FTL C)

set(DNSMASQ_VERSION pi-hole-v2.92rc1)

# Set default install prefix to /opt/pihole for backward compatibility
# Packagers (e.g., Yocto) can override with -DCMAKE_INSTALL_PREFIX=/usr
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
    set(CMAKE_INSTALL_PREFIX "/opt/pihole" CACHE PATH "Install prefix" FORCE)
endif()

# Force FHS system directories BEFORE GNUInstallDirs (CMake <4.1 workaround)
# In CMake 4.1+, CMP0192 would handle this automatically for /opt prefixes
# These directories are ALWAYS absolute (/etc, /var, /run) per FHS 3.0
set(CMAKE_INSTALL_SYSCONFDIR "/etc" CACHE PATH "System configuration (/etc)" FORCE)
set(CMAKE_INSTALL_LOCALSTATEDIR "/var" CACHE PATH "Variable state data (/var)" FORCE)
set(CMAKE_INSTALL_RUNSTATEDIR "/run" CACHE PATH "Runtime data (/run)" FORCE)

include(GNUInstallDirs)

if(CMAKE_INSTALL_PREFIX MATCHES "^/opt/")
    set(PIHOLE_INSTALL_SCRIPTDIR "${CMAKE_INSTALL_LIBEXECDIR}" CACHE PATH "Script install directory")
    set(PIHOLE_INSTALL_LOGDIR "${CMAKE_INSTALL_LOCALSTATEDIR}/log/pihole" CACHE PATH "Log directory")
    set(PIHOLE_INSTALL_RUNDIR "${CMAKE_INSTALL_RUNSTATEDIR}" CACHE PATH "Runtime directory")
else()
    set(PIHOLE_INSTALL_SCRIPTDIR "${CMAKE_INSTALL_LIBEXECDIR}/pihole" CACHE PATH "Script install directory")
    set(PIHOLE_INSTALL_LOGDIR "${CMAKE_INSTALL_LOCALSTATEDIR}/log/pihole" CACHE PATH "Log directory")
    set(PIHOLE_INSTALL_RUNDIR "${CMAKE_INSTALL_RUNSTATEDIR}" CACHE PATH "Runtime directory")
endif()

# XXX maybe a gap, maybe not. But we need it for dealing with several other packages variable state
if(NOT DEFINED CMAKE_INSTALL_LIBSTATEDIR)
    set(CMAKE_INSTALL_LIBSTATEDIR "${CMAKE_INSTALL_LOCALSTATEDIR}/lib" CACHE PATH "Variable state information")
endif()

set(PIHOLE_INSTALL_LIBSTATEDIR "${CMAKE_INSTALL_LIBSTATEDIR}/pihole" CACHE PATH "Variable state information")
set(PIHOLE_INSTALL_SYSCONFDIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/pihole" CACHE PATH "Config directory")

# Absolute path variants for use in configuration files (systemd units, shell scripts, pkg-config)
# These must be used in configure_file() templates because systemd Exec* directives and
# shell script shebangs require absolute paths at runtime.
# Reference: https://cmake.org/cmake/help/latest/module/GNUInstallDirs.html
# Note: CMAKE_INSTALL_FULL_* variables respect DESTDIR during installation, making them
# safe for packaging systems (Yocto, Debian, RPM). They expand at configure-time with
# the correct prefix, and install(FILES ...) automatically handles DESTDIR staging.
set(PIHOLE_INSTALL_FULL_SCRIPTDIR "${CMAKE_INSTALL_PREFIX}/${PIHOLE_INSTALL_SCRIPTDIR}")
set(PIHOLE_INSTALL_FULL_LOGDIR "${PIHOLE_INSTALL_LOGDIR}")  # Already absolute
set(PIHOLE_INSTALL_FULL_RUNDIR "${PIHOLE_INSTALL_RUNDIR}")  # Already absolute
set(PIHOLE_INSTALL_FULL_LIBSTATEDIR "${PIHOLE_INSTALL_LIBSTATEDIR}")  # Already absolute

message(STATUS "Installation paths (CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}):")
message(STATUS "  Binaries: ${CMAKE_INSTALL_BINDIR} (${CMAKE_INSTALL_FULL_BINDIR})")
message(STATUS "  Scripts:  ${PIHOLE_INSTALL_SCRIPTDIR} (${PIHOLE_INSTALL_FULL_SCRIPTDIR})")
message(STATUS "  Config:   ${PIHOLE_INSTALL_SYSCONFDIR}")
message(STATUS "  Logs:     ${PIHOLE_INSTALL_LOGDIR}")
message(STATUS "  Run:      ${PIHOLE_INSTALL_RUNDIR}")

# Optional: Make systemd installation optional
option(INSTALL_SYSTEMD "Install systemd service unit" ON)

# TODO: Add CMake Config File or pkg-config

add_subdirectory(src)
add_subdirectory(maint)
