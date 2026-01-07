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

# Determine project version from git tags by including gen_version.cmake
# This avoids code duplication - the tag detection logic is centralized in gen_version.cmake
set(GEN_VERSION_CONFIGURE_MODE TRUE)
include(${CMAKE_SOURCE_DIR}/src/gen_version.cmake)

project(PIHOLE_FTL VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH} LANGUAGES C)

message(STATUS "Project version: ${PROJECT_VERSION} (from git tag: ${GIT_TAG})")

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
set(PIHOLE_INSTALL_FULL_LOGDIR "${PIHOLE_INSTALL_LOGDIR}") # Already absolute
set(PIHOLE_INSTALL_FULL_RUNDIR "${PIHOLE_INSTALL_RUNDIR}") # Already absolute
set(PIHOLE_INSTALL_FULL_LIBSTATEDIR "${PIHOLE_INSTALL_LIBSTATEDIR}") # Already absolute

message(STATUS "Installation paths (CMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}):")
message(STATUS "  Binaries: ${CMAKE_INSTALL_BINDIR} (${CMAKE_INSTALL_FULL_BINDIR})")
message(STATUS "  Scripts:  ${PIHOLE_INSTALL_SCRIPTDIR} (${PIHOLE_INSTALL_FULL_SCRIPTDIR})")
message(STATUS "  Config:   ${PIHOLE_INSTALL_SYSCONFDIR}")
message(STATUS "  Logs:     ${PIHOLE_INSTALL_LOGDIR}")
message(STATUS "  Run:      ${PIHOLE_INSTALL_RUNDIR}")

# Optional: Make systemd installation optional
option(INSTALL_SYSTEMD "Install systemd service unit" ON)

# Generate version.c from git information
# This is done at build time to ensure version info is always up-to-date
add_custom_target(
        gen_version
        ALL
        COMMAND ${CMAKE_COMMAND} -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER} -P ${CMAKE_SOURCE_DIR}/src/gen_version.cmake
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
        BYPRODUCTS ${CMAKE_SOURCE_DIR}/src/version.c
        COMMENT "Generating version.c using gen_version.cmake"
)

add_subdirectory(src)
add_subdirectory(maint)

# ============================================================================
# CMake Config and pkg-config File Generation
# ============================================================================
include(CMakePackageConfigHelpers)

# Prepare variables for config files
# Note: SYSTEMD_UNIT_DIR is set in maint/systemd/CMakeLists.txt
# We need to defer its evaluation or set a default here
if(NOT DEFINED SYSTEMD_UNIT_DIR)
        if(CMAKE_INSTALL_PREFIX MATCHES "^/opt/")
                set(SYSTEMD_UNIT_DIR "${CMAKE_INSTALL_SYSCONFDIR}/systemd/system")
        else()
                set(SYSTEMD_UNIT_DIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system")
        endif()
endif()

set(PIHOLE_FTL_BINARY "${CMAKE_INSTALL_BINDIR}/pihole-FTL")
set(PIHOLE_FTL_SCRIPTS_DIR "${PIHOLE_INSTALL_SCRIPTDIR}")
set(PIHOLE_FTL_SYSTEMD_UNIT_DIR "${SYSTEMD_UNIT_DIR}")

# Generate CMake Config File
configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/PiholeFTLConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/PiholeFTLConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PiholeFTL
        PATH_VARS PIHOLE_FTL_BINARY PIHOLE_FTL_SCRIPTS_DIR PIHOLE_FTL_SYSTEMD_UNIT_DIR
)

# Generate CMake Config Version File
write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/PiholeFTLConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
)

# Generate pkg-config File
# Note: Uses CMAKE_INSTALL_FULL_* variables for absolute paths, required by pkg-config spec
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pihole-ftl.pc.in ${CMAKE_CURRENT_BINARY_DIR}/pihole-ftl.pc @ONLY)

# Install CMake Config Files
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/PiholeFTLConfig.cmake ${CMAKE_CURRENT_BINARY_DIR}/PiholeFTLConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PiholeFTL
        COMPONENT development
)

# Install pkg-config File
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pihole-ftl.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
        COMPONENT development
)

message(STATUS "Config files will be installed:")
message(STATUS "  CMake:      ${CMAKE_INSTALL_LIBDIR}/cmake/PiholeFTL/")
message(STATUS "  pkg-config: ${CMAKE_INSTALL_LIBDIR}/pkgconfig/pihole-ftl.pc")
