#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Build script for FTL
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

# Abort script if one command returns a non-zero value
set -e

# Set builddir
builddir="cmake/"

# Parse arguments
# If the first argument starts in "-D", we pass it to CMake
if [[ "${1}" == "-D"* ]]; then
    cmake_args="${1}"
    shift
fi

# Parse the remaining arguments
for var in "$@"
do
    case "${var}" in
        "clean"          ) clean=1;;
        "nobuild"        ) nobuild=1;;
        "install"        ) install=1;;
        "restart"        ) restart=1;;
        "tail"           ) tail=1;;
        "debug"          ) debug=1;;
        "dev"            ) dev=1;;
        "test"           ) test=1;;
        "clean-logs"     ) clean_logs=1;;
        "clang"          ) clang=1;;
        "ci"             ) builddir="cmake_ci/";;
        "-h"  | "help"   ) help=0;;
        *                ) echo -e "Unknown option: ${var}\n"; help=1;;
    esac
done

# Display help text if requested
if [[ -n "${help}" ]]; then
    cat << EOF
Usage: $0 [options]
Helper script simplifying the build process of Pi-hole FTL.

Shortcuts:
  dev                Build, install, restart, and tail logs.
  debug              Build, install, restart, and attach debugger.

Other options:
  clean              Clean the build environment before building.
  nobuild            Do not trigger a build, e.g., after cleaning.
  install            Install the built binaries (requires sudo).
  restart            Restart the pihole-FTL service (requires sudo).
  clean-logs         Clean the FTL and dnsmasq log files.
  tail               Tail (follow) the FTL and dnsmasq log files.
  -h, help           Display this help text.

Special CI options:
  ci                 Use the CI build directory (cmake_ci/).
  clang              Use clang as the compiler.
  test               Run tests after building.

If no options are provided, the script will build the sources.
If the -d option is provided, the script will build, install, restart,
and tail the two most important log file. The -d option is intended
for development purposes.
EOF

    exit "${help}"
fi

# debug, tail and dev are mutually exclusive
if [[ $((debug + tail + dev)) -gt 1 ]]; then
    echo "Error: debug, tail, and dev are mutually exclusive options."
    exit 1
fi

# If we are in debug mode, we also want to build, install, and restart
if [[ -n "${debug}" ]]; then
    install=1
    restart=1
fi

# If we are in dev mode, we want to build, install, restart, and tail the logs
# by default
if [[ -n "${dev}" ]]; then
    install=1
    restart=1
    tail=1
fi

# Check if we need sudo
SUDO=""
if [[ -n "${install}" || -n "${restart}" || -n "${clean_logs}" ]]; then
    # Check if we are root, if not, we need sudo
    if [[ $(id -u) -ne 0 ]]; then
        SUDO="sudo"
    fi
fi

# Prepare build environment
if [[ -n "${clean}" ]]; then
    echo "Cleaning build environment"
    # Remove build directory
    rm -rf "${builddir}"
fi

# Remove possibly outdated api/docs elements
for filename in src/api/docs/hex/* src/api/docs/hex/**/*; do
    # Skip if not a file
    if [ ! -f "${filename}" ]; then
        continue
    fi

    # Get the original filename
    original_filename="${filename/"src/api/docs/hex/"/"src/api/docs/content/"}"

    # Remove the file if it is outdated
    if [ "${filename}" -ot "${original_filename}" ]; then
        rm "${filename}"
    fi
done

# Remove compiled LUA scripts if older than the plain ones
for scriptname in src/lua/scripts/*.lua; do
    if [ -f "${scriptname}.hex" ] && [ "${scriptname}.hex" -ot "${scriptname}" ]; then
        rm "${scriptname}.hex"
    fi
done

# If we are asked to NOT build, we exit here
if [[ -n ${nobuild} ]]; then
    exit 0
fi

# Set compiler to clang if requested
if [[ -n "${clang}" ]]; then
    export CC=clang
    export CXX=clang++
    export STATIC="false"
fi

# Configure build, pass CMake CACHE entries if present
# Wrap multiple options in "" as first argument to ./build.sh:
#     ./build.sh "-DA=1 -DB=2" install
mkdir -p "${builddir}"
cd "${builddir}"
if [[ -n ${cmake_args} ]]; then
    cmake "${cmake_args}" ..
else
    cmake ..
fi

# If MAKEFLAGS is unset, we set it to "-j$(nproc)"
if [[ -z "${MAKEFLAGS}" ]]; then
    MAKEFLAGS="-j$(nproc)"
fi

# Build the sources
cmake --build . -- ${MAKEFLAGS}

# Checksum verification
./pihole-FTL verify

# If we are asked to install, we do this here (requires root privileges)
# Otherwise, we simply copy the binary one level down
if [[ -n "${install}" ]]; then
    echo "Installing pihole-FTL"
    ${SUDO} cmake --install .
else
    echo "Copying compiled pihole-FTL binary to repository root"
    cp pihole-FTL ../
fi

# If we are asked to run tests, we do this here
if [[ -n "${test}" ]]; then
    cd ..
    bash test/run.sh
fi

# If we are asked to restart, we do this here
if [[ -n "${restart}" ]]; then
    echo "Restarting pihole-FTL"

    # First, reset the failure-counter in case a previous error caused a
    # restarting loop now preventing systemd from starting FTL
    ${SUDO} systemctl reset-failed pihole-FTL

    # Restart FTL
    ${SUDO} systemctl restart pihole-FTL
fi

# If we are asked to clean the logs, we do this here
if [[ -n "${clean_logs}" ]]; then
    echo "Cleaning log files"
    for log_file in "$(pihole-FTL --config files.log.ftl)" "$(pihole-FTL --config files.log.dnsmasq)"; do
        echo "Cleaning ${log_file}"
        echo "" | ${SUDO} tee "$log_file"
    done
fi

# If we want to attach the debugger, we do this here
if [[ -n "${debug}" ]]; then
    echo "Waiting for pihole-FTL to start..."
    pid_file=$(pihole-FTL --config files.pid)

    # Loop until the pid file is created and non-empty
    while [ ! -f "${pid_file}" ] || [ ! -s "${pid_file}" ]; do
        sleep 0.1
    done

    # Get the pid from the pid file
    pid=$(cat "${pid_file}")

    # Attach gdb to the process
    echo "Attaching debugger to pihole-FTL (PID: ${pid})..."
    ${SUDO} gdb -p "${pid}"
fi

# If we are asked to tail the log, we do this here
if [[ -n "${tail}" ]]; then

    # Check if tmux is installed
    if ! command -v tmux &> /dev/null; then
        echo "Error: tmux is not installed. Please install tmux to use the tail option."
        exit 1
    fi

    # Get the log file locations
    ftl_log=$(pihole-FTL --config files.log.ftl)
    dnsmasq_log=$(pihole-FTL --config files.log.dnsmasq)

    # Create tmux sub-session with two panes next to each other each running a tail command
    tmux new-session -d "tail -f ${ftl_log}" \; split-window -h "tail -f ${dnsmasq_log}" \; attach
fi
