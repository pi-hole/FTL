#!/bin/bash

# Only run tests on x86_64 target
if [[ "${1}" != "pihole-FTL-linux-x86_64" ]]; then
  exit 0
fi

# Install necessary additional components for testing
apt install dns-utils

# Create necessary directories
mkdir -p /etc/pihole /var/run/pihole /var/log

# Start FTL
./pihole-FTL

# Prepare BATS
mkdir -p test/libs
git submodule add https://github.com/sstephenson/bats test/libs/bats
git submodule add https://github.com/ztombol/bats-support test/libs/bats-support
# git submodule add https://github.com/ztombol/bats-assert test/libs/bats-assert

# Block until FTL is ready, retry once per second for 45 seconds
sleep 2

# Print content of pihole-FTL.log
cat /var/log/pihole-FTL.log

# Run tests
#test/libs/bats/bin/bats "test/test_suite.sh"
exit $?
