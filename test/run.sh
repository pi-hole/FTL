#!/bin/bash

# Only run tests on x86_64 target
if [[ "${1}" != "pihole-FTL-linux-x86_64" ]]; then
  exit 0
fi

# Install necessary additional components for testing
apt -qq install dnsutils -y > /dev/null

# Create necessary directories
mkdir -p /etc/pihole /var/run/pihole /var/log

# Download prepared gravity database
wget https://ftl.pi-hole.net/gravity.db
mv gravity.db /etc/pihole/gravity.db

# Prepare setupVars.conf
echo "BLOCKING_ENABLED=true" > /etc/pihole/setupVars.conf

# Prepare pihole-FTL.conf
echo "" > /etc/pihole/pihole-FTL.conf

# Start FTL
./pihole-FTL-linux-x86_64

# Prepare BATS
mkdir -p test/libs
git submodule add https://github.com/sstephenson/bats test/libs/bats
git submodule add https://github.com/ztombol/bats-support test/libs/bats-support
# git submodule add https://github.com/ztombol/bats-assert test/libs/bats-assert

# Block until FTL is ready, retry once per second for 45 seconds
sleep 2

# Print versions of pihole-FTL
echo -n "FTL version: "
dig TXT CHAOS version.FTL @127.0.0.1 +short
echo -n "Contained dnsmasq version: "
dig TXT CHAOS version.bind @127.0.0.1 +short

# Print content of pihole-FTL.log
cat /var/log/pihole-FTL.log

# Run tests
#test/libs/bats/bin/bats "test/test_suite.sh"
exit $?
