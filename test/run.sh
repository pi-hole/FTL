#!/bin/bash

binary="${1}"

# Only run tests on x86_64 target
if [[ ${CI} && "${binary}" != "pihole-FTL-linux-x86_64" ]]; then
  echo "Skipping tests (${1})!"
  exit 0
fi

# Install necessary additional components for testing
apt-get -qq install dnsutils -y > /dev/null

# Create necessary directories
mkdir -p /etc/pihole /var/run/pihole /var/log

# Prepare gravity database
sqlite3 /etc/pihole/gravity.db < test/gravity.db.schema

# Prepare setupVars.conf
echo "BLOCKING_ENABLED=true" > /etc/pihole/setupVars.conf

# Prepare pihole-FTL.conf
echo "" > /etc/pihole/pihole-FTL.conf

# Start FTL
if ! ./${binary}; then
  echo "Pihole-FTL failed to start"
  exit 1
fi

# Prepare BATS
mkdir -p test/libs
git clone --depth=1 https://github.com/sstephenson/bats test/libs/bats > /dev/null
git clone --depth=1 https://github.com/ztombol/bats-support test/libs/bats-support > /dev/null

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
test/libs/bats/bin/bats "test/test_suite.sh"
exit $?
