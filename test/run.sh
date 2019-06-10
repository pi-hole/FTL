#!/bin/bash

# Only run tests on x86_64 target
if [[ ${CI} == "true" && "${CIRCLE_JOB}" != "x86_64" ]]; then
  echo "Skipping tests (CIRCLE_JOB: ${CIRCLE_JOB})!"
  exit 0
fi

# Install necessary additional components for testing
apt-get -qq install dnsutils -y > /dev/null

# Create necessary directories
mkdir -p /etc/pihole /var/run/pihole /var/log

# Prepare gravity database
sqlite3 /etc/pihole/gravity.db < test/gravity.db.sql

# Prepare setupVars.conf
echo "BLOCKING_ENABLED=true" > /etc/pihole/setupVars.conf

# Prepare pihole-FTL.conf
echo "" > /etc/pihole/pihole-FTL.conf

# Set restrictive umask
OLDUMASK=$(umask)
umask 0022

# Start FTL
if ! ./pihole-FTL; then
  echo "pihole-FTL failed to start"
  exit 1
fi

# Prepare BATS
mkdir -p test/libs
git clone --depth=1 https://github.com/bats-core/bats-core test/libs/bats > /dev/null

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
test/libs/bats/bin/bats "test/test_suite.bats"
RET=$?

# Restore umask
umask $OLDUMASK

# Exit with return code of bats tests
exit $RET
