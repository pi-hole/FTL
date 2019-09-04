#!/bin/bash

# Only run tests on x86_64, x86_64-musl, and x86_32 targets
if [[ ${CI} == "true" && "${CIRCLE_JOB}" != "x86_64" &&  "${CIRCLE_JOB}" != "x86_64-musl" && "${CIRCLE_JOB}" != "x86_32" ]]; then
  echo "Skipping tests (CIRCLE_JOB: ${CIRCLE_JOB})!"
  exit 0
fi

# Create pihole user if it does not exist
if ! id -u pihole &> /dev/null; then
  useradd -m -s /usr/sbin/nologin pihole
fi

# Create necessary directories and files
mkdir -p /etc/pihole /var/run/pihole /var/log
touch /var/log/pihole-FTL.log /var/run/pihole-FTL.pid /var/run/pihole-FTL.port
chown pihole:pihole /etc/pihole /var/run/pihole /var/log/pihole-FTL.log /var/run/pihole-FTL.pid /var/run/pihole-FTL.port

# Copy binary into a location the new user pihole can access
cp ./pihole-FTL /home/pihole
chmod +x /home/pihole/pihole-FTL
# Note: We cannot add CAP_NET_RAW and CAP_NET_ADMIN at this point
setcap CAP_NET_BIND_SERVICE+eip /home/pihole/pihole-FTL

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
if ! su pihole -s /bin/sh -c /home/pihole/pihole-FTL; then
  echo "pihole-FTL failed to start"
  exit 1
fi

# Prepare BATS
mkdir -p test/libs
git clone --depth=1 --quiet https://github.com/bats-core/bats-core test/libs/bats > /dev/null

# Block until FTL is ready, retry once per second for 45 seconds
sleep 2

# Print versions of pihole-FTL
echo -n "FTL version: "
dig TXT CHAOS version.FTL @127.0.0.1 +short
echo -n "Contained dnsmasq version: "
dig TXT CHAOS version.bind @127.0.0.1 +short

# Print content of pihole.log
cat /var/log/pihole.log

# Print content of pihole-FTL.log
cat /var/log/pihole-FTL.log

# Run tests
test/libs/bats/bin/bats "test/test_suite.bats"
RET=$?

# Kill pihole-FTL after having completed tests
kill $(pidof pihole-FTL)

# Restore umask
umask $OLDUMASK

# Remove copied file
rm /home/pihole/pihole-FTL

# Exit with return code of bats tests
exit $RET
