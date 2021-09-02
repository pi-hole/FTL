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

# Kill possibly running pihole-FTL process
while pidof -s pihole-FTL > /dev/null; do
  pid="$(pidof -s pihole-FTL)"
  echo "Terminating running pihole-FTL process with PID ${pid}"
  kill $pid
  sleep 1
done

# Clean up possible old files from earlier test runs
rm -f /etc/pihole/gravity.db /etc/pihole/pihole-FTL.db /var/log/pihole.log /var/log/pihole-FTL.log /dev/shm/FTL-*

# Create necessary directories and files
mkdir -p /home/pihole /etc/pihole /run/pihole /var/log
touch /var/log/pihole-FTL.log /var/log/pihole.log /run/pihole-FTL.pid /run/pihole-FTL.port
chown pihole:pihole /etc/pihole /run/pihole /var/log/pihole.log /var/log/pihole-FTL.log /run/pihole-FTL.pid /run/pihole-FTL.port

# Copy binary into a location the new user pihole can access
cp ./pihole-FTL /home/pihole/pihole-FTL
chmod +x /home/pihole/pihole-FTL
# Note: We cannot add CAP_NET_RAW and CAP_NET_ADMIN at this point
setcap CAP_NET_BIND_SERVICE+eip /home/pihole/pihole-FTL

# Prepare gravity database
sqlite3 /etc/pihole/gravity.db < test/gravity.db.sql
chown pihole:pihole /etc/pihole/gravity.db

# Prepare pihole-FTL database
rm -rf /etc/pihole/pihole-FTL.db
sqlite3 /etc/pihole/pihole-FTL.db < test/pihole-FTL.db.sql
chown pihole:pihole /etc/pihole/pihole-FTL.db

# Prepare setupVars.conf
echo "BLOCKING_ENABLED=true" > /etc/pihole/setupVars.conf

# Prepare pihole-FTL.conf
echo -e "DEBUG_ALL=true\nRESOLVE_IPV4=no\nRESOLVE_IPV6=no" > /etc/pihole/pihole-FTL.conf

# Prepare dnsmasq.conf
# We hard-code OpenDNS as resolver (8.8.8.8 doesn't resolve HTTPS/SVCB,
# 1.1.1.1 doesn't implement ANY, 9.9.9.9 doesn't implement RRSIG)
echo -e "log-queries=extra\nlog-facility=/var/log/pihole.log\nserver=84.200.69.80\nno-resolv" > /etc/dnsmasq.conf

# Set restrictive umask
OLDUMASK=$(umask)
umask 0022

# Prepare LUA scripts
mkdir -p /opt/pihole/libs
wget -O /opt/pihole/libs/inspect.lua https://ftl.pi-hole.net/libraries/inspect.lua

# Terminate running FTL instance (if any)
if pidof pihole-FTL &> /dev/null; then
  echo "Terminating running pihole-FTL instance"
  killall pihole-FTL
  sleep 2
fi

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

# Print content of pihole.log and pihole-FTL.log
#cat /var/log/pihole.log
#cat /var/log/pihole-FTL.log

# Run tests
test/libs/bats/bin/bats "test/test_suite.bats"
RET=$?

curl_to_tricorder() {
  curl --silent --upload-file "${1}" https://tricorder.pi-hole.net
}

if [[ $RET != 0 ]]; then
  echo -n "pihole.log: "
  curl_to_tricorder /var/log/pihole.log
  echo ""
  echo -n "pihole-FTL.log: "
  curl_to_tricorder /var/log/pihole-FTL.log
  echo ""
  echo -n "dig.log: "
  curl_to_tricorder ./dig.log
  echo ""
fi

# Kill pihole-FTL after having completed tests
kill $(pidof pihole-FTL)

# Restore umask
umask $OLDUMASK

# Remove copied file
rm /home/pihole/pihole-FTL

# Exit with return code of bats tests
exit $RET
