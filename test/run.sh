#!/bin/bash

# Only run tests on x86_64, x86_64-musl, and x86_32 targets
if [[ ${CI} == "true" && "${CI_ARCH}" != "x86_64" &&  "${CI_ARCH}" != "x86_64-musl" && "${CI_ARCH}" != "x86_32" ]]; then
  echo "Skipping tests (CI_ARCH: ${CI_ARCH})!"
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
rm -f /etc/pihole/gravity.db /etc/pihole/pihole-FTL.db /var/log/pihole/pihole.log /var/log/pihole/FTL.log /dev/shm/FTL-*

# Create necessary directories and files
mkdir -p /home/pihole /etc/pihole /run/pihole /var/log/pihole
echo "" > /var/log/pihole/FTL.log
echo "" > /var/log/pihole/pihole.log
touch /run/pihole-FTL.pid /run/pihole-FTL.port dig.log ptr.log
chown pihole:pihole /etc/pihole /run/pihole /var/log/pihole/pihole.log /var/log/pihole/FTL.log /run/pihole-FTL.pid /run/pihole-FTL.port

# Copy binary into a location the new user pihole can access
cp ./pihole-FTL /home/pihole/pihole-FTL
chmod +x /home/pihole/pihole-FTL
# Note: We cannot add CAP_NET_RAW and CAP_NET_ADMIN at this point
setcap CAP_NET_BIND_SERVICE+eip /home/pihole/pihole-FTL

# Prepare gravity database
./pihole-FTL sqlite3 /etc/pihole/gravity.db < test/gravity.db.sql
chown pihole:pihole /etc/pihole/gravity.db

# Prepare pihole-FTL database
rm -rf /etc/pihole/pihole-FTL.db
./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db < test/pihole-FTL.db.sql
chown pihole:pihole /etc/pihole/pihole-FTL.db

# Prepare setupVars.conf
echo "BLOCKING_ENABLED=true" > /etc/pihole/setupVars.conf

# Prepare pihole-FTL.conf
cp test/pihole-FTL.conf /etc/pihole/pihole-FTL.conf

# Prepare dnsmasq.conf
cp test/dnsmasq.conf /etc/dnsmasq.conf

# Prepare local powerDNS resolver
bash test/pdns/setup.sh

# Set restrictive umask
OLDUMASK=$(umask)
umask 0022

# Prepare LUA scripts
mkdir -p /opt/pihole/libs
wget -O /opt/pihole/libs/inspect.lua https://ftl.pi-hole.net/libraries/inspect.lua

# Start FTL
if ! su pihole -s /bin/sh -c /home/pihole/pihole-FTL; then
  echo "pihole-FTL failed to start"
  exit 1
fi

# Prepare BATS
if [ -z "$BATS" ]; then
  mkdir -p test/libs
  git clone --depth=1 --quiet https://github.com/bats-core/bats-core test/libs/bats > /dev/null
  BATS=test/libs/bats/bin/bats
fi

# Give FTL some time for startup preparations
sleep 2

# Print versions of pihole-FTL
echo -n "FTL version (DNS): "
dig TXT CHAOS version.FTL @127.0.0.1 +short
echo "FTL verbose version (CLI): "
/home/pihole/pihole-FTL -vv
echo -n "Contained dnsmasq version (DNS): "
dig TXT CHAOS version.bind @127.0.0.1 +short

# Run tests
$BATS "test/test_suite.bats"
RET=$?

curl_to_tricorder() {
  curl --silent --upload-file "${1}" https://tricorder.pi-hole.net
}

if [[ $RET != 0 ]]; then
  echo -n "pihole/pihole.log: "
  curl_to_tricorder /var/log/pihole/pihole.log
  echo ""
  echo -n "pihole/FTL.log: "
  curl_to_tricorder /var/log/pihole/FTL.log
  echo ""
  echo -n "dig.log: "
  curl_to_tricorder ./dig.log
  echo ""
  echo -n "ptr.log: "
  curl_to_tricorder ./ptr.log
  echo ""getallqueries
  echo -n "getallqueries.log: "
  curl_to_tricorder ./getallqueries.log
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
