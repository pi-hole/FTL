#!/bin/bash

# Skip tests on targets not supporting them
if [[ ${TEST} == "false" ]]; then
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
  kill "$pid"
  sleep 1
done

# Clean up possible old files from earlier test runs
rm -rf /etc/pihole /var/log/pihole /dev/shm/FTL-*

# Create necessary directories and files
mkdir -p /home/pihole /etc/pihole /run/pihole /var/log/pihole
echo "" > /var/log/pihole/FTL.log
echo "" > /var/log/pihole/pihole.log
touch /run/pihole-FTL.pid /run/pihole-FTL.port dig.log ptr.log
touch /var/log/pihole/HTTP_info.log /var/log/pihole/PH7.log /etc/pihole/dhcp.leases
chown pihole:pihole /etc/pihole /run/pihole /var/log/pihole/pihole.log /var/log/pihole/FTL.log /run/pihole-FTL.pid /run/pihole-FTL.port
chown pihole:pihole /var/log/pihole/HTTP_info.log /var/log/pihole/PH7.log /etc/pihole/dhcp.leases

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

# Prepare TLS key and certificate
cp test/test.pem /etc/pihole/test.pem
cp test/test.crt /etc/pihole/test.crt

# Prepare pihole.toml
cp test/pihole.toml /etc/pihole/pihole.toml
chown pihole:pihole /etc/pihole/pihole.toml

# Prepare 01-pihole-tests.conf
mkdir /etc/dnsmasq.d
cp test/01-pihole-tests.conf /etc/dnsmasq.d/01-pihole-tests.conf

# Prepare versions file (read by /api/version)
cp test/versions /etc/pihole/versions

# Prepare local powerDNS resolver
bash test/pdns/setup.sh

# Set restrictive umask
OLDUMASK=$(umask)
umask 0022

# Set exemplary config value by environment variable
export FTLCONF_misc_nice="-11"
export FTLCONF_dns_upstrrr="-11"
export FTLCONF_debug_api="not_a_bool"

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
  echo ""
  echo -n "HTTP_info.log: "
  curl_to_tricorder /var/log/pihole/HTTP_info.log
  echo ""
  echo -n "PH7.log: "
  curl_to_tricorder /var/log/pihole/PH7.log
  echo ""
  echo -n "pihole.toml: "
  curl_to_tricorder /etc/pihole/pihole.toml
  echo ""
fi

# Kill pihole-FTL after having completed tests
kill "$(pidof pihole-FTL)"

# Restore umask
umask "$OLDUMASK"

# Run performance tests
if ! su pihole -s /bin/sh -c "/home/pihole/pihole-FTL --perf"; then
  echo "pihole-FTL --perf failed to start"
fi

# Remove copied file
rm /home/pihole/pihole-FTL

# Stop local powerDNS resolver
killall pdns_server
killall pdns_recursor

# Exit with return code of bats tests
exit $RET
