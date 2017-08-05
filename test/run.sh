#!/bin/bash

dnsmasq_pre() {
  echo -n $(date +"%b %e %H:%M:%S")
  echo -n "dnsmasq[123]:"
}

# Prepare FTL's files
ts="$(dnsmasq_pre)"
cat <<EOT >> pihole.log
${ts} query[AAAA] raspberrypi from 127.0.0.1
${ts} /etc/pihole/local.list raspberrypi is fda2:2001:5647:0:ba27:ebff:fe37:4205
${ts} query[A] checkip.dyndns.org from 127.0.0.1
${ts} forwarded checkip.dyndns.org to 2001:1608:10:25::9249:d69b
${ts} forwarded checkip.dyndns.org to 2001:1608:10:25::1c04:b12f
${ts} forwarded checkip.dyndns.org to 2620:0:ccd::2
${ts} forwarded checkip.dyndns.org to 2620:0:ccc::2
${ts} reply checkip.dyndns.org is <CNAME>
${ts} reply checkip.dyndns.com is 216.146.38.70
${ts} reply checkip.dyndns.com is 216.146.43.71
${ts} reply checkip.dyndns.com is 91.198.22.70
${ts} reply checkip.dyndns.com is 216.146.43.70
${ts} query[A] pi.hole from 10.8.0.2
${ts} /etc/pihole/local.list pi.hole is 192.168.2.10
${ts} query[A] example.com from 10.8.0.2
${ts} /etc/pihole/local.list example.com is 192.168.2.10
${ts} query[A] play.google.com from 192.168.2.208
${ts} forwarded play.google.com to 2001:1608:10:25::9249:d69b
${ts} forwarded play.google.com to 2001:1608:10:25::1c04:b12f
${ts} forwarded play.google.com to 2620:0:ccd::2
${ts} forwarded play.google.com to 2620:0:ccc::2
${ts} reply play.google.com is <CNAME>
${ts} reply play.l.google.com is 216.58.208.110
${ts} reply play.l.google.com is 216.58.208.110
${ts} reply play.l.google.com is 216.58.208.110
${ts} reply play.google.com is <CNAME>
${ts} query[AAAA] play.google.com from 192.168.2.208
${ts} forwarded play.google.com to 2620:0:ccd::2
${ts} reply play.l.google.com is 2a00:1450:4017:802::200e
${ts} query[A] blacklisted.com from 192.168.2.208
${ts} /etc/pihole/black.list blacklisted.com is 1.2.3.4
${ts} query[A] addomain.com from 192.168.2.208
${ts} /etc/pihole/gravity.list addomain.com is 1.2.3.4
EOT
touch "pihole-FTL.log"

# Start FTL
./pihole-FTL travis-ci

# Prepare BATS
mkdir -p test/libs
git submodule add https://github.com/sstephenson/bats test/libs/bats
git submodule add https://github.com/ztombol/bats-support test/libs/bats-support
# git submodule add https://github.com/ztombol/bats-assert test/libs/bats-assert

# Block until FTL is ready, retry once per second for 45 seconds
n=0
until [ $n -ge 45 ]; do
  nc -vv -z -w 30 127.0.0.1 4711 && break
  n=$[$n+1]
  sleep 1
done

# Print content of pihole-FTL.log
cat pihole-FTL.log

# Run tests
test/libs/bats/bin/bats "test/test_suite.sh"
exit $?
