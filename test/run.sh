#!/bin/bash

dnsmasq_pre() {
  echo -n $(date +"%b %e %H:%M:%S")
  echo -n "dnsmasq[123]:"
}

# Prepare FTL's files
ts="$(dnsmasq_pre)"
cat <<EOT >> pihole.log
${ts} 1 1270.0.01/1234 query[AAAA] raspberrypi from 127.0.0.1
${ts} 1 1270.0.01/1234 /etc/pihole/local.list raspberrypi is fda2:2001:5647:0:ba27:ebff:fe37:4205
${ts} 2 1270.0.01/1234 query[A] ChEcKiP.DyNdNs.OrG from 127.0.0.1
${ts} 2 1270.0.01/1234 forwarded ChEcKiP.DyNdNs.OrG to 2001:1608:10:25::9249:d69b
${ts} 2 1270.0.01/1234 forwarded ChEcKiP.DyNdNs.OrG to 2001:1608:10:25::1c04:b12f
${ts} 2 1270.0.01/1234 forwarded ChEcKiP.DyNdNs.OrG to 2620:0:ccd::2
${ts} 2 1270.0.01/1234 forwarded ChEcKiP.DyNdNs.OrG to 2620:0:ccc::2
${ts} 2 1270.0.01/1234 reply ChEcKiP.DyNdNs.OrG is <CNAME>
${ts} 2 1270.0.01/1234 reply ChEcKiP.DyNdNs.OrG is 216.146.38.70
${ts} 2 1270.0.01/1234 reply ChEcKiP.DyNdNs.OrG is 216.146.43.71
${ts} 2 1270.0.01/1234 reply ChEcKiP.DyNdNs.OrG is 91.198.22.70
${ts} 2 1270.0.01/1234 reply ChEcKiP.DyNdNs.OrG is 216.146.43.70
${ts} 3 1270.0.01/1234 query[A] pi.hole from 10.8.0.2
${ts} 3 1270.0.01/1234 /etc/pihole/local.list pi.hole is 192.168.2.10
${ts} 4 1270.0.01/1234 query[A] example.com from 10.8.0.2
${ts} 4 1270.0.01/1234 /etc/pihole/local.list example.com is 192.168.2.10
${ts} 5 1270.0.01/1234 query[A] play.google.com from 192.168.2.208
${ts} 5 1270.0.01/1234 forwarded play.google.com to 2001:1608:10:25::9249:d69b
${ts} 5 1270.0.01/1234 forwarded play.google.com to 2001:1608:10:25::1c04:b12f
${ts} 5 1270.0.01/1234 forwarded play.google.com to 2620:0:ccd::2
${ts} 5 1270.0.01/1234 forwarded play.google.com to 2620:0:ccc::2
${ts} 5 1270.0.01/1234 reply play.google.com is <CNAME>
${ts} 5 1270.0.01/1234 reply play.l.google.com is 216.58.208.110
${ts} 5 1270.0.01/1234 reply play.l.google.com is 216.58.208.110
${ts} 5 1270.0.01/1234 reply play.l.google.com is 216.58.208.110
${ts} 5 1270.0.01/1234 reply play.google.com is <CNAME>
${ts} 6 1270.0.01/1234 query[AAAA] play.google.com from 192.168.2.208
${ts} 6 1270.0.01/1234 forwarded play.google.com to 2620:0:ccd::2
${ts} 6 1270.0.01/1234 reply play.l.google.com is 2a00:1450:4017:802::200e
${ts} 7 1270.0.01/1234 query[A] blacklisted.com from 192.168.2.208
${ts} 7 1270.0.01/1234 /etc/pihole/black.list blacklisted.com is 1.2.3.4
${ts} 8 1270.0.01/1234 query[A] addomain.com from 192.168.2.208
${ts} 8 1270.0.01/1234 /etc/pihole/gravity.list addomain.com is 1.2.3.4
EOT
touch "pihole-FTL.log"

cat <<EOT >> pihole-FTL.conf
DBFILE=pihole-FTL.db
LOGFILE=pihole-FTL.log
SOCKETFILE=pihole-FTL.sock
EOT

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
  echo "..."
  tail -n2 pihole-FTL.log
  echo "..."
  sleep 1
done

# Print content of pihole-FTL.log
cat pihole-FTL.log

# Run tests
test/libs/bats/bin/bats "test/test_suite.sh"
exit $?
