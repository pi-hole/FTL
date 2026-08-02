#!/bin/bash

echo "************ Installing PowerDNS configuration ************"

# Delete possibly existing zone database. Include the WAL/SHM siblings —
# leaving them behind lets SQLite replay stale transactions against the
# freshly created database on the next open.
mkdir -p /var/lib/powerdns/
rm -f /var/lib/powerdns/pdns.sqlite3*

# Install config files
if [ -d /etc/powerdns ]; then
  # Debian
  cp test/pdns/pdns.conf /etc/powerdns/pdns.conf
  RECURSOR_CONF=/etc/powerdns/recursor.conf
elif [ -d /etc/pdns ]; then
  cp test/pdns/pdns.conf /etc/pdns/pdns.conf
  if [ -d /etc/pdns-recursor ]; then
    # Fedora
    RECURSOR_CONF=/etc/pdns-recursor/recursor.conf
  else
    # Alpine
    RECURSOR_CONF=/etc/pdns/recursor.conf
  fi
else
  echo "Error: Unable to determine powerDNS config directory"
  exit 1
fi

cp test/pdns/luadns.lua /etc/pdns/luadns.lua
cp test/pdns/recursor.conf $RECURSOR_CONF

# Create zone database
if [ -f /usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql ]; then
  # Debian
  ./pihole-FTL sqlite3 /var/lib/powerdns/pdns.sqlite3 < /usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql
elif [ -f /usr/share/doc/pdns/schema.sqlite3.sql ]; then
  # Alpine
  ./pihole-FTL sqlite3 /var/lib/powerdns/pdns.sqlite3 < /usr/share/doc/pdns/schema.sqlite3.sql
else
  echo "Error: powerDNS SQL schema not found"
  exit 1
fi
# Create zone ftl
pdnsutil zone create ftl ns1.ftl

# Create A records
pdnsutil rrset add ftl. a.ftl. A 192.168.1.1
pdnsutil rrset add ftl. gravity.ftl. A 192.168.1.2
pdnsutil rrset add ftl. denied.ftl. A 192.168.1.3
pdnsutil rrset add ftl. allowed.ftl. A 192.168.1.4
pdnsutil rrset add ftl. gravity-allowed.ftl. A 192.168.1.5
pdnsutil rrset add ftl. antigravity.ftl. A 192.168.1.6
pdnsutil rrset add ftl. x.y.z.abp.antigravity.ftl. A 192.168.1.7
pdnsutil rrset add ftl. regex1.ftl. A 192.168.2.1
pdnsutil rrset add ftl. regex2.ftl. A 192.168.2.2
pdnsutil rrset add ftl. regex5.ftl. A 192.168.2.3
pdnsutil rrset add ftl. regexA.ftl. A 192.168.2.4
pdnsutil rrset add ftl. regex-REPLYv4.ftl. A 192.168.2.5
pdnsutil rrset add ftl. regex-REPLYv6.ftl. A 192.168.2.6
pdnsutil rrset add ftl. regex-REPLYv46.ftl. A 192.168.2.7
pdnsutil rrset add ftl. regex-A.ftl. A 192.168.2.8
pdnsutil rrset add ftl. regex-notA.ftl. A 192.168.2.9
pdnsutil rrset add ftl. any.ftl. A 192.168.3.1

# Create AAAA records
pdnsutil rrset add ftl. aaaa.ftl. AAAA fe80::1c01
pdnsutil rrset add ftl. regex-REPLYv4.ftl. AAAA fe80::2c01
pdnsutil rrset add ftl. regex-REPLYv6.ftl. AAAA fe80::2c02
pdnsutil rrset add ftl. regex-REPLYv46.ftl. AAAA fe80::2c03
pdnsutil rrset add ftl. any.ftl. AAAA fe80::3c01
pdnsutil rrset add ftl. gravity-aaaa.ftl. AAAA fe80::4c01

# Create CNAME records
pdnsutil rrset add ftl. cname-1.ftl. CNAME gravity.ftl.
pdnsutil rrset add ftl. cname-2.ftl. CNAME cname-1.ftl.
pdnsutil rrset add ftl. cname-3.ftl. CNAME cname-2.ftl.
pdnsutil rrset add ftl. cname-4.ftl. CNAME cname-3.ftl.
pdnsutil rrset add ftl. cname-5.ftl. CNAME cname-4.ftl.
pdnsutil rrset add ftl. cname-6.ftl. CNAME cname-5.ftl.
pdnsutil rrset add ftl. cname-7.ftl. CNAME cname-6.ftl.
pdnsutil rrset add ftl. cname-ok.ftl. CNAME a.ftl.

# Create CNAME for SOA test domain
pdnsutil rrset add ftl. soa.ftl. CNAME ftl.

# Create CNAME for NODATA tests
pdnsutil rrset add ftl. aaaa-cname.ftl. CNAME gravity-aaaa.ftl.
pdnsutil rrset add ftl. a-cname.ftl. CNAME gravity.ftl.

# Create PTR records
pdnsutil rrset add ftl. ptr.ftl. PTR ptr.ftl.

# Other testing records
pdnsutil rrset add ftl. srv.ftl. SRV "0 1 80 a.ftl"
pdnsutil rrset add ftl. txt.ftl. TXT "\"Some example text\""
# We want this to output $1 without expansion
# shellcheck disable=SC2016
pdnsutil rrset add ftl. naptr.ftl. NAPTR '10 10 "u" "smtp+E2U" "!.*([^\.]+[^\.]+)$!mailto:postmaster@$1!i" .'
pdnsutil rrset add ftl. naptr.ftl. NAPTR '20 10 "s" "http+N2L+N2C+N2R" "" ftl.'
pdnsutil rrset add ftl. mx.ftl. MX "50 ns1.ftl."

# SVCB + HTTPS
pdnsutil rrset add ftl. svcb.ftl. SVCB '1 port="80"'
pdnsutil rrset add ftl. regex-multiple.ftl. SVCB '1 port="80"'
pdnsutil rrset add ftl. regex-notMultiple.ftl. SVCB '1 port="80"'

# HTTPS
pdnsutil rrset add ftl. https.ftl. HTTPS '1 . alpn="h3,h2"'
pdnsutil rrset add ftl. regex-multiple.ftl. HTTPS '1 . alpn="h3,h2"'
pdnsutil rrset add ftl. regex-notMultiple.ftl. HTTPS '1 . alpn="h3,h2"'

# ANY
pdnsutil rrset add ftl. regex-multiple.ftl. A 192.168.3.12
pdnsutil rrset add ftl. regex-multiple.ftl. AAAA fe80::3f41
pdnsutil rrset add ftl. regex-notMultiple.ftl. A 192.168.3.12
pdnsutil rrset add ftl. regex-notMultiple.ftl. AAAA fe80::3f41

# TXT
pdnsutil rrset add ftl. any.ftl. TXT "\"Some example text\""

# NOERROR: Create a record that returns NOERROR but no data
pdnsutil rrset add ftl. noerror.ftl. NS ns1.ftl.

# Blocked Cisco Umbrella IP (https://support.opendns.com/hc/en-us/articles/227986927-What-are-the-Cisco-Umbrella-Block-Page-IP-Addresses)
pdnsutil rrset add ftl. umbrella.ftl. A 146.112.61.104
pdnsutil rrset add ftl. umbrella.ftl. AAAA ::ffff:9270:3d68 #::ffff:146.112.61.104

# Special record which consists of both blocked and non-blocked IP
pdnsutil rrset add ftl. umbrella-multi.ftl. A 1.2.3.4
pdnsutil rrset add ftl. umbrella-multi.ftl. A 146.112.61.104
pdnsutil rrset add ftl. umbrella-multi.ftl. A 8.8.8.8

# Null address
pdnsutil rrset add ftl. null.ftl. A 0.0.0.0
pdnsutil rrset add ftl. null.ftl. AAAA ::

# Serve Apple's iCloud Private Relay domains locally (unsigned) instead of
# recursing to the public internet. The bats suite resolves mask.icloud.com
# through an allowlisted client; hosting the mask.icloud.com -> mask.apple-dns.net
# CNAME chain here keeps the query counts deterministic regardless of whether
# Apple currently DNSSEC-signs these zones (see test/api/test_api.py).
pdnsutil zone create icloud.com ns1.ftl
pdnsutil rrset add icloud.com. mask.icloud.com. CNAME mask.apple-dns.net.
pdnsutil rrset add icloud.com. mask-h2.icloud.com. CNAME mask.apple-dns.net.
pdnsutil zone create apple-dns.net ns1.ftl
pdnsutil rrset add apple-dns.net. mask.apple-dns.net. A 172.224.181.14

# Create valid internal DNSSEC zone
pdnsutil zone create dnssec ns1.ftl
pdnsutil rrset add dnssec. a.dnssec. A 192.168.4.1
pdnsutil rrset add dnssec. aaaa.dnssec. AAAA fe80::4c01
pdnsutil zone secure dnssec
# Export zone DS records and convert to dnsmasq trust-anchor format
# Example:
#   dnssec. IN DS 42206 8 2 6d2007e292483fa061db37011676d9592649d1600e5b2ece1326f792ebedd412 ; ( SHA256 digest )
# --->
#   trust-anchor=dnssec.,42206,8,2,6d2007e292483fa061db37011676d9592649d1600e5b2ece1326f792ebedd412
pdnsutil zone export-ds dnssec. | head -n1 | awk '{FS=" "; OFS=""; print "trust-anchor=",$1,",",$4,",",$5,",",$6,",",$7}' > /etc/dnsmasq.d/02-trust-anchor.conf

# Create a locally-signed root zone so DNSSEC validation never leaves the test
# environment. FTL ships the real ICANN root trust anchors, so without a local
# root dnsmasq would fetch the live root DNSKEY (whose key set drifts with ICANN
# rollovers). Serving a signed root here and trusting its key keeps it hermetic.
pdnsutil zone create . ns1.
pdnsutil zone secure .
pdnsutil zone export-ds . | head -n1 | awk '{FS=" "; OFS=""; print "trust-anchor=",$1,",",$4,",",$5,",",$6,",",$7}' >> /etc/dnsmasq.d/02-trust-anchor.conf

# Create intentionally broken DNSSEC (BOGUS) zone
# The only difference to above is that this zone is signed with a key that is
# not in the trust chain
# It will cause the DNSSEC validation to fail with error message:
#   unsupported DS digest
pdnsutil zone create bogus ns1.ftl
pdnsutil rrset add bogus. a.bogus. A 192.168.5.1
pdnsutil rrset add bogus. aaaa.bogus. AAAA fe80::5c01
pdnsutil zone secure bogus
# Install a *deliberately mismatched* trust anchor for the bogus zone (same
# keytag/algorithm/digest-type as the real key, but a corrupted digest). This
# makes bogus validation fail as BOGUS *locally* instead of dnsmasq walking up
# to the real ICANN root to learn the zone has no secure delegation.
pdnsutil zone export-ds bogus. | head -n1 | \
  awk '{OFS=""; d=$7; d=substr(d, 1, length(d) - 8) "deadbeef"; print "trust-anchor=", $1, ",", $4, ",", $5, ",", $6, ",", d}' \
  >> /etc/dnsmasq.d/02-trust-anchor.conf

# Create reverse lookup zone
pdnsutil zone create arpa ns1.ftl
pdnsutil rrset add arpa. 1.1.168.192.in-addr.arpa. PTR ftl.
pdnsutil rrset add arpa. 2.1.168.192.in-addr.arpa. PTR a.ftl.
pdnsutil rrset add arpa. 1.0.c.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa. PTR ftl.
pdnsutil rrset add arpa. 2.0.c.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa. PTR aaaa.ftl.

# Delegate the unsigned child zones from the locally-signed root. Both ftl and
# arpa are children of the '.' zone we serve, so the root has to carry an NS
# delegation for them; without it the signed root answers NXDOMAIN for their DS
# query (rather than a proper "insecure delegation" NODATA proof) and
# `pdnsutil zone check` reports "No delegation ... in parent '.'". They are
# unsigned, so an NS record with no DS is the correct, secure-parent way to mark
# them as an insecure delegation.
pdnsutil rrset add . ftl.  NS ns1.ftl.
pdnsutil rrset add . arpa. NS ns1.ftl.

# Calculates the ‘ordername’ and ‘auth’ fields for all zones so they comply with
# DNSSEC settings. Can be used to fix up migrated data. Can always safely be
# run, it does no harm.
pdnsutil zone rectify-all

# Do final checking
pdnsutil zone check ftl
pdnsutil zone check arpa

pdnsutil zone list-all

echo "********* Done installing PowerDNS configuration **********"

# Stop any previously running powerDNS daemons. killall is asynchronous,
# so wait until each process is actually gone before starting the new
# instance — otherwise the new daemon can fail to bind its port silently.
for proc in pdns_server pdns_recursor; do
  killall "$proc" 2> /dev/null || true
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pidof "$proc" > /dev/null 2>&1 || break
    sleep 0.2
  done
  killall -9 "$proc" 2> /dev/null || true
done

# Have to create the socketdir or the recursor will fail to start. Also
# clean stale pid/control-socket files left behind by a previous run.
mkdir -p /var/run/pdns-recursor
rm -f /var/run/pdns-recursor/*

# Start authoritative pdns_server and wait for it to accept queries on
# its configured port (5554) before continuing.
pdns_server --daemon
for _ in 1 2 3 4 5 6 7 8 9 10; do
  dig @127.0.0.1 -p 5554 ftl. SOA +tries=1 +time=1 +short > /dev/null 2>&1 && break
  sleep 0.5
done

# Start pdns_recursor and wait for it to accept queries on port 5555.
pdns_recursor --daemon
for _ in 1 2 3 4 5 6 7 8 9 10; do
  dig @127.0.0.1 -p 5555 ftl. SOA +tries=1 +time=1 +short > /dev/null 2>&1 && break
  sleep 0.5
done
