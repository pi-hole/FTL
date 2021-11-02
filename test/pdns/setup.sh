#!/bin/bash

echo "************ Installing PowerDNS configuration ************"

# Delete possibly existing zone database
mkdir -p /var/lib/powerdns/
rm /var/lib/powerdns/pdns.sqlite3 2> /dev/null

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

cp test/pdns/recursor.conf $RECURSOR_CONF

# Create zone database
if [ -f /usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql ]; then
  # Debian
  sqlite3 /var/lib/powerdns/pdns.sqlite3 < /usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql
elif [ -f /usr/share/doc/pdns/schema.sqlite3.sql ]; then
  # Alpine
  sqlite3 /var/lib/powerdns/pdns.sqlite3 < /usr/share/doc/pdns/schema.sqlite3.sql
else
  echo "Error: powerDNS SQL schema not found"
  exit 1
fi
# Create zone ftl
pdnsutil create-zone ftl ns1.ftl
pdnsutil add-record ftl. . SOA "ns1.ftl. hostmaster.ftl. 1 10800 3600 604800 3600"

# Create A records
pdnsutil add-record ftl. a A 192.168.1.1
pdnsutil add-record ftl. gravity A 192.168.1.2
pdnsutil add-record ftl. denied A 192.168.1.3
pdnsutil add-record ftl. allowed A 192.168.1.4
pdnsutil add-record ftl. gravity-allowed A 192.168.1.5
pdnsutil add-record ftl. regex1 A 192.168.2.1
pdnsutil add-record ftl. regex2 A 192.168.2.2
pdnsutil add-record ftl. regex5 A 192.168.2.3
pdnsutil add-record ftl. regexA A 192.168.2.4
pdnsutil add-record ftl. regex-REPLYv4 A 192.168.2.5
pdnsutil add-record ftl. regex-REPLYv6 A 192.168.2.6
pdnsutil add-record ftl. regex-REPLYv46 A 192.168.2.7
pdnsutil add-record ftl. regex-A A 192.168.2.8
pdnsutil add-record ftl. regex-notA A 192.168.2.9
pdnsutil add-record ftl. any A 192.168.3.1

# Create AAAA records
pdnsutil add-record ftl. aaaa AAAA fe80::1c01
pdnsutil add-record ftl. regex-REPLYv4 AAAA fe80::2c01
pdnsutil add-record ftl. regex-REPLYv6 AAAA fe80::2c02
pdnsutil add-record ftl. regex-REPLYv46 AAAA fe80::2c03
pdnsutil add-record ftl. any AAAA fe80::3c01

# Create CNAME records
pdnsutil add-record ftl. cname-1 CNAME gravity.ftl
pdnsutil add-record ftl. cname-2 CNAME cname-1.ftl
pdnsutil add-record ftl. cname-3 CNAME cname-2.ftl
pdnsutil add-record ftl. cname-4 CNAME cname-3.ftl
pdnsutil add-record ftl. cname-5 CNAME cname-4.ftl
pdnsutil add-record ftl. cname-6 CNAME cname-5.ftl
pdnsutil add-record ftl. cname-7 CNAME cname-6.ftl
pdnsutil add-record ftl. cname-ok CNAME a.ftl

# Create CNAME for SOA test domain
pdnsutil add-record ftl. soa CNAME ftl

# Create PTR records
pdnsutil add-record ftl. ptr PTR ptr.ftl.

# Other testing records
pdnsutil add-record ftl. srv SRV "0 1 80 a.ftl"
pdnsutil add-record ftl. txt TXT "\"Some example text\""
# We want this to output $1 without expansion
# shellcheck disable=SC2016
pdnsutil add-record ftl. naptr NAPTR '10 10 "u" "smtp+E2U" "!.*([^\.]+[^\.]+)$!mailto:postmaster@$1!i" .'
pdnsutil add-record ftl. naptr NAPTR '20 10 "s" "http+N2L+N2C+N2R" "" ftl.'
pdnsutil add-record ftl. mx MX "50 ns1.ftl."

# SVCB + HTTPS
if ! pdnsutil add-record ftl. svcb SVCB '1 port="80"'; then
  # see RFC3597: Handling of Unknown DNS Resource Record (RR) Types
  # and https://ypcs.fi/howto/2020/09/30/announce-https-via-dns/
  pdnsutil add-record ftl. svcb TYPE64 "\# 13 000109706F72743D2238302200"
fi

# HTTPS
if ! pdnsutil add-record ftl. https HTTPS '1 . alpn="h3,h2"'; then
  # comment above applies
  pdnsutil add-record ftl. https TYPE65 "\# 15 000100000100080322683303683222"
fi

# Create reverse lookup zone
pdnsutil create-zone arpa ns1.ftl
pdnsutil add-record arpa. 1.1.168.192.in-addr PTR ftl.
pdnsutil add-record arpa. 2.1.168.192.in-addr PTR a.ftl.
pdnsutil add-record arpa. 1.0.c.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6 PTR ftl.
pdnsutil add-record arpa. 2.0.c.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6 PTR aaaa.ftl.

# Calculates the ‘ordername’ and ‘auth’ fields for all zones so they comply with
# DNSSEC settings. Can be used to fix up migrated data. Can always safely be
# run, it does no harm.
pdnsutil rectify-all-zones

# Do final checking
pdnsutil check-zone ftl
pdnsutil check-zone arpa

echo "********* Done installing PowerDNS configuration **********"

# Start services
killall pdns_server
pdns_server --daemon
# Have to create the socketdir or the recursor will fails to start
mkdir -p /var/run/pdns-recursor
killall pdns_recursor
pdns_recursor --daemon
