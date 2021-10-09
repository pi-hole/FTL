#!/bin/bash

echo "************ Installing PowerDNS configuration ************"

# Install config files
cp test/pdns/pdns.conf /etc/powerdns/pdns.conf
cp test/pdns/recursor.conf /etc/powerdns/recursor.conf

# Create zone database
rm /var/lib/powerdns/pdns.sqlite3 2> /dev/null
sqlite3 /var/lib/powerdns/pdns.sqlite3 < /usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql

# Create zone ftl
pdnsutil create-zone ftl ns1.ftl

# Create A records
pdnsutil add-record ftl. a A 192.168.1.1
pdnsutil add-record ftl. gravity A 192.168.1.2
pdnsutil add-record ftl. blacklisted A 192.168.1.3
pdnsutil add-record ftl. whitelisted A 192.168.1.4
pdnsutil add-record ftl. gravity-whitelisted A 192.168.1.5
pdnsutil add-record ftl. regex1 A 192.168.2.1
pdnsutil add-record ftl. regex2 A 192.168.2.2
pdnsutil add-record ftl. regex5 A 192.168.2.3
pdnsutil add-record ftl. regexA A 192.168.2.4
pdnsutil add-record ftl. regex-REPLYv4 A 192.168.2.5
pdnsutil add-record ftl. regex-REPLYv6 A 192.168.2.6
pdnsutil add-record ftl. regex-REPLYv46 A 192.168.2.7
pdnsutil add-record ftl. regex-A A 192.168.2.8
pdnsutil add-record ftl. regex-notA A 192.168.2.9

# Create AAAA records
pdnsutil add-record ftl. aaaa AAAA fe80::1c01
pdnsutil add-record ftl. regex-REPLYv4 AAAA fe80::2c01
pdnsutil add-record ftl. regex-REPLYv6 AAAA fe80::2c02
pdnsutil add-record ftl. regex-REPLYv46 AAAA fe80::2c03

# Create CNAME records
pdnsutil add-record ftl. cname-1 CNAME gravity.ftl
pdnsutil add-record ftl. cname-2 CNAME cname-1.ftl
pdnsutil add-record ftl. cname-3 CNAME cname-2.ftl
pdnsutil add-record ftl. cname-4 CNAME cname-3.ftl
pdnsutil add-record ftl. cname-5 CNAME cname-4.ftl
pdnsutil add-record ftl. cname-6 CNAME cname-5.ftl
pdnsutil add-record ftl. cname-7 CNAME cname-6.ftl

# Create CNAME for SOA test domain
pdnsutil add-record ftl. soa CNAME ftl

# Create PTR records
pdnsutil add-record ftl. ptr PTR ptr.ftl.

# Other testing records
pdnsutil add-record ftl. srv SRV "0 1 80 a.ftl"
pdnsutil add-record ftl. txt TXT "\"Some example text\""
pdnsutil add-record ftl. naptr NAPTR '10 10 "u" "smtp+E2U" "!.*([^\.]+[^\.]+)$!mailto:postmaster@$1!i" .'
pdnsutil add-record ftl. naptr NAPTR '20 10 "s" "http+N2L+N2C+N2R" "" ftl.'
pdnsutil add-record ftl. mx MX "50 ns1.ftl."

# SVCB
# below data means: SVCB 1 port="80"
# comment above applies
pdnsutil add-record ftl. svcb TYPE64 "\# 13 31202e20706f72743d22383022"

# HTTPS
# below data means: HTTPS 1 . alpn="h3,h2"
# see RFC3597: Handling of Unknown DNS Resource Record (RR) Types
# and https://ypcs.fi/howto/2020/09/30/announce-https-via-dns/
pdnsutil add-record ftl. https TYPE65 "\# 16 31202e20616c706e3d2268332c683222"

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
service pdns restart
service pdns-recursor restart
