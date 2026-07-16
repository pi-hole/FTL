#!/usr/bin/env bats

# Load BATS libraries for enhanced testing capabilities
bats_load_library 'bats-support'
bats_load_library 'bats-assert'
bats_load_library 'bats-file'
load 'bats_helper.bash'

# Log the current test description to the FTL log at the start of each test.
# `setup()` is run by bats before every `@test` block.
setup() {
  printf 'Starting test: %s\n' "$BATS_TEST_DESCRIPTION" >> /var/log/pihole/FTL.log
}


@test "Compare template and test TOML config files" {
  # We skip the first 5 lines of the files as they contain the version and
  # timestamp of the file creation/modification
  run bash -c 'diff <(tail -n +6 test/pihole.toml) <(tail -n +6 /etc/pihole/pihole.toml)'
  refute_output
}

@test "Check FTL binary integrity" {
  run bash -c './pihole-FTL verify'
  assert_output --partial "Binary integrity check: OK"
}

@test "Running a second instance is detected and prevented" {
  run bash -c 'su pihole -s /bin/sh -c "./pihole-FTL -f"'
   assert_output --partial "CRIT: pihole-FTL is already running"
}

@test "dnsmasq options as expected" {
  run bash -c './pihole-FTL -vv | grep "dumpfile"'
  assert_line --index 0 "Features:        IPv6 GNU-getopt no-DBus no-UBus no-i18n IDN2 DHCP DHCPv6 Lua TFTP no-conntrack ipset no-nftset auth DNSSEC loop-detect inotify dumpfile"
  assert_line --index 1 ""
}

@test "Initial blocking status is enabled" {
  run bash -c 'grep -c "Blocking status is enabled" /var/log/pihole/FTL.log'
  refute_line --index 0 "0"
}

@test "Number of compiled regex filters as expected" {
  run bash -c 'grep "Compiled [0-9]* allow" /var/log/pihole/FTL.log'
  assert_line --partial --index 0 "Compiled 2 allow and 11 deny regex"
}

@test "Denied domain is blocked" {
  run bash -c "dig denied.ftl @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""
  
  run bash -c "dig denied.ftl @127.0.0.1 | grep 'EDE: '"
  assert_line --partial --index 0 "EDE: 15 (Blocked): (denylist)"
  assert_line --index 1 ""
}

@test "Gravity domain is blocked" {
  run bash -c "dig gravity.ftl @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""

  run bash -c "dig gravity.ftl @127.0.0.1 | grep 'EDE: '"
  assert_line --partial --index 0 "EDE: 15 (Blocked): (gravity)"
  assert_line --index 1 ""
}

@test "Gravity domain is blocked (TCP)" {
  run bash -c "dig gravity.ftl @127.0.0.1 +tcp +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""
  
  run bash -c "dig gravity.ftl @127.0.0.1 +tcp | grep 'EDE: '"
  assert_line --partial --index 0 "EDE: 15 (Blocked): (gravity)"
  assert_line --index 1 ""
}

@test "Gravity domain + allowed exact match is not blocked" {
  run bash -c "dig allowed.ftl @127.0.0.1 +short"
  assert_line --index 0 "192.168.1.4"
}

@test "Gravity domain + allowed regex match is not blocked" {
  run bash -c "dig gravity-allowed.ftl @127.0.0.1 +short"
  assert_line --index 0 "192.168.1.5"
}

@test "Gravity + antigravity exact matches are not blocked" {
  run bash -c "dig antigravity.ftl @127.0.0.1 +short"
  assert_line --index 0 "192.168.1.6"
}

@test "Regex denied match is blocked" {
  run bash -c "dig regex5.ftl @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""
  
  run bash -c "dig regex5.ftl @127.0.0.1 | grep 'EDE: '"
  assert_line --partial --index 0 "EDE: 15 (Blocked): (regex)"
  assert_line --index 1 ""
}

@test "Regex denylist mismatch is not blocked" {
  run bash -c "dig regexA.ftl @127.0.0.1 +short"
  assert_line --index 0 "192.168.2.4"
}

@test "Regex denylist match + allowlist exact match is not blocked" {
  run bash -c "dig regex1.ftl @127.0.0.1 +short"
  assert_line --index 0 "192.168.2.1"
}

@test "Regex denylist match + allowlist regex match is not blocked" {
  run bash -c "dig regex2.ftl @127.0.0.1 +short"
  assert_line --index 0 "192.168.2.2"
}

@test "Client 2: Gravity match matching unassociated allowlist is blocked" {
  run bash -c "dig allowed.ftl -b 127.0.0.2 @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
}

@test "Client 2: Regex denylist match matching unassociated allowlist is blocked" {
  run bash -c "dig regex1.ftl -b 127.0.0.2 @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
}

@test "Same domain is not blocked for client 1 ..." {
  run bash -c "dig regex1.ftl @127.0.0.1 +short"
  assert_line --index 0 "192.168.2.1"
}

@test "... or client 3" {
  run bash -c "dig regex1.ftl -b 127.0.0.3  @127.0.0.1 +short"
  assert_line --index 0 "192.168.2.1"
}

@test "Client 2: Unassociated denylist match is not blocked" {
  run bash -c "dig denied.ftl -b 127.0.0.2 @127.0.0.1 +short"
  assert_line --index 0 "192.168.1.3"
}

@test "Client 3: Exact denylist domain is not blocked" {
  run bash -c "dig denied.ftl -b 127.0.0.3 @127.0.0.1 +short"
  assert_line --index 0 "192.168.1.3"
}

@test "Client 3: Regex denylist domain is not blocked" {
  run bash -c "dig regex1.ftl -b 127.0.0.3 @127.0.0.1 +short"
  assert_line --index 0 "192.168.2.1"
}

@test "Client 3: Gravity domain is not blocked" {
  run bash -c "dig a.ftl -b 127.0.0.3 @127.0.0.1 +short"
  assert_line --index 0 "192.168.1.1"
}

@test "Client 4: Client is recognized by MAC address" {
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "dig TXT CHAOS version.bind -b 127.0.0.4 @127.0.0.1 +short"

  # Wait for lines we want to see in the log file
  run bash -c "./pihole-FTL wait-for '**** got cache reply: version.bind is <TXT>' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  run bash -c "grep -c \"Found database hardware address 127.0.0.4 -> aa:bb:cc:dd:ee:ff\" /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c \"Gravity database: Client aa:bb:cc:dd:ee:ff found. Using groups (4)\" /var/log/pihole/FTL.log"
  refute_line --index 0 "0"
  run bash -c "grep -c 'Regex deny: Querying associated regexes for client 127.0.0.4 (groups: 4)' /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c 'Regex allow: Querying associated regexes for client 127.0.0.4 (groups: 4)' /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c 'Regex allow ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.4' /var/log/pihole/FTL.log"
  assert_line --index 0 "2"
  run bash -c "grep -c 'Regex deny ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.4' /var/log/pihole/FTL.log"
  assert_line --index 0 "11"
}

@test "Client 5: Client is recognized by MAC address" {
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "dig TXT CHAOS version.bind -b 127.0.0.5 @127.0.0.1 +short"

  # Wait for lines we want to see in the log file
  run bash -c "./pihole-FTL wait-for '**** got cache reply: version.bind is <TXT>' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  run bash -c "grep -c \"Found database hardware address 127.0.0.5 -> aa:bb:cc:dd:ee:ff\" /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c \"Gravity database: Client aa:bb:cc:dd:ee:ff found. Using groups (4)\" /var/log/pihole/FTL.log"
  refute_line --index 0 "0"
  run bash -c "grep -c 'Regex deny: Querying associated regexes for client 127.0.0.5 (groups: 4)' /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c 'Regex allow: Querying associated regexes for client 127.0.0.5 (groups: 4)' /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c 'Regex allow ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.5' /var/log/pihole/FTL.log"
  assert_line --index 0 "2"
  run bash -c "grep -c 'Regex deny ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.5' /var/log/pihole/FTL.log"
  assert_line --index 0 "11"
}

@test "Client 6: Client is recognized by interface name" {
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "dig TXT CHAOS version.bind -b 127.0.0.6 @127.0.0.1 +short"

  # Wait for lines we want to see in the log file
  run bash -c "./pihole-FTL wait-for '**** got cache reply: version.bind is <TXT>' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success
  run bash -c "grep -c \"Found database hardware address 127.0.0.6 -> 00:11:22:33:44:55\" /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c \"There is no record for 00:11:22:33:44:55 in the client table\" /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c \"Found database interface 127.0.0.6 -> enp0s123\" /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c \"Gravity database: Client 00:11:22:33:44:55 found (identified by interface enp0s123). Using groups (5)\" /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c 'Regex deny: Querying associated regexes for client 127.0.0.6 (groups: 5)' /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c 'Regex allow: Querying associated regexes for client 127.0.0.6 (groups: 5)' /var/log/pihole/FTL.log"
  assert_line --index 0 "1"
  run bash -c "grep -c 'Regex allow ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.6' /var/log/pihole/FTL.log"
  assert_line --index 0 "2"
  run bash -c "grep -c 'Regex deny ([[:digit:]]*, DB ID [[:digit:]]*) .* NOT ENABLED for client 127.0.0.6' /var/log/pihole/FTL.log"
  assert_line --index 0 "11"
}

@test "Normal query (A) is not blocked" {
  run bash -c "dig A a.ftl @127.0.0.1 +short"
  assert_line --index 0 "192.168.1.1"
}

@test "Normal query (AAAA) is not blocked (TCP query)" {
  run bash -c "dig AAAA aaaa.ftl @127.0.0.1 +short +tcp"
  assert_line --index 0 "fe80::1c01"
}

@test "Mozilla canary domain is blocked with NXDOMAIN" {
  run bash -c "dig A use-application-dns.net @127.0.0.1"
  assert_line --partial --index 3 "status: NXDOMAIN"
  run bash -c 'grep -c "Mozilla canary domain use-application-dns.net is NXDOMAIN" /var/log/pihole/pihole.log'
  assert_line --index 0 "1"
}

@test "Local DNS test: A a.ftl" {
  run bash -c "dig A a.ftl @127.0.0.1 +short"
  assert_line --index 0 "192.168.1.1"
  assert_line --index 1 ""
}

@test "Local DNS test: AAAA aaaa.ftl" {
  run bash -c "dig AAAA aaaa.ftl @127.0.0.1 +short"
  assert_line --index 0 "fe80::1c01"
  assert_line --index 1 ""
}

@test "Local DNS test: ANY any.ftl" {
  run bash -c "dig ANY any.ftl @127.0.0.1 +short"
  assert_line --partial "192.168.3.1"
  assert_line --partial "fe80::3c01"
  # TXT records should not be returned due to filter-rr=ANY
  refute_output --partial "Some example text"
}

@test "Local DNS test: CNAME cname-ok.ftl" {
  run bash -c "dig CNAME cname-ok.ftl @127.0.0.1 +short"
  assert_line --index 0 "a.ftl."
  assert_line --index 1 ""
}

@test "Local DNS test: SRV srv.ftl" {
  run bash -c "dig SRV srv.ftl @127.0.0.1 +short"
  assert_line --index 0 "0 1 80 a.ftl."
  assert_line --index 1 ""
}

@test "Local DNS test: PTR ptr.ftl" {
  run bash -c "dig PTR ptr.ftl @127.0.0.1 +short"
  assert_line --index 0 "ptr.ftl."
  assert_line --index 1 ""
}

@test "Local DNS test: TXT txt.ftl" {
  run bash -c "dig TXT txt.ftl @127.0.0.1 +short"
  assert_line --index 0 "\"Some example text\""
  assert_line --index 1 ""
}

@test "Local DNS test: NAPTR naptr.ftl" {
  run bash -c "dig NAPTR naptr.ftl @127.0.0.1 +short"
  assert_line --partial '10 10 "u" "smtp+E2U" "!.*([^.]+[^.]+)$!mailto:postmaster@$1!i" .'
  assert_line --partial '20 10 "s" "http+N2L+N2C+N2R" "" ftl.'
}

@test "Local DNS test: MX mx.ftl" {
  run bash -c "dig MX mx.ftl @127.0.0.1 +short"
  assert_line --index 0 "50 ns1.ftl."
  assert_line --index 1 ""
}

@test "Local DNS test: SVCB svcb.ftl" {
  run bash -c "dig SVCB svcb.ftl @127.0.0.1 +short"
  assert_line --index 0 '1 port=\"80\".'
  assert_line --index 1 ""
}

@test "Local DNS test: HTTPS https.ftl" {
  run bash -c "dig HTTPS https.ftl @127.0.0.1 +short"
  assert_line --index 0 '1 . alpn="h3,h2"'
  assert_line --index 1 ""
}

@test "CNAME inspection: Shallow CNAME is blocked" {
  run bash -c "dig A cname-1.ftl @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""
}

@test "CNAME inspection: Deep CNAME is blocked" {
  run bash -c "dig A cname-7.ftl @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""
}

@test "CNAME inspection: NODATA CNAME targets are blocked" {
  run bash -c "dig A a-cname.ftl @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""
  run bash -c "dig AAAA a-cname.ftl @127.0.0.1 +short"
  assert_line --index 0 "::"
  assert_line --index 1 ""
  run bash -c "dig A aaaa-cname.ftl @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""
  run bash -c "dig AAAA aaaa-cname.ftl @127.0.0.1 +short"
  assert_line --index 0 "::"
  assert_line --index 1 ""
}

@test "DNSSEC: SECURE domain is resolved" {
  run bash -c "dig A a.dnssec @127.0.0.1"
  assert_line --partial --index 3 "status: NOERROR"
}

@test "DNSSEC: BOGUS domain is rejected" {
  run bash -c "dig A a.bogus @127.0.0.1"
  assert_line --partial --index 3 "status: SERVFAIL"
}

@test "Special domain: NXDOMAIN is returned" {
  run bash -c "dig A mask.icloud.com @127.0.0.1"
  assert_line --partial --index 3 "status: NXDOMAIN"
}

@test "Special domain: Record is returned when explicitly allowed" {
  run bash -c "dig A mask.icloud.com -b 127.0.0.2 @127.0.0.1"
  assert_line --partial --index 3 "status: NOERROR"
}

# NXRA + RA unset cannot be tested with PowerDNS as upstream provider

@test "Upstream blocked domain: NULL is recognized" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test
  run bash -c "dig A null.ftl @127.0.0.1"
  assert_line --partial --index 3 "status: NOERROR"
  assert_line --regexp "null.ftl.[[:space:]]+2[[:space:]]+IN[[:space:]]+A[[:space:]]+0.0.0.0"
  assert_line --partial --index 7 "EDE: 15 (Blocked): (upstream NULL)"

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  # Split log into array by newline
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "${log}"
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: A/127.0.0.1/null.ftl is not blocked (domainlist ID: -1)"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: **** forwarded null.ftl to 127.0.0.1#5555"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: blocked upstream with 0.0.0.0"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES:   Adding RR: \"null.ftl A 0.0.0.0\""* ]]
}

@test "Upstream blocked domain: NULL is recognized (cached)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test
  run bash -c "dig A null.ftl @127.0.0.1"
  assert_line --partial --index 3 "status: NOERROR"
  assert_line --regexp "null.ftl.[[:space:]]+2[[:space:]]+IN[[:space:]]+A[[:space:]]+0.0.0.0"

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  # Split log into array by newline
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "${log}"
  [[ ${lines[@]} == *"DEBUG_QUERIES: null.ftl is known as blocked upstream with NULL address (expires in"* ]]
  [[ ${lines[@]} != *"DEBUG_QUERIES: **** forwarded null.ftl to 127.0.0.1#5555"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES:   Adding RR: \"null.ftl A 0.0.0.0\""* ]]
}

@test "Upstream blocked domain: NULL is recognized (IPv6)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test
  run bash -c "dig AAAA null.ftl @127.0.0.1"
  assert_line --partial --index 3 "status: NOERROR"
  assert_line --regexp "null.ftl.[[:space:]]+2[[:space:]]+IN[[:space:]]+AAAA[[:space:]]+::"
  assert_line --partial --index 7 "EDE: 15 (Blocked): (upstream NULL)"


  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  # Split log into array by newline
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "${log}"
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: AAAA/127.0.0.1/null.ftl is not blocked (domainlist ID: -1)"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: **** forwarded null.ftl to 127.0.0.1#5555"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: blocked upstream with ::"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES:   Adding RR: \"null.ftl AAAA ::\""* ]]
}

@test "Upstream blocked domain: IP is recognized" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test
  run bash -c "dig A umbrella.ftl +short @127.0.0.1"
  assert_line --index 0 "146.112.61.104"
  assert_line --index 1 ""

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  # Split log into array by newline
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "${log}"
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: A/127.0.0.1/umbrella.ftl is not blocked (domainlist ID: -1)"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: **** forwarded umbrella.ftl to 127.0.0.1#5555"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: blocked upstream with known address (IPv4)"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: A/127.0.0.1/umbrella.ftl -> EXTERNAL_BLOCKED_IP"* ]]
}

@test "Upstream blocked domain: IP is recognized (cached)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test
  run bash -c "dig A umbrella.ftl +short @127.0.0.1"
  assert_line --index 0 "146.112.61.104"
  assert_line --index 1 ""

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  # Split log into array by newline
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "${log}"
  [[ ${lines[@]} == *"DEBUG_QUERIES: umbrella.ftl is known as blocked upstream with known address (expires in"* ]]
  # Test for NOT forwarded ...
  [[ ${lines[@]} != *"DEBUG_QUERIES: **** forwarded umbrella.ftl to 127.0.0.1#5555"* ]]
  # ... but cached
  [[ ${lines[@]} == *"DEBUG_QUERIES: **** got cache reply: umbrella.ftl is 146.112.61.104"* ]]
}

@test "Upstream blocked domain: IP is recognized (IPv6)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test
  run bash -c "dig AAAA umbrella.ftl +short @127.0.0.1"
  assert_line --index 0 "::ffff:146.112.61.104"
  assert_line --index 1 ""

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  # Split log into array by newline
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "${log}"
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: AAAA/127.0.0.1/umbrella.ftl is not blocked (domainlist ID: -1)"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: **** forwarded umbrella.ftl to 127.0.0.1#5555"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: blocked upstream with known address (IPv6)"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: AAAA/127.0.0.1/umbrella.ftl -> EXTERNAL_BLOCKED_IP"* ]]
}

@test "Upstream blocked domain: IP is recognized (multi)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test
  run bash -c "dig A umbrella-multi.ftl +short @127.0.0.1"
  assert_line --partial "146.112.61.104"
  assert_line --partial "8.8.8.8"
  assert_line --partial "1.2.3.4"

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  # Split log into array by newline
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "${log}"
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: A/127.0.0.1/umbrella-multi.ftl is not blocked (domainlist ID: -1)"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: **** forwarded umbrella-multi.ftl to 127.0.0.1#5555"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: A/127.0.0.1/umbrella-multi.ftl -> EXTERNAL_BLOCKED_IP"* ]]
}

@test "Upstream blocked domain: EDE 15 is recognized" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test
  run bash -c "dig A nxdomain.ede15.ftl @127.0.0.1"
  assert_line --partial --index 7 "EDE: 15 (Blocked): (upstream EDE 15)"

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  # Split log into array by newline
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "${log}"
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: A/127.0.0.1/nxdomain.ede15.ftl is not blocked (domainlist ID: -1)"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: **** forwarded nxdomain.ede15.ftl to 127.0.0.1#5555"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES: DNS cache: A/127.0.0.1/nxdomain.ede15.ftl -> EXTERNAL_BLOCKED_EDE15"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES:   Adding RR: \"nxdomain.ede15.ftl A 0.0.0.0\""* ]]
}

@test "Upstream blocked domain: EDE 15 is recognized (cached)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test
  run bash -c "dig A nxdomain.ede15.ftl @127.0.0.1"
  assert_line --partial --index 7 "EDE: 15 (Blocked): (upstream EDE 15)"

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  # Split log into array by newline
  lines=()
  while IFS= read -r line; do
    lines+=("$line")
  done <<< "${log}"
  [[ ${lines[@]} == *"DEBUG_QUERIES: nxdomain.ede15.ftl is known as blocked upstream with EDE15 (expires in"* ]]
  [[ ${lines[@]} != *"DEBUG_QUERIES: **** forwarded umbrella.ftl to 127.0.0.1#5555"* ]]
  [[ ${lines[@]} == *"DEBUG_QUERIES:   Adding RR: \"nxdomain.ede15.ftl A 0.0.0.0\""* ]]
}

@test "ABP-style matching working as expected" {
  run bash -c "dig A special.gravity.ftl @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""

  run bash -c "dig A a.b.c.d.special.gravity.ftl @127.0.0.1 +short"
  assert_line --index 0 "0.0.0.0"
  assert_line --index 1 ""
}

@test "pihole-FTL.db schema is as expected" {
  run bash -c './pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db .dump'
  assert_line --partial "CREATE TABLE IF NOT EXISTS \"query_storage\" (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL, forward INTEGER, additional_info INTEGER, reply_type INTEGER, reply_time REAL, dnssec INTEGER, list_id INTEGER, ede INTEGER);"
  assert_line --partial "CREATE INDEX idx_queries_timestamps ON \"query_storage\" (timestamp);"
  assert_line --partial "CREATE TABLE ftl (id INTEGER PRIMARY KEY NOT NULL, value BLOB NOT NULL, description TEXT);"
  assert_line --partial "CREATE TABLE counters (id INTEGER PRIMARY KEY NOT NULL, value INTEGER NOT NULL);"
  assert_line --partial "CREATE TABLE IF NOT EXISTS \"network\" (id INTEGER PRIMARY KEY NOT NULL, hwaddr TEXT UNIQUE NOT NULL, interface TEXT NOT NULL, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, numQueries INTEGER NOT NULL, macVendor TEXT, aliasclient_id INTEGER);"
  assert_line --partial "CREATE TABLE IF NOT EXISTS \"network_addresses\" (network_id INTEGER NOT NULL, ip TEXT UNIQUE NOT NULL, lastSeen INTEGER NOT NULL DEFAULT (cast(strftime('%s', 'now') as int)), name TEXT, nameUpdated INTEGER, FOREIGN KEY(network_id) REFERENCES network(id));"
  assert_line --partial "CREATE TABLE aliasclient (id INTEGER PRIMARY KEY NOT NULL, name TEXT NOT NULL, comment TEXT);"
  assert_line --partial "INSERT INTO ftl VALUES(0,22,'Database version');"
  # vvv This has been added in version 10 vvv
  assert_line --partial "CREATE VIEW queries AS SELECT q.id, q.timestamp, q.type, q.status, COALESCE(d.domain, q.domain) AS domain, COALESCE(c.ip, q.client) AS client, COALESCE(f.forward, q.forward) AS forward, COALESCE(a.content, q.additional_info) AS additional_info, q.reply_type, q.reply_time, q.dnssec, q.list_id, q.ede FROM query_storage q LEFT JOIN domain_by_id d ON q.domain = d.id LEFT JOIN client_by_id c ON q.client = c.id LEFT JOIN forward_by_id f ON q.forward = f.id LEFT JOIN addinfo_by_id a ON q.additional_info = a.id;"
  assert_line --partial "CREATE TABLE domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL);"
  assert_line --partial "CREATE TABLE client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT);"
  assert_line --partial "CREATE TABLE forward_by_id (id INTEGER PRIMARY KEY, forward TEXT NOT NULL);"
  assert_line --partial "CREATE UNIQUE INDEX domain_by_id_domain_idx ON domain_by_id(domain);"
  assert_line --partial "CREATE UNIQUE INDEX client_by_id_client_idx ON client_by_id(ip,name);"
  # vvv This has been added in version 11 vvv
  assert_line --partial "CREATE TABLE addinfo_by_id (id INTEGER PRIMARY KEY, type INTEGER NOT NULL, content NOT NULL);"
  assert_line --partial "CREATE UNIQUE INDEX addinfo_by_id_idx ON addinfo_by_id(type,content);"
  # vvv This has been added in version 15 vvv
  assert_line --partial "CREATE TABLE session (id INTEGER PRIMARY KEY, login_at TIMESTAMP NOT NULL, valid_until TIMESTAMP NOT NULL, remote_addr TEXT NOT NULL, user_agent TEXT, sid TEXT NOT NULL, csrf TEXT NOT NULL, tls_login BOOL, tls_mixed BOOL, app BOOL, cli BOOL, x_forwarded_for TEXT);"
  # vvv This has been added in version 20 vvv
  assert_line --partial "CREATE INDEX network_addresses_network_id_index ON network_addresses (network_id);"
}

@test "Ownership, permissions and type of pihole-FTL.db correct" {
  run bash -c 'ls -l /etc/pihole/pihole-FTL.db'
  # Depending on the shell (x86_64-musl is built on busybox) there can be one or multiple spaces between user and group
  assert_line --regexp --index 0 "pihole[[:space:]]+pihole"
  assert_file_permission 640 /etc/pihole/pihole-FTL.db
  run bash -c 'file /etc/pihole/pihole-FTL.db'
  assert_line --partial --index 0 "/etc/pihole/pihole-FTL.db: SQLite 3.x database"
}

@test "MAC vendor lookup resolves MA-L, MA-M and MA-S blocks (longest prefix)" {
  # The macvendor table stores Wireshark manuf keys verbatim: a plain "XX:XX:XX"
  # for /24 (MA-L) and a masked form for the sub-divided blocks, e.g.
  # "34:E1:D1:80/28" (MA-M) and "00:1B:C5:00:00/36" (MA-S). Seed a small db in
  # that exact format.
  DB=/tmp/macvendor_test.db
  rm -f "${DB}"
  ./pihole-FTL sqlite3 "${DB}" "CREATE TABLE macvendor (mac TEXT NOT NULL, vendor TEXT NOT NULL, PRIMARY KEY (mac));"
  ./pihole-FTL sqlite3 "${DB}" "INSERT INTO macvendor (mac, vendor) VALUES ('98:48:27','Tp-Link'),('34:E1:D1:80/28','Hubitat'),('34:E1:D1:00/28','Tianjin Sublue'),('00:1B:C5:00:00/36','Converging Systems');"

  # Mirrors the longest-prefix query used by getMACVendor(): reconstruct the
  # candidate /24, /28 and /36 keys from the MAC and let the longest match win.
  _macvendor_lookup() {
    ./pihole-FTL sqlite3 "${DB}" "SELECT vendor FROM macvendor WHERE mac IN (substr(upper('${1}'),1,8),substr(upper('${1}'),1,9)||substr(upper('${1}'),10,1)||'0/28',substr(upper('${1}'),1,12)||substr(upper('${1}'),13,1)||'0/36') ORDER BY length(mac) DESC LIMIT 1;"
  }

  # MA-L (/24)
  run _macvendor_lookup "98:48:27:c4:2f:f2"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "Tp-Link" ]]

  # MA-M (/28): the bare 24-bit OUI 34:E1:D1 has no row of its own
  run _macvendor_lookup "34:e1:d1:80:76:de"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "Hubitat" ]]

  # A different MA-M (/28) under the same 24-bit parent resolves independently
  run _macvendor_lookup "34:e1:d1:00:11:22"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "Tianjin Sublue" ]]

  # MA-S (/36)
  run _macvendor_lookup "00:1b:c5:00:00:42"
  printf "%s\n" "${lines[@]}"
  [[ "${lines[0]}" == "Converging Systems" ]]

  # Unknown OUI: no match
  run _macvendor_lookup "de:ad:be:ef:00:01"
  printf "%s\n" "${lines[@]}"
  [[ -z "${lines[0]}" ]]

  rm -f "${DB}"
}

@test "Test fail on invalid CLI argument" {
  run bash -c './pihole-FTL abc'
  assert_line --index 0 "pihole-FTL: invalid option -- 'abc'"
  assert_line --index 1 "Command: './pihole-FTL abc'"
  assert_line --index 2 "Try './pihole-FTL --help' for more information"
}

@test "Help CLI argument return help text" {
  run bash -c './pihole-FTL help'
  assert_line --partial --index 0 "The Pi-hole FTL engine - "
}

@test "CLI config output as expected" {
  # Partial match printing
  run bash -c './pihole-FTL --config dns.upstream'
  assert_line --index 0 "dns.upstreams = [ 127.0.0.1#5555 ]"

  # Exact match printing
  run bash -c './pihole-FTL --config dns.upstreams'
  assert_line --index 0 "[ 127.0.0.1#5555 ]"
  run bash -c './pihole-FTL --config dns.piholePTR'
  assert_line --index 0 "PI.HOLE"
  run bash -c './pihole-FTL --config dns.hosts'
  assert_line --index 0 "[ 1.1.1.1 abc-custom.com def-custom.de, 2.2.2.2 äste.com steä.com ]"
  run bash -c './pihole-FTL --config webserver.port'
  assert_line --index 0 "80o,443os,[::]:80o,[::]:443os"
}

@test "'pihole-FTL backtrace' generates a structured backtrace" {
  run bash -c './pihole-FTL backtrace'
  printf "%s\n" "${lines[@]}"
  # This path generates a backtrace without crashing, so it exits cleanly
  assert_success
  # The header reports a frame count (and, for a real crash, the unwind source)
  assert_line --regexp --index 0 '^Backtrace \([^)]*frames[^)]*\):$'
  # At least the first two frames are collected
  assert_output --partial "#0"
  assert_output --partial "#1"
  # The calling chain is symbolized (addr2line or the dladdr fallback): the
  # 'backtrace' subcommand is reached via parse_args() from main()
  assert_output --partial "parse_args"
  assert_output --partial "main"
  # The closing marker is present
  assert_output --partial "--- end of backtrace"
}

@test "'pihole-FTL backtrace' resolves source locations when addr2line is present" {
  if ! command -v addr2line >/dev/null 2>&1; then
    skip "addr2line not installed; resolution-dependent assertion skipped"
  fi
  run bash -c './pihole-FTL backtrace'
  printf "%s\n" "${lines[@]}"
  assert_success
  # parse_args() resolves to its project-relative source location
  assert_output --partial "src/args.c"
  # addr2line is available, so the 'not installed' hint must not be printed
  refute_output --partial "addr2line is not installed"
}

@test "'pihole-FTL backtrace' prints resolve guidance when addr2line is unavailable" {
  # Hide addr2line via an empty PATH (the binary itself is launched by an
  # explicit relative path, so it still runs). The directly spawned addr2line
  # child then fails to exec and exits 127, which must be reported as
  # 'not installed' and every unresolved frame must get a copy-pasteable
  # reproducer command.
  run bash -c 'PATH="" ./pihole-FTL backtrace'
  printf "%s\n" "${lines[@]}"
  assert_success
  assert_output --partial "Backtrace ("
  assert_output --partial "addr2line is not installed"
  assert_output --partial "unresolved frame"
  assert_output --partial "addr2line -f -e"
}

# NOTE: Log validation (WARNING/ERROR/CRIT/DB checks) moved to the final
# log scan in run.sh, which runs after both BATS and pytest complete.

# Regex tests
@test "Compiled deny regex as expected" {
  run bash -c 'grep -c "Compiling deny regex 0 (DB ID 6): regex\[0-9\].ftl" /var/log/pihole/FTL.log'
  assert_line --index 0 "1"
}

@test "Compiled allow regex as expected" {
  run bash -c 'grep -c "Compiling allow regex 0 (DB ID 3): regex2" /var/log/pihole/FTL.log'
  assert_line --index 0 "1"
  run bash -c 'grep -c "Compiling allow regex 1 (DB ID 4): ^gravity-allowed" /var/log/pihole/FTL.log'
  assert_line --index 0 "1"
}

@test "Regex Test 1: \"regex7.ftl\" vs. [database regex]: MATCH" {
  run bash -c './pihole-FTL regex-test "regex7.ftl"'
  assert_success
}

@test "Regex Test 2: \"a\" vs. \"a\": MATCH" {
  run bash -c './pihole-FTL regex-test "a" "a"'
  assert_success
}

@test "Regex Test 3: \"aa\" vs. \"^[a-z]{1,3}$\": MATCH" {
  run bash -c './pihole-FTL regex-test "aa" "^[a-z]{1,3}$"'
  assert_success
}

@test "Regex Test 4: \"aaaa\" vs. \"^[a-z]{1,3}$\": NO MATCH" {
  run bash -c './pihole-FTL regex-test "aaaa" "^[a-z]{1,3}$"'
  assert_failure 2
}

@test "Regex Test 5: \"aa\" vs. \"^a(?#some comment)a$\": MATCH (comments)" {
  run bash -c './pihole-FTL regex-test "aa" "^a(?#some comment)a$"'
  assert_success
}

@test "Regex Test 6: \"abc.abc\" vs. \"([a-z]*)\.\1\": MATCH" {
  run bash -c './pihole-FTL regex-test "abc.abc" "([a-z]*)\.\1"'
  assert_success
}

@test "Regex Test 7: Complex character set: MATCH" {
  run bash -c './pihole-FTL regex-test "__abc#LMN012$x%yz789*" "[[:digit:]a-z#$%]+"'
  assert_success
}

@test "Regex Test 8: Range expression: MATCH" {
  run bash -c './pihole-FTL regex-test "!ABC-./XYZ~" "[--Z]+"'
  assert_success
}

@test "Regex Test 9: Back reference: \"aabc\" vs. \"(a)\1{1,2}\": MATCH" {
  run bash -c './pihole-FTL regex-test "aabc" "(a)\1{1,2}"'
  assert_success
}

@test "Regex Test 10: Back reference: \"foo\" vs. \"(.)\1$\": MATCH" {
  run bash -c './pihole-FTL regex-test "foo" "(.)\1$"'
  assert_success
}

@test "Regex Test 11: Back reference: \"foox\" vs. \"(.)\1$\": NO MATCH" {
  run bash -c './pihole-FTL regex-test "foox" "(.)\1$"'
  assert_failure 2
}

@test "Regex Test 12: Back reference: \"1234512345\" vs. \"([0-9]{5})\1\": MATCH" {
  run bash -c './pihole-FTL regex-test "1234512345" "([0-9]{5})\1"'
  assert_success
}

@test "Regex Test 13: Back reference: \"12345\" vs. \"([0-9]{5})\1\": NO MATCH" {
  run bash -c './pihole-FTL regex-test "12345" "([0-9]{5})\1"'
  assert_failure 2
}

@test "Regex Test 14: Complex back reference: MATCH" {
  run bash -c './pihole-FTL regex-test "cat.foo.dog---cat%dog!foo" "(cat)\.(foo)\.(dog)---\1%\3!\2"'
  assert_success
}

@test "Regex Test 15: Approximate matching, 0 errors: MATCH" {
  run bash -c './pihole-FTL regex-test "foobarzap" "foo(bar){~1}zap"'
  assert_success
}

@test "Regex Test 16: Approximate matching, 1 error (inside fault-tolerant area): MATCH" {
  run bash -c './pihole-FTL regex-test "foobrzap" "foo(bar){~1}zap"'
  assert_success
}

@test "Regex Test 17: Approximate matching, 1 error (outside fault-tolert area): NO MATCH" {
  run bash -c './pihole-FTL regex-test "foxbrazap" "foo(bar){~1}zap"'
  assert_failure 2
}

@test "Regex Test 18: Approximate matching, 0 global errors: MATCH" {
  run bash -c './pihole-FTL regex-test "foobar" "^(foobar){~1}$"'
  assert_success
}

@test "Regex Test 19: Approximate matching, 1 global error: MATCH" {
  run bash -c './pihole-FTL regex-test "cfoobar" "^(foobar){~1}$"'
  assert_success
}

@test "Regex Test 20: Approximate matching, 2 global errors: NO MATCH" {
  run bash -c './pihole-FTL regex-test "ccfoobar" "^(foobar){~1}$"'
  assert_failure 2
}

@test "Regex Test 21: Approximate matching, insert + substitute: MATCH" {
  run bash -c './pihole-FTL regex-test "oobargoobaploowap" "(foobar){+2#2~2}"'
  assert_success
}

@test "Regex Test 22: Approximate matching, insert + delete: MATCH" {
  run bash -c './pihole-FTL regex-test "3oifaowefbaoraofuiebofasebfaobfaorfeoaro" "(foobar){+1 -2}"'
  assert_success
}

@test "Regex Test 23: Approximate matching, insert + delete (insufficient): NO MATCH" {
  run bash -c './pihole-FTL regex-test "3oifaowefbaoraofuiebofasebfaobfaorfeoaro" "(foobar){+1 -1}"'
  assert_failure 2
}

@test "Regex Test 24: Useful hint for invalid regular expression \"f{x}\": Invalid contents of {}" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "f{x}"'
  assert_line --index 1 "Invalid regex CLI filter \"f{x}\": Invalid contents of {}"
  assert_failure 1
}

@test "Regex Test 25: Useful hint for invalid regular expression \"a**\": Invalid use of repetition operators" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "a**"'
  assert_line --index 1 "Invalid regex CLI filter \"a**\": Invalid use of repetition operators"
  assert_failure 1
}

@test "Regex Test 26: Useful hint for invalid regular expression \"x\\\": Trailing backslash" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "x\\"'
  assert_line --index 1 "Invalid regex CLI filter \"x\\\": Trailing backslash"
  assert_failure 1
}

@test "Regex Test 27: Useful hint for invalid regular expression \"[\": Missing ']'" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "["'
  assert_line --index 1 "Invalid regex CLI filter \"[\": Missing ']'"
  assert_failure 1
}

@test "Regex Test 28: Useful hint for invalid regular expression \"(\": Missing ')'" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "("'
  assert_line --index 1 "Invalid regex CLI filter \"(\": Missing ')'"
  assert_failure 1
}

@test "Regex Test 29: Useful hint for invalid regular expression \"{1\": Missing '}'" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "{1"'
  assert_line --index 1 "Invalid regex CLI filter \"{1\": Missing '}'"
  assert_failure 1
}

@test "Regex Test 30: Useful hint for invalid regular expression \"[[.foo.]]\": Unknown collating element" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "[[.foo.]]"'
  assert_line --index 1 "Invalid regex CLI filter \"[[.foo.]]\": Unknown collating element"
  assert_failure 1
}

@test "Regex Test 31: Useful hint for invalid regular expression \"[[:foobar:]]\": Unknown character class name" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "[[:foobar:]]"'
  assert_line --index 1 "Invalid regex CLI filter \"[[:foobar:]]\": Unknown character class name"
  assert_failure 1
}

@test "Regex Test 32: Useful hint for invalid regular expression \"(a)\\2\": Invalid back reference" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "(a)\\2"'
  assert_line --index 1 "Invalid regex CLI filter \"(a)\\2\": Invalid back reference"
  assert_failure 1
}

@test "Regex Test 33: Useful hint for invalid regular expression \"[g-1]\": Invalid character range" {
  run bash -c './pihole-FTL regex-test "fbcdn.net" "[g-1]"'
  assert_line --index 1 "Invalid regex CLI filter \"[g-1]\": Invalid character range"
  assert_failure 1
}

@test "Regex Test 34: Quiet mode: Match = Return code 0, nothing else" {
  run bash -c './pihole-FTL -q regex-test "fbcdn.net" "f"'
  assert_success
}

@test "Regex Test 35: Quiet mode: Invalid regex = Return code 1, with error message" {
  run bash -c './pihole-FTL -q regex-test "fbcdn.net" "g{x}"'
  assert_line --index 0 "Invalid regex CLI filter \"g{x}\": Invalid contents of {}"
  assert_failure 1
}

@test "Regex Test 36: Quiet mode: No Match = Return code 2, nothing else" {
  run bash -c './pihole-FTL -q regex-test "fbcdn.net" "g"'
  assert_failure 2
}

@test "Regex Test 37: Option \";querytype=A\" working as expected (ONLY matching A queries)" {
  run bash -c 'dig A regex-A @127.0.0.1'
  run bash -c 'dig A regex-A @127.0.0.1 +short'
  assert_line --index 0 "0.0.0.0"
  run bash -c 'dig AAAA regex-A @127.0.0.1'
  run bash -c 'dig AAAA regex-A @127.0.0.1 +short'
  # refute_line --index 0 "::" Would be more exact, but a BATS bug causes this to error (https://github.com/bats-core/bats-assert/issues/91)
  refute_output "::"
}

@test "Regex Test 38: Option \";querytype=!A\" working as expected (NOT matching A queries)" {
  run bash -c 'dig A regex-notA @127.0.0.1'
  run bash -c 'dig A regex-notA @127.0.0.1 +short'
  # refute_line --index 0 "0.0.0.0" Would be more exact, but a BATS bug causes this to error (https://github.com/bats-core/bats-assert/issues/91)
  refute_output "0.0.0.0"
  run bash -c 'dig AAAA regex-notA @127.0.0.1'
  run bash -c 'dig AAAA regex-notA @127.0.0.1 +short'
  assert_line --index 0 "::"
}

@test "Regex Test 39: Option \";invert\" working as expected (match is inverted)" {
  run bash -c './pihole-FTL -q regex-test "f" "g;invert"'
  assert_success
  run bash -c './pihole-FTL -q regex-test "g" "g;invert"'
  assert_failure 2
}

@test "Regex Test 40: Option \";querytype\" sanity checks" {
  run bash -c './pihole-FTL regex-test "f" g\;querytype=!A\;querytype=A'
  assert_line --partial "Overwriting previous querytype setting (multiple \"querytype=...\" found)"
}

@test "Regex Test 41: Option \"^;reply=NXDOMAIN\" working as expected" {
  run bash -c 'dig A regex-NXDOMAIN @127.0.0.1'
  assert_line --partial --index 3 "status: NXDOMAIN"
}

@test "Regex Test 42: Option \"^;reply=NODATA\" working as expected" {
  run bash -c 'dig A regex-NODATA @127.0.0.1'
  assert_line --partial --index 3 "status: NOERROR"
}

@test "Regex Test 43: Option \";reply=REFUSED\" working as expected" {
  run bash -c 'dig A regex-REFUSED @127.0.0.1'
  assert_line --partial --index 3 "status: REFUSED"
}

@test "Regex Test 44: Option \";reply=1.2.3.4\" working as expected" {
  run bash -c 'dig A regex-REPLYv4 @127.0.0.1 +short'
  assert_line --index 0 "1.2.3.4"
  run bash -c 'dig AAAA regex-REPLYv4 @127.0.0.1 +short'
  assert_line --index 0 "::"
}

@test "Regex Test 45: Option \";reply=fe80::1234\" working as expected" {
  run bash -c 'dig A regex-REPLYv6 @127.0.0.1 +short'
  assert_line --index 0 "0.0.0.0"
  run bash -c 'dig AAAA regex-REPLYv6 @127.0.0.1 +short'
  assert_line --index 0 "fe80::1234"
}

@test "Regex Test 46: Option \";reply=1.2.3.4;reply=fe80::1234\" working as expected" {
  run bash -c 'dig A regex-REPLYv46 @127.0.0.1 +short'
  assert_line --index 0 "1.2.3.4"
  run bash -c 'dig AAAA regex-REPLYv46 @127.0.0.1 +short'
  assert_line --index 0 "fe80::1234"
}

@test "Regex Test 47: Option \";querytype=A\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" f\;querytype=A'
  assert_success
  assert_line --partial --index 5 "- A"
}

@test "Regex Test 48: Option \";querytype=!TXT\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" f\;querytype=!TXT'
  assert_success
  refute_line --partial "- TXT"
}

@test "Regex Test 49: Option \";reply=NXDOMAIN\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" f\;reply=NXDOMAIN'
  assert_success
  assert_line --index 4 "    Hint: This regex forces reply type NXDOMAIN"
}

@test "Regex Test 50: Option \";invert\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" g\;invert'
  assert_success
  assert_line --index 4 "    Hint: This regex is inverted"
}

@test "Regex Test 51: Option \";querytype=A,HTTPS\" reported on CLI" {
  run bash -c './pihole-FTL regex-test "f" f\;querytype=A,HTTPS'
  assert_success
  assert_line --partial --index 5 "- A"
  assert_line --partial --index 6 "- HTTPS"
}

@test "Regex Test 52: Option \";querytype=ANY,HTTPS,SVCB;reply=refused\" working as expected (ONLY matching ANY, HTTPS or SVCB queries)" {
  run bash -c 'dig A regex-multiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: NOERROR"
  run bash -c 'dig AAAA regex-multiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: NOERROR"
  run bash -c 'dig SVCB regex-multiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: REFUSED"
  run bash -c 'dig HTTPS regex-multiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: REFUSED"
  run bash -c 'dig ANY regex-multiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: REFUSED"
}

@test "Regex Test 53: Option \";querytype=!ANY,HTTPS,SVCB;reply=refused\" working as expected (NOT matching ANY, HTTPS or SVCB queries)" {
  run bash -c 'dig A regex-notMultiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: REFUSED"
  run bash -c 'dig AAAA regex-notMultiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: REFUSED"
  run bash -c 'dig SVCB regex-notMultiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: NOERROR"
  run bash -c 'dig HTTPS regex-notMultiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: NOERROR"
  run bash -c 'dig ANY regex-notMultiple.ftl @127.0.0.1'
  assert_line --partial --index 3 "status: NOERROR"
}

@test "API addresses reported correctly by CHAOS TXT domain.api.ftl" {
  run bash -c 'dig CHAOS TXT domain.api.ftl +short @127.0.0.1'
  assert_line --index 0 '"http://pi.hole:80/api/" "https://pi.hole:443/api/"'
}

@test "API addresses reported correctly by CHAOS TXT local.api.ftl" {
  run bash -c 'dig CHAOS TXT local.api.ftl +short @127.0.0.1'
  assert_line --index 0 '"http://127.0.0.1:80/api/" "https://127.0.0.1:443/api/" "http://[::1]:80/api/" "https://[::1]:443/api/"'
}

@test "API addresses reported by CHAOS TXT api.ftl identical to domain.api.ftl" {
  run bash -c 'dig CHAOS TXT api.ftl +short @127.0.0.1'
  api="${lines[0]}"
  run bash -c 'dig CHAOS TXT domain.api.ftl +short @127.0.0.1'
  domain_api="${lines[0]}"
  assert_equal "${api}" "${domain_api}"
}

# "ldd" prints library dependencies and the used interpreter for a given program
#
# Dependencies on shared libraries are displayed like
#    libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fa7d28be000)
#
# In this test, we use ldd and check for the dependency arrow "=>" to check if
# our generated binary depends on shared libraries in the way we expect it to

@test "Dependence on shared libraries" {
  run bash -c 'ldd ./pihole-FTL'
  if [ "${STATIC}" != "true" ]; then
    assert_line --partial  "=>"
  else
    refute_line --partial "=>"
  fi
}

# "file" determines the file type of our generated binary
#
# We use its ability to test whether a specific interpreter is
# required by the given executable. What the interpreter is, is not
# really well documented in "man elf(5)", however, one can say that
# the interpreter is a program that finds and loads the shared
# libraries needed by a program, prepares the program to run, and then
# runs it.
#
# In this test, we use "file" to confirm the absence of the dependence
# on an interpreter for the static binary.

@test "Dependence on specific interpreter" {
  run bash -c 'file ./pihole-FTL'
  if [ "${STATIC}" != "true" ]; then
    assert_line --partial  "interpreter"
  else
    refute_line --partial "interpreter"
  fi
}

@test "Compiler version is correctly reported on startup" {
  compiler_version="$(${CC} --version | head -n1)" && export compiler_version
  run bash -c 'grep "Compiled for" /var/log/pihole/FTL.log'
  printf "Output: %s\n\$CC: %s\nVersion: %s\n" "${lines[@]:-not set}" "${CC:-not set}" "${compiler_version:-not set}"
  assert_line --partial --index 0 "using ${compiler_version}"
}

@test "No errors on setting busy handlers for the databases" {
  run bash -c 'grep -c "Cannot set busy handler" /var/log/pihole/FTL.log'
  assert_line --index 0 "0"
}

@test "Blocking status is correctly logged in pihole.log" {
  run bash -c 'grep -c "gravity blocked gravity.ftl is 0.0.0.0" /var/log/pihole/pihole.log'
  assert_line --index 0 "4"
}

# NOTE: HTTP 404 tests moved to pytest (test/api/test_api.py)

@test "LUA: Interpreter returns FTL version" {
  run bash -c './pihole-FTL lua -e "print(pihole.ftl_version())"'
  assert_line --partial --index 0 "v"
}

@test "LUA: Interpreter loads and enabled bundled library \"inspect\"" {
  run bash -c './pihole-FTL lua -e "print(inspect(inspect))"'
  assert_line --partial '_DESCRIPTION = "human-readable representations of tables'
  assert_line --partial '_VERSION = "inspect.lua 3.1.0"'
}

@test "LUA: pihole.json_decode round-trips JSON" {
  run bash -c './pihole-FTL lua -e "local t = pihole.json_decode([[{\"a\":1,\"b\":[2,3],\"c\":true,\"d\":null,\"e\":\"x\"}]]); print(t.a, t.b[1], t.b[2], t.c, t.d, t.e)"'
  assert_success
  assert_line --index 0 "1.0	2.0	3.0	true	nil	x"
}

@test "LUA: pihole.json_decode handles nested objects" {
  run bash -c './pihole-FTL lua -e "local t = pihole.json_decode([[{\"o\":{\"k\":\"v\"}}]]); print(t.o.k)"'
  assert_success
  assert_line --index 0 "v"
}

@test "LUA: pihole.json_decode handles empty object and array" {
  run bash -c './pihole-FTL lua -e "local t = pihole.json_decode([[{\"o\":{},\"a\":[]}]]); print(next(t.o), next(t.a))"'
  assert_success
  assert_line --index 0 "nil	nil"
}

@test "LUA: pihole.json_decode returns nil + error for invalid JSON" {
  run bash -c './pihole-FTL lua -e "local t, err = pihole.json_decode([[{not json}]]); print(type(t), err)"'
  assert_line --index 0 --partial "nil"
  assert_line --index 0 --partial "invalid JSON"
}

@test "EDNS(0) analysis working as expected" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  #                                  CLIENT SUBNET          COOKIE                       MAC HEX                     MAC TEXT                                          CPE-ID
  run bash -c 'dig localhost +short +subnet=192.168.1.1/32 +ednsopt=10:1122334455667788 +ednsopt=65001:000102030405 +ednsopt=65073:41413A42423A43433A44443A45453A4646 +ednsopt=65074:414243444546 @127.0.0.1'
  assert_line --index 0 "127.0.0.1"
  assert_success

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  log="$(sed -n "${before},${after}p" /var/log/pihole/FTL.log)"
  printf "%s\n" "${log}"

  # Start actual test
  run bash -c "grep -c \"EDNS0: CLIENT SUBNET: 192.168.1.1/32\"" <<< "${log}"
  assert_line --index 0 "1"
  run bash -c "grep -c \"EDNS0: COOKIE (client-only): 1122334455667788\"" <<< "${log}"
  assert_line --index 0 "1"
  run bash -c "grep -c \"EDNS0: MAC address (BYTE format): 00:01:02:03:04:05\"" <<< "${log}"
  assert_line --index 0 "1"
  run bash -c "grep -c \"EDNS0: MAC address (TEXT format): AA:BB:CC:DD:EE:FF\"" <<< "${log}"
  assert_line --index 0 "1"
  run bash -c "grep -c \"EDNS0: CPE-ID (payload size 6): \\\"ABCDEF\\\" (0x41 0x42 0x43 0x44 0x45 0x46)\"" <<< "${log}"
  assert_line --index 0 "1"
}

@test "EDNS(0) ECS can overwrite client address (IPv4)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=192.168.47.97/32 @127.0.0.1'
  assert_line --index 0 "127.0.0.1"
  assert_success

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"
  assert_line --partial "**** new UDP IPv4 query[A] query \"localhost\" from lo/192.168.47.97#53 "
}

@test "EDNS(0) ECS can overwrite client address (IPv6)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=fe80::b167:af1e:968b:dead/128 @127.0.0.1'
  assert_line --index 0 "127.0.0.1"
  assert_success

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"
  assert_line --partial "**** new UDP IPv4 query[A] query \"localhost\" from lo/fe80::b167:af1e:968b:dead#53 "
}

@test "alias-client is imported and used for configured client" {
  run bash -c 'grep -c "Added alias-client \"some-aliasclient\" (aliasclient-0) with FTL ID 0" /var/log/pihole/FTL.log'
  assert_line --index 0 "1"
  run bash -c 'grep -c "Aliasclient ID 127.0.0.6 -> 0" /var/log/pihole/FTL.log'
  assert_line --index 0 "1"
  run bash -c 'grep -c "Client .* (127.0.0.6) IS  managed by this alias-client, adding counts" /var/log/pihole/FTL.log'
  assert_line --index 0 "1"
}

@test "EDNS(0) ECS skipped for loopback address (IPv4)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=127.0.0.1/32 @127.0.0.1'
  assert_line --index 0 "127.0.0.1"
  assert_success

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"
  assert_line --partial "EDNS0: CLIENT SUBNET: Skipped 127.0.0.1/32 (IPv4 loopback address)"
}

@test "EDNS(0) ECS skipped for loopback address (IPv6)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c 'dig localhost +short +subnet=::1/128 @127.0.0.1'
  assert_line --index 0 "127.0.0.1"
  assert_success

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"
  assert_line --partial "EDNS0: CLIENT SUBNET: Skipped ::1/128 (IPv6 loopback address)"
}

@test "Embedded SQLite3 shell available and functional" {
  run bash -c './pihole-FTL sqlite3 -help'
  assert_line --index 0 "Usage: sqlite3 [OPTIONS] [FILENAME [SQL...]]"
}

@test "Embedded SQLite3 shell is called for .db file" {
  run bash -c './pihole-FTL abc.db ".version"'
  assert_line --partial --index 0 "SQLite 3."
}

@test "Embedded SQLite3 shell prints FTL version in interactive mode" {
  # shell.c contains a call to print_FTL_version
  run bash -c "echo -e '.quit\n' | ./pihole-FTL sqlite3 -interactive"
  assert_line --partial --index 0 "Pi-hole FTL"
}

@test "Embedded SQLite3 shell ignores .sqliterc \"-ni\"" {
  # Install .sqliterc file at current home directory
  cp test/sqliterc ~/.sqliterc
  run bash -c "./pihole-FTL sqlite3 /etc/pihole/gravity.db \"SELECT value FROM info WHERE property = 'abp_domains';\""
  refute_line --index 0 "1"
  run bash -c "./pihole-FTL sqlite3 -ni /etc/pihole/gravity.db \"SELECT value FROM info WHERE property = 'abp_domains';\""
  assert_line --index 0 "1"
  rm ~/.sqliterc
}

@test "Embedded LUA engine is called for .lua file" {
  echo 'print("Hello from LUA")' > abc.lua
  run bash -c './pihole-FTL abc.lua'
  assert_line --index 0 "Hello from LUA"
  rm abc.lua
}

@test "Pi-hole PTR generation check" {
  run bash -c "bash test/hostnames.sh | tee ptr.log"
  refute_line --partial "ERROR"
}

@test "No missing config items in pihole.toml" {
  run bash -c 'grep "DEBUG_CONFIG: " /var/log/pihole/FTL.log'
  run bash -c 'grep "DEBUG_CONFIG: " /var/log/pihole/FTL.log | grep -c "DOES NOT EXIST"'
  assert_line --index 0 "0"
}

@test "Check dnsmasq warnings in source code" {
  run bash -c "bash test/dnsmasq_warnings.sh"
  refute_output
  
}

@test "Pi-hole use interface-dependent replies for pi.hole" {
  run bash -c "dig A pi.hole +short @127.0.0.1"
  assert_line --index 0 "127.0.0.1"

  run bash -c "dig AAAA pi.hole +short @127.0.0.1"
  assert_line --index 0 "::1"
}

@test "Pi-hole uses interface-dependent replies inside CNAME chains" {
  run bash -c "dig A pihole.mydomain.net +short @127.0.0.1"
  assert_line --index 0 "pi.hole."
  assert_line --index 1 "127.0.0.1"

  run bash -c "dig AAAA pihole.mydomain.net +short @127.0.0.1"
  assert_line --index 0 "pi.hole."
  assert_line --index 1 "::1"
}

@test "Pi-hole uses dns.reply.host.IPv4/6 for pi.hole" {
  # Set the reply for pi.hole to custom IPv4 and IPv6 addresses
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c 'curl -s -X PATCH http://127.0.0.1/api/config -d "{\"config\":{\"dns\":{\"reply\":{\"host\":{\"force4\":true,\"IPv4\":\"10.100.0.10\",\"force6\":true,\"IPv6\":\"fe80::10\"}}}}}"'

  # Wait for change to be applied
  run bash -c "./pihole-FTL wait-for 'INFO: Config file written to /etc/pihole/pihole.toml' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  run bash -c "dig A pi.hole +short @127.0.0.1"
  assert_line --index 0 "10.100.0.10"
  run bash -c "dig AAAA pi.hole +short @127.0.0.1"
  assert_line --index 0 "fe80::10"

  run bash -c "dig A pi.hole @127.0.0.1 | grep 'EDE: '"
  assert_line --partial --index 0 "EDE: 29: (synthesized)"
  assert_line --index 1 ""
  run bash -c "dig AAAA pi.hole @127.0.0.1 | grep 'EDE: '"
  assert_line --partial --index 0 "EDE: 29: (synthesized)"
  assert_line --index 1 ""
}

@test "Pi-hole uses dns.reply.host.IPv4/6 replies inside CNAME chains" {
  run bash -c "dig A pihole.mydomain.net +short @127.0.0.1"
  assert_line --index 0 "pi.hole."
  assert_line --index 1 "10.100.0.10"

  run bash -c "dig AAAA pihole.mydomain.net +short @127.0.0.1"
  assert_line --index 0 "pi.hole."
  assert_line --index 1 "fe80::10"
}

@test "Pi-hole uses dns.reply.host.IPv4/6 for hostname" {
  run bash -c "dig A $(hostname) +short @127.0.0.1"
  assert_line --index 0 "10.100.0.10"
  run bash -c "dig AAAA $(hostname) +short @127.0.0.1"
  assert_line --index 0 "fe80::10"

  run bash -c "dig A $(hostname) @127.0.0.1 | grep 'EDE: '"
  assert_line --partial --index 0 "EDE: 29: (synthesized)"
  assert_line --index 1 ""
  run bash -c "dig AAAA $(hostname) @127.0.0.1 | grep 'EDE: '"
  assert_line --partial --index 0 "EDE: 29: (synthesized)"
  assert_line --index 1 ""
}

@test "Pi-hole uses dns.reply.blocking.IPv4/6 for blocked domain" {
  run bash -c 'grep "mode = \"NULL\"" /etc/pihole/pihole.toml'
  assert_line --index 0 '    mode = "NULL"'

  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)

  run bash -c './pihole-FTL --config dns.blocking.mode IP'
 
  # Wait for change to become effective
  run bash -c "./pihole-FTL wait-for 'DEBUG_CONFIG: pihole.toml unchanged' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  run bash -c "kill -HUP $(cat /run/pihole-FTL.pid)"

  # Wait for change to become effective
  run bash -c "./pihole-FTL wait-for 'INFO: Compiled 2 allow and 11 deny regex for 11 clients' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  run bash -c 'grep "mode = \"IP" /etc/pihole/pihole.toml'
  assert_line --partial --index 0 'mode = "IP" ### CHANGED, default = "NULL"'

  run bash -c "dig A denied.ftl +short @127.0.0.1"
  assert_line --index 0 "10.100.0.11"

  run bash -c "dig AAAA denied.ftl +short @127.0.0.1"
  assert_line --index 0 "fe80::11"
}

@test "Antigravity domain is not blocked" {
  run bash -c "dig A antigravity.ftl +short @127.0.0.1"
  assert_line --index 0 "192.168.1.6"
}

@test "Antigravity ABP-domain is not blocked" {
  run bash -c "dig A x.y.z.abp.antigravity.ftl +short @127.0.0.1"
  assert_line --index 0 "192.168.1.7"
}

@test "Custom DNS records: Multiple domains per line are accepted" {
  run bash -c "dig A abc-custom.com +short @127.0.0.1"
  assert_line --index 0 "1.1.1.1"
  run bash -c "dig A def-custom.de +short @127.0.0.1"
  assert_line --index 0 "1.1.1.1"
}

@test "Zone update (non-query) is rejected with NOTIMP (UDP)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c "python3 test/zone_update.py udp"
  assert_line --index 0 "UDP response: NOTIMP"
  assert_line --index 1 ""

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"

  # Check for expected log lines
  assert_line --partial "new UDP IPv4 non-query[type=0] \"opcode\" from lo/127.0.0.1"
  assert_line --partial "**** got cache reply: opcode is (null) "
}

@test "Zone update (non-query) is rejected with NOTIMP (TCP)" {
  # Get number of lines in the log before the test
  before="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Run test command
  run bash -c "python3 test/zone_update.py tcp"
  assert_line --index 0 "TCP response: NOTIMP"
  assert_line --index 1 ""

  # Get number of lines in the log after the test
  after="$(grep -c ^ /var/log/pihole/FTL.log)"

  # Extract relevant log lines
  run bash -c "sed -n \"${before},${after}p\" /var/log/pihole/FTL.log"

  # Check for expected log lines
  assert_line --partial "new TCP IPv4 non-query[type=0] \"opcode\" from lo/127.0.0.1"
  assert_line --partial "**** got cache reply: opcode is (null) "
}

@test "Mixed-case DNS queries are returned in the same case" {
  run bash -c "dig AAAA AaaA.fTL @127.0.0.1"
  assert_line --regexp "AaaA.fTL.[[:space:]]+[[:digit:]]+[[:space:]]+IN[[:space:]]+AAAA[[:space:]]+fe80::1c01"
}

@test "Custom DNS records: International domains are converted to IDN form" {
  # äste.com ---> xn--ste-pla.com
  run bash -c "dig A xn--ste-pla.com +short @127.0.0.1"
  assert_line --index 0 "2.2.2.2"
  # steä.com -> xn--ste-sla.com
  run bash -c "dig A xn--ste-sla.com +short @127.0.0.1"
  assert_line --index 0 "2.2.2.2"
}

@test "Local CNAME records: International domains are converted to IDN form" {
  # brücke.com ---> xn--brcke-lva.com
  run bash -c "dig A xn--brcke-lva.com +short @127.0.0.1"
  # xn--ste-pla.com ---> äste.com
  assert_line --index 0 "xn--ste-pla.com."
  assert_line --index 1 "2.2.2.2"
}

@test "IDN2 CLI interface correctly encodes/decodes domain according to IDNA2008 + TR46" {
  run bash -c './pihole-FTL idn2 äste.com'
  assert_line --index 0 "xn--ste-pla.com"
  run bash -c './pihole-FTL idn2 -d xn--ste-pla.com'
  assert_line --index 0 "äste.com"
  run bash -c './pihole-FTL idn2 ß.de'
  assert_line --index 0 "xn--zca.de"
  run bash -c './pihole-FTL idn2 -d xn--zca.de'
  assert_line --index 0 "ß.de"
}

@test "Environmental variable is favored over config file" {
  # The config file has -10 but we set FTLCONF_misc_nice="-11"
  run bash -c 'grep "nice = -11" /etc/pihole/pihole.toml'
  assert_line --index 0 "  nice = -11 ### CHANGED (env), default = -10"
}

@test "Capitalized Environmental variable is used and favored over config file" {
  # The config file has 90 but we set FTLCONF_MISC_CHECK_SHMEM="91"
  run bash -c 'grep "shmem = 91" /etc/pihole/pihole.toml'
  assert_line --index 0 "    shmem = 91 ### CHANGED (env), default = 90"
}

@test "Correct number of environmental variables is logged" {
  grep "FTLCONF environment variables" /var/log/pihole/FTL.log
  run bash -c 'grep -q "5 FTLCONF environment variables found (2 used, 2 invalid, 1 ignored)" /var/log/pihole/FTL.log'
  assert_success
}

@test "Correct environmental variable is logged" {
  grep "FTLCONF_misc_nice" /var/log/pihole/FTL.log
  run bash -c 'grep -q "FTLCONF_misc_nice is used" /var/log/pihole/FTL.log'
  assert_success
}

@test "Invalid environmental variable is logged (type mismatch)" {
  grep "FTLCONF_debug_api" /var/log/pihole/FTL.log
  run bash -c 'grep -q "FTLCONF_debug_api is not a boolean, using default instead" /var/log/pihole/FTL.log'
  assert_success
}

@test "Invalid environmental variable is logged (validation failed)" {
  grep "FTLCONF_files_pcap" /var/log/pihole/FTL.log
  run bash -c 'grep -q "FTLCONF_files_pcap files.pcap: not a valid file path (\"\*123#./test/pcap\"), using default instead" /var/log/pihole/FTL.log'
  assert_success
}

@test "Unknown environmental variable is logged, a useful alternative is suggested" {
  grep "FTLCONF_dns_upstrrr" /var/log/pihole/FTL.log
  run bash -c 'grep -A1 "FTLCONF_dns_upstrrr is unknown" /var/log/pihole/FTL.log'
  assert_line --partial --index 0 "WARNING: [?] FTLCONF_dns_upstrrr is unknown, did you mean any of these?"
  assert_line --partial --index 1 "WARNING:     - FTLCONF_dns_upstreams"
}

@test "cJSON_GetErrorPtr and cJSON_InitHooks are never used (for thread-safety reasons)" {
  # cJSON_GetErrorPtr() is not thread-safe but can be replaces by cJSON_ParseWithOpts()
  # cJSON_InitHooks() is only thread-safe if used before any other cJSON function in a thread
  # We grep for the two functions recursively and exclude cJSON.{c,h} where they are defined
  run bash -c 'grep -rE "(cJSON_GetErrorPtr)|(cJSON_InitHooks)" src/ | grep -vE "^src/webserver/cJSON/cJSON."'
  refute_output
}

@test "CLI complains about unknown config key and offers a suggestion" {
  run bash -c './pihole-FTL --config dbg.all'
  assert_line --index 0 "Unknown config option dbg.all, did you mean:"
  assert_line --index 1 " - debug.all"
  assert_failure 4
  run bash -c './pihole-FTL --config misc.privacyLLL'
  assert_line --index 0 "Unknown config option misc.privacyLLL, did you mean:"
  assert_line --index 1 " - misc.privacylevel"
  assert_failure 4
}

@test "Changing a config option set forced by ENVVAR is not possible via the CLI" {
  run bash -c './pihole-FTL --config misc.nice -12'
  assert_line --index 0 "Config option misc.nice is read-only (set via environmental variable)"
  assert_failure 5
}

# NOTE: Envvar-protected config API test moved to pytest (test/api/test_api.py)

# We cannot easily test IPv6 as it may not be available in docker (CI)

# NOTE: API tests (search, history, lists, queries, Lua pages, auth)
# moved to pytest (test/api/test_api.py, test/api/test_z_auth.py)

@test "Config validation working on the CLI (type-based checking)" {
  run bash -c './pihole-FTL --config dns.port true'
  assert_line --index 0 'Config setting dns.port is invalid, allowed options are: unsigned integer (16 bit)'
  assert_failure 2

  run bash -c './pihole-FTL --config dns.revServers "abc"'
  assert_line --index 0 'Config setting dns.revServers is invalid: not valid JSON, error at: abc'
  assert_failure 2
}

# NOTE: API config validation tests moved to pytest (test/api/test_api.py)

@test "Config validation working on the CLI (validator-based checking)" {
  run bash -c './pihole-FTL --config dns.hosts "[\"111.222.333.444 abc\"]"'
  assert_line --index 0 'Invalid value: dns.hosts[0]: neither a valid IPv4 nor IPv6 address ("111.222.333.444")'
  assert_failure 3

  run bash -c './pihole-FTL --config dns.hosts "[\"1.1.1.1 cf\",\"8.8.8.8 google\",\"1.2.3.4\"]"'
  assert_line --index 0 'Invalid value: dns.hosts[2]: entry does not have at least one hostname ("1.2.3.4")'
  assert_failure 3

  run bash -c './pihole-FTL --config dns.revServers "[\"abc,def,ghi\"]"'
  assert_line --index 0 'Invalid value: dns.revServers[0]: <enabled> not a boolean ("abc")'
  assert_failure 3

  run bash -c './pihole-FTL --config dns.revServers "[\"true,abc,def,ghi\"]"'
  assert_line --index 0 'Invalid value: dns.revServers[0]: <ip-address> neither a valid IPv4 nor IPv6 address ("abc")'
  assert_failure 3

  run bash -c './pihole-FTL --config dns.revServers "[\"true,1.2.3.4/55,def,ghi\"]"'
  assert_line --index 0 'Invalid value: dns.revServers[0]: <prefix-len> not a valid IPv4 prefix length ("55")'
  assert_failure 3

  run bash -c './pihole-FTL --config dns.revServers "[\"true,::1/255,def,ghi\"]"'
  assert_line --index 0 'Invalid value: dns.revServers[0]: <prefix-len> not a valid IPv6 prefix length ("255")'
  assert_failure 3

  run bash -c './pihole-FTL --config dns.revServers "[\"true,1.1.1.1,def,ghi\"]"'
  assert_line --regexp --index 0 'New dnsmasq configuration is not valid \(.+resolve at line [[:digit:]]+ of /etc/pihole/dnsmasq.conf.temp: "rev-server=1.1.1.1,def"\), config remains unchanged'
  assert_failure 3

  run bash -c './pihole-FTL --config webserver.api.excludeClients "[\".*\",\"$$$\",\"[[[\"]"'
  assert_line --index 0 'Invalid value: webserver.api.excludeClients[2]: not a valid regex ("[[["): Missing '\'']'\'''
  assert_failure 3
}

@test "DNS hosts sanitization: Whitespace is normalized when saving" {
  # Set dns.hosts with various whitespace formatting issues
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c './pihole-FTL --config dns.hosts "[\"  192.168.1.1    host1.local  \", \"   10.0.0.1\\t\\thost2.local   host3.local\", \"127.0.0.1     host4.local\\t\\thost5.local\"]"'
  assert_success

  # Wait for change to become effective
  run bash -c "./pihole-FTL wait-for 'HOSTS file written to /etc/pihole/hosts/custom.list' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  # Check that the sanitized entries are properly formatted
  run bash -c './pihole-FTL --config dns.hosts'
  assert_line --index 0 '[ 192.168.1.1 host1.local, 10.0.0.1 host2.local host3.local, 127.0.0.1 host4.local host5.local ]'
}

@test "DNS hosts sanitization: Comments are handled correctly" { 
  # Set dns.hosts with entries containing comments
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c './pihole-FTL --config dns.hosts "[\"192.168.1.1   host1.local   # this is a comment with  double spaces\", \"   10.0.0.1\\thost2.local\\t\\t\\t\"]"'
  assert_success

  # Wait for change to become effective
  run bash -c "./pihole-FTL wait-for 'HOSTS file written to /etc/pihole/hosts/custom.list' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  # Check that the sanitized entries are properly formatted
  run bash -c './pihole-FTL --config dns.hosts'
  assert_line --index 0 '[ 192.168.1.1 host1.local # this is a comment with  double spaces, 10.0.0.1 host2.local ]'
}

# NOTE: API config validation, auth, Lua page tests moved to pytest
# (test/api/test_api.py, test/api/test_z_auth.py)

@test "CLI: Setting and removing password leaves no net change" {
  # Set password via CLI
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c './pihole-FTL --config webserver.api.password ABC'
  assert_success

  # Wait for the running FTL instance to pick up the config file change
  run bash -c "./pihole-FTL wait-for 'pihole.toml unchanged' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  # Verify login is required
  run bash -c 'curl -s 127.0.0.1/api/auth'
  assert_line --partial --index 0 '"valid":false'

  # Verify correct password works
  run bash -c 'curl -s -X POST 127.0.0.1/api/auth -d "{\"password\":\"ABC\"}" | jq .session.valid'
  assert_line --index 0 "true"

  # Remove password via CLI
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c './pihole-FTL --config webserver.api.password ""'
  assert_success

  # Wait for the running FTL instance to pick up the config file change
  run bash -c "./pihole-FTL wait-for 'pihole.toml unchanged' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  # Verify no login is required again
  run bash -c 'curl -s 127.0.0.1/api/auth'
  assert_line --partial --index 0 '"valid":true'
  assert_line --partial --index 0 '"no password set"'
}

@test "CLI: Setting password via stdin (--config <key> -) leaves no net change" {
  # Set password via stdin (value is piped, not in argv)
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "echo 'STDIN_PW' | ./pihole-FTL --config webserver.api.password -"
  assert_success

  # Wait for the running FTL instance to pick up the config file change
  run bash -c "./pihole-FTL wait-for 'pihole.toml unchanged' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  # Verify login is required
  run bash -c 'curl -s 127.0.0.1/api/auth'
  assert_line --partial --index 0 '"valid":false'

  # Verify the stdin-supplied password works
  run bash -c 'curl -s -X POST 127.0.0.1/api/auth -d "{\"password\":\"STDIN_PW\"}" | jq .session.valid'
  assert_line --index 0 "true"

  # Verify the password was never present in the long-running FTL
  # daemon's argv. The daemon was started without --config so its
  # cmdline should not contain the password.
  for pid in $(pidof pihole-FTL 2>/dev/null); do
    if [ -r "/proc/$pid/cmdline" ]; then
      ! tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q "STDIN_PW"
    fi
  done

  # Remove password via stdin (empty value)
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "echo '' | ./pihole-FTL --config webserver.api.password -"
  assert_success

  # Wait for the running FTL instance to pick up the config file change
  run bash -c "./pihole-FTL wait-for 'pihole.toml unchanged' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  # Verify no login is required again
  run bash -c 'curl -s 127.0.0.1/api/auth'
  assert_line --partial --index 0 '"valid":true'
  assert_line --partial --index 0 '"no password set"'
}

@test "CLI: Stdin --config rejects values longer than 4095 bytes" {
  # Generate a value that is exactly 4096 bytes (no newline within the
  # 4096-byte buffer means the value did not fit and would be silently
  # truncated). The CLI must refuse this with a non-zero exit code.
  run bash -c "python3 -c 'import sys; sys.stdout.write(\"a\"*4096)' | ./pihole-FTL --config webserver.api.password -"
  assert_failure
  assert_output --partial "too long"
}

@test "CLI: Stdin --config reads only the first line for multi-line input" {
  # For multi-line input, only the first line is consumed. The second
  # line ("SECOND_LINE") is dropped. We verify by piping "MULTI\nSECOND"
  # and confirming only "MULTI" was set.
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  run bash -c "printf 'MULTI\nSECOND_LINE\n' | ./pihole-FTL --config webserver.api.password -"
  assert_success

  # Wait for the running FTL instance to pick up the config file change
  run bash -c "./pihole-FTL wait-for 'pihole.toml unchanged' /var/log/pihole/FTL.log 5 $logsize_before"
  assert_success

  # Only the first line was used as the password
  run bash -c 'curl -s -X POST 127.0.0.1/api/auth -d "{\"password\":\"MULTI\"}" | jq .session.valid'
  assert_line --index 0 "true"

  # The second line was NOT used
  run bash -c 'curl -s -X POST 127.0.0.1/api/auth -d "{\"password\":\"SECOND_LINE\"}" | jq .session.valid'
  refute_line --index 0 "true"

  # Cleanup: remove the password
  run bash -c "./pihole-FTL --config webserver.api.password \"\""
  assert_success
}

@test "Test TLS/SSL server using self-signed certificate" {
  # -s: silent
  # -I: HEAD request
  # --cacert: use this CA certificate to verify the server certificate
  # --resolve: resolve pi.hole:443 to 127.0.0.1
  #            we need this line because curl is not using FTL as resolver
  #            and would otherwise not be able to resolve pi.hole
  run bash -c 'curl -sI --cacert /etc/pihole/test.crt --resolve pi.hole:443:127.0.0.1 https://pi.hole/'
  assert_line --partial --index 0 "HTTP/1.1 "
  run bash -c 'curl -I --cacert /etc/pihole/test.crt --resolve pi.hole:443:127.0.0.1 https://pi.hole/'
  assert_success
}

@test "X.509 certificate parser returns expected result" {
  # We are getting the certificate from the config
  run bash -c './pihole-FTL --read-x509'
  assert_line --index 0 "Reading certificate from /etc/pihole/test.pem ..."
  assert_line --index 1 "Certificate (X.509):"
  assert_line --index 2 "  cert. version     : 3"
  assert_line --index 3 "  serial number     : 36:36:32:32:35:31:37:36:30:30:39:31:30:30:37"
  assert_line --index 4 "  issuer name       : CN=pi.hole, O=Pi-hole, C=DE"
  assert_line --index 5 "  subject name      : CN=pi.hole"
  assert_line --index 6 "  issued  on        : 2023-01-16 21:15:12"
  assert_line --index 7 "  expires on        : 2053-01-16 21:15:12"
  assert_line --index 8 "  signed using      : ECDSA with SHA256"
  assert_line --index 9 "  EC key size       : 384 bits"
  assert_line --index 10 "  basic constraints : CA=false"
  assert_line --index 11 "  subject alt name  :"
  assert_line --index 12 "      dNSName : pi.hole"
  assert_line --index 13 "Public key (PEM):"
  assert_line --index 14 "-----BEGIN PUBLIC KEY-----"
  assert_line --index 15 "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuH7sWfGRkvm5s5LVYTwbM6PjZmuK4KPh"
  assert_line --index 16 "A5qaWfVqJw4jeEMkvyT4CKtiruLEBcqzimkBhP6dlMOUM/K0caRC5Jm46fMC9bV3"
  assert_line --index 17 "74ibYXxiX4bkiu8m/GDjM5RgiS1D1x+U"
  assert_line --index 18 "-----END PUBLIC KEY-----"
  assert_line --index 19 ""
}

@test "X.509 certificate parser returns expected result (with private key)" {
  # We are explicitly specifying the certificate file here
  run bash -c './pihole-FTL --read-x509-key /etc/pihole/test.pem'
  [[ "${lines[0]}"  == "Reading certificate from /etc/pihole/test.pem ..." ]]
  [[ "${lines[1]}"  == "Certificate (X.509):" ]]
  [[ "${lines[2]}"  == "  cert. version     : 3" ]]
  [[ "${lines[3]}"  == "  serial number     : 36:36:32:32:35:31:37:36:30:30:39:31:30:30:37" ]]
  [[ "${lines[4]}"  == "  issuer name       : CN=pi.hole, O=Pi-hole, C=DE" ]]
  [[ "${lines[5]}"  == "  subject name      : CN=pi.hole" ]]
  [[ "${lines[6]}"  == "  issued  on        : 2023-01-16 21:15:12" ]]
  [[ "${lines[7]}"  == "  expires on        : 2053-01-16 21:15:12" ]]
  [[ "${lines[8]}"  == "  signed using      : ECDSA with SHA256" ]]
  [[ "${lines[9]}"  == "  EC key size       : 384 bits" ]]
  [[ "${lines[10]}" == "  basic constraints : CA=false" ]]
  [[ "${lines[11]}" == "  subject alt name  :" ]]
  [[ "${lines[12]}" == "      dNSName : pi.hole" ]]
  [[ "${lines[13]}" == "Private key:" ]]
  [[ "${lines[14]}" == "  ID: 0" ]]
  [[ "${lines[15]}" == "  Keysize: 384 bits" ]]
  [[ "${lines[16]}" == "  Algorithm: 151126016" ]]
  [[ "${lines[17]}" == "  Lifetime: 0" ]]
  [[ "${lines[18]}" == "  Type: ECC (key pair)" ]]
  [[ "${lines[19]}" == "  Curvetype: SEC random curve over prime fields (secp384r1)" ]]
  [[ "${lines[20]}" == "Private key (PEM):" ]]
  [[ "${lines[21]}" == "-----BEGIN EC PRIVATE KEY-----" ]]
  [[ "${lines[22]}" == "MIGkAgEBBDBGWIbQ11v8sQjrlj+KUS7OJoR0M9xyZyMLhkejtXlHGNXn2lK8ZzPW" ]]
  [[ "${lines[23]}" == "UUA6+ZqgdA+gBwYFK4EEACKhZANiAAS4fuxZ8ZGS+bmzktVhPBszo+Nma4rgo+ED" ]]
  [[ "${lines[24]}" == "mppZ9WonDiN4QyS/JPgIq2Ku4sQFyrOKaQGE/p2Uw5Qz8rRxpELkmbjp8wL1tXfv" ]]
  [[ "${lines[25]}" == "iJthfGJfhuSK7yb8YOMzlGCJLUPXH5Q=" ]]
  [[ "${lines[26]}" == "-----END EC PRIVATE KEY-----" ]]
  [[ "${lines[27]}" == "Public key (PEM):" ]]
  [[ "${lines[28]}" == "-----BEGIN PUBLIC KEY-----" ]]
  [[ "${lines[29]}" == "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEuH7sWfGRkvm5s5LVYTwbM6PjZmuK4KPh" ]]
  [[ "${lines[30]}" == "A5qaWfVqJw4jeEMkvyT4CKtiruLEBcqzimkBhP6dlMOUM/K0caRC5Jm46fMC9bV3" ]]
  [[ "${lines[31]}" == "74ibYXxiX4bkiu8m/GDjM5RgiS1D1x+U" ]]
  [[ "${lines[32]}" == "-----END PUBLIC KEY-----" ]]
  [[ "${lines[33]}" == "" ]]
}

@test "X.509 certificate parser can check if domain is included" {
  run bash -c './pihole-FTL --read-x509-key /etc/pihole/test.pem pi.hole'
  assert_line --index 0 "Reading certificate from /etc/pihole/test.pem ..."
  assert_line --index 1 "Certificate matches domain pi.hole"
  assert_line --index 2 ""
  assert_success
  run bash -c './pihole-FTL --read-x509-key /etc/pihole/test.pem pi-hole.net'
  assert_line --index 0 "Reading certificate from /etc/pihole/test.pem ..."
  assert_line --index 1 "Certificate does not match domain pi-hole.net"
  assert_line --index 2 ""
  assert_failure
}

@test "Test embedded GZIP compressor" {
  run bash -c './pihole-FTL gzip test/pihole-FTL.db.sql'
  assert_success
  assert_line --index 0 "Compressed test/pihole-FTL.db.sql (2.0kB) to test/pihole-FTL.db.sql.gz (689.0B), 66.0% size reduction"
  run bash -c './pihole-FTL gzip test/pihole-FTL.db.sql.gz test/pihole-FTL.db.sql.1'
  assert_success
  assert_line --index 0 "Uncompressed test/pihole-FTL.db.sql.gz (677.0B) to test/pihole-FTL.db.sql.1 (2.0kB), 199.3% size increase"
  run bash -c 'gzip -dkc test/pihole-FTL.db.sql.gz > test/pihole-FTL.db.sql.2'
  assert_success
  run bash -c 'rm test/pihole-FTL.db.sql.gz'
  assert_success
  run bash -c 'cmp test/pihole-FTL.db.sql test/pihole-FTL.db.sql.1'
  assert_success
  run bash -c 'cmp test/pihole-FTL.db.sql test/pihole-FTL.db.sql.2'
  assert_success
  run bash -c 'rm test/pihole-FTL.db.sql.[1-2]'
  assert_success
}

@test "TAR parser regression harness" {
  run ./tar_regression
  assert_success
}

@test "GZIP parser regression harness" {
  run ./gzip_regression
  assert_success
}

@test "SHA256 checksum working" {
  run bash -c './pihole-FTL sha256sum test/test.pem'
  assert_line --index 0 "ce4c01340ef46bf3bc26831f7c53763d57c863528826aa795f1da5e16d6e7b2d  test/test.pem"
}

@test "Internal IP -> name resolution works (UDP IPv4)" {
  run bash -c "./pihole-FTL ptr 127.0.0.1 | tail -n1"
  assert_line --index 0 "localhost"
}

@test "Internal IP -> name resolution works (UDP IPv6)" {
  run bash -c "./pihole-FTL ptr ::1 | tail -n1"
  assert_line --index 0 "localhost"
}

@test "Internal IP -> name resolution works (TCP IPv4)" {
  run bash -c "./pihole-FTL ptr 127.0.0.1 tcp | tail -n1"
  assert_line --index 0 "localhost"
}

@test "Internal IP -> name resolution works (TCP IPv6)" {
  run bash -c "./pihole-FTL ptr ::1 tcp | tail -n1"
  assert_line --index 0 "localhost"
}

@test "Create, verify and re-import Teleporter file via CLI" {
  run bash -c './pihole-FTL --teleporter'
  assert_success
  # Get filename from last line printed by FTL
  filename="${lines[-1]}"
#  run bash -c 'zipinfo ${filename}'
#  printf "%s\n" "${lines[@]}"
#  assert_success
  run bash -c "./pihole-FTL --teleporter ${filename}"
  assert_line --index -9 "Imported etc/pihole/pihole.toml"
  assert_line --index -8 "Imported etc/pihole/dhcp.leases"
  assert_line --index -7 "Imported etc/pihole/gravity.db->group"
  assert_line --index -6 "Imported etc/pihole/gravity.db->adlist"
  assert_line --index -5 "Imported etc/pihole/gravity.db->adlist_by_group"
  assert_line --index -4 "Imported etc/pihole/gravity.db->domainlist"
  assert_line --index -3 "Imported etc/pihole/gravity.db->domainlist_by_group"
  assert_line --index -2 "Imported etc/pihole/gravity.db->client"
  assert_line --index -1 "Imported etc/pihole/gravity.db->client_by_group"
  assert_success
  run bash -c "rm ${filename}"
}

# NOTE: Config file rotation count test moved to test_final.bats

@test "Suggest expected completions" {
  run bash -c './pihole-FTL --complete pihole-FTL versio'
  assert_line --index 0 "version"
  assert_line --index 1 ""
  run bash -c './pihole-FTL --complete pihole-FTL --config debug.ne'
  assert_line --index 0 "debug.networking"
  assert_line --index 1 "debug.netlink"
  assert_line --index 2 ""
  run bash -c './pihole-FTL --complete pihole-FTL --config debug.networking t'
  assert_line --index 0 "true"
  assert_line --index 1 ""
}


@test "Webserver options are logged as expected" {
  run bash -c 'grep -F "Webserver option 0/12: document_root=/var/www/html" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 1/12: error_pages=/var/www/html/admin/" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 2/12: listening_ports=80o,443os,[::]:80o,[::]:443os" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 3/12: decode_url=yes" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 4/12: enable_directory_listing=no" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 5/12: num_threads=50" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 6/12: authentication_domain=pi.hole" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 7/12: additional_header=X-DNS-Prefetch-Control: off\r\nContent-Security-Policy: default-src '"'none'"'; connect-src '"'self'"'; font-src '"'self'"'; frame-ancestors '"'none'"'; img-src '"'self'"'; manifest-src '"'self'"'; script-src '"'self'"'; style-src '"'self'"' '"'unsafe-inline'"'; form-action '"'self'"'\r\nX-Frame-Options: DENY\r\nX-XSS-Protection: 0\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: strict-origin-when-cross-origin\r\n" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 8/12: index_files=index.html,index.htm,index.lp" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 9/12: enable_keep_alive=yes" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 10/12: keep_alive_timeout_ms=5000" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 11/12: ssl_certificate=/etc/pihole/test.pem" /var/log/pihole/FTL.log'
  assert_success
  run bash -c 'grep -F "Webserver option 12/12: <END OF OPTIONS>" /var/log/pihole/FTL.log'
  assert_success
}

# NOTE: FTL termination test moved to run.sh (runs after both BATS and pytest)
