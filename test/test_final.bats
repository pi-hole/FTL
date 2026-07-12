#!/usr/bin/env bats
# Final log validation and FTL termination tests.
# This file runs AFTER both test_suite.bats and the pytest API tests
# to catch any unexpected log messages produced during the entire run.

# Load BATS libraries for enhanced testing capabilities
bats_load_library 'bats-support'
bats_load_library 'bats-assert'
load 'bats_helper.bash'

@test "No WARNING messages in FTL.log (besides known warnings)" {
  run bash -c 'grep "WARNING:" /var/log/pihole/FTL.log | grep -v -E "CAP_NET_ADMIN|CAP_NET_RAW|CAP_SYS_NICE|CAP_IPC_LOCK|CAP_CHOWN|CAP_NET_BIND_SERVICE|CAP_SYS_TIME|FTLCONF_|(negative DS reply without NS record received for )|(nameserver 127.0.0.1 refused to do a recursive query)|API: Config item is invalid|API: Config item validation failed|API: Not found|API: Config items set via environment variables|API: Rate-limiting login attempts|API: You need to specify both|API: No request body data|API: Invalid request|API: Rate-limiting 2FA token requests|2FA code has already been used|API: Reused 2FA token"'
  refute_output
}

@test "No ERROR messages in FTL.log (besides known/intended errors)" {
  run bash -c 'grep "ERROR: " /var/log/pihole/FTL.log | grep -v -E "(index\.html)|(Failed to create shared memory object)|(FTLCONF_debug_api is not a boolean)|(FTLCONF_files_pcap)|(Failed to set|adjust time during NTP sync: Insufficient permissions)|(nlrequest error)|(Failed to read ARP cache)"'
  refute_output
}

@test "No CRIT messages in FTL.log (besides error due to starting FTL more than once)" {
  run bash -c 'grep "CRIT:" /var/log/pihole/FTL.log | grep -v "CRIT: pihole-FTL is already running"'
  refute_output
}

@test "No \"DB not available\" messages in FTL.log" {
  run bash -c 'grep -c "database not available" /var/log/pihole/FTL.log'
  assert_line --index 0 "0"
}

@test "Expected number of config file rotations" {
  # BATS:   1x pihole.toml write (dns.reply.host API PATCH)
  # BATS:   2x pihole.toml writes (CLI password set/remove processes)
  # pytest: 3x pihole.toml writes (password, app_pwhash, serve_all via API)
  # pytest: 2x pihole.toml writes (dns/hosts config array PUT + DELETE)
  # pytest: 2x pihole.toml writes (dns/blocking disable + enable)
  # pytest: 4x pihole.toml writes (config PATCH round-trips: bool + int, change + restore each)
  # pytest: 2x pihole.toml writes (auth stress test password set + remove)
  # pytest: 2x pihole.toml writes (TOTP stress test secret set + remove)
  # pytest: 2x pihole.toml writes (auth security test password set + remove)
  # pytest: 2x pihole.toml writes (auth security test TOTP secret set + remove)
  # dotdoh.bats: 2x pihole.toml writes (encrypted setup + plaintext teardown)
  run bash -c 'grep -c "INFO: Config file written to /etc/pihole/pihole.toml" /var/log/pihole/FTL.log'
  printf "pihole.toml write count: %s\n" "${lines[0]}"
  # On RISCV64, pytest is skipped (too slow), so only BATS writes occur
  if [[ "${CI_ARCH}" == "linux/riscv64" ]]; then
      assert_line --index 0 "3"
  else
    [[ ${lines[0]} == "24" ]]
  fi
  # CLI password set/remove trigger inotify reload but result in
  # "pihole.toml unchanged" as the in-memory config already matches
  run bash -c 'grep -c "pihole.toml unchanged" /var/log/pihole/FTL.log'
  printf "pihole.toml unchanged count: %s\n" "${lines[0]}"
  [[ ${lines[0]} -ge 2 ]]
  assert_success
  run bash -c 'grep -c "DEBUG_CONFIG: Config file written to /etc/pihole/dnsmasq.conf" /var/log/pihole/FTL.log'
  printf "dnsmasq.conf write count: %s\n" "${lines[0]}"
  assert_line --index 0 "3"
  run bash -c 'grep -c "DEBUG_CONFIG: HOSTS file written to /etc/pihole/hosts/custom.list" /var/log/pihole/FTL.log'
  printf "custom.list write count: %s\n" "${lines[0]}"
  # On RISCV64, pytest is skipped, so only BATS writes occur (3x)
  # Otherwise, pytest dns/hosts config array PUT + DELETE add 2 more (5x)
  if [[ "${CI_ARCH}" == "linux/riscv64" ]]; then
    assert_line --index 0 "3"
  else
    assert_line --index 0 "5"
  fi
}

@test "Query with ID 0 has been saved to the database" {
  # FTL exports queries from in-memory DB to disk after a configurable
  # delay (default 30s). Poll up to 60s for the export to complete.
  for i in $(seq 1 30); do
    run bash -c './pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db "SELECT COUNT(*) FROM queries WHERE id=0;"'
    if [[ ${lines[0]} == "1" ]]; then
      break
    fi
    sleep 2
  done
  assert_line --index 0 "1"
}

@test "FTL terminates with message" {
  logsize_before=$(stat -c%s /var/log/pihole/FTL.log)
  # Kill pihole-FTL after having completed all tests
  pid=$(cat /run/pihole-FTL.pid)
  printf "Killing pihole-FTL with PID %s\n" "$pid"

  run bash -c "kill $pid"
  assert_success

  # Wait until pihole-FTL has terminated
  run bash -c "./pihole-FTL wait-for '########## FTL terminated after' /var/log/pihole/FTL.log 30 $logsize_before"
  assert_success
}

@test "Shutdown reason logged at INFO level (#2818)" {
  # Verify the shutdown path now logs at INFO level instead of DEBUG-only
  run bash -c 'grep "INFO: Shutting down (exit code" /var/log/pihole/FTL.log'
  assert_success
}

@test "SIGTERM source re-logged near final termination message (#2818)" {
  # Verify the SIGTERM sender is re-logged during cleanup so it appears
  # near the "FTL terminated" message even in truncated logs
  run bash -c 'grep "INFO: Terminated by" /var/log/pihole/FTL.log'
  assert_success

  # Verify ordering: "Terminated by" must appear AFTER "Shutting down" and
  # BEFORE the final "FTL terminated" message
  run bash -c 'grep -n "Shutting down (exit code\|Terminated by\|FTL terminated after" /var/log/pihole/FTL.log | tail -3'
  assert_line --partial --index 0 "Shutting down (exit code"
  assert_line --partial --index 1 "Terminated by"
  assert_line --partial --index 2 "FTL terminated after"
}
