#!/usr/bin/env bats

# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# pi.hole/<hostname> reply tests on a multi-homed host
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

# These tests verify that pi.hole/<hostname> is answered with ALL usable
# addresses of the interface a query arrived on (#2996), independent of which
# of its addresses was queried and consistent across them - instead of one
# arbitrary pre-picked address. Two dummy interfaces are created:
#
#   ftlsrv0: 192.168.249.1/24, 192.168.249.2/24, 10.99.0.1/24,
#            fd43:998::1/64 (+ the kernel's automatic fe80:: link-local)
#   ftlcli0: 192.168.249.77/24                                 (client side)
#
# Querying pi.hole from 192.168.249.77 must return every server address of
# the queried family on ftlsrv0 - including the one in the unrelated
# 10.99.0.0/24, because routing decisions are the client's job - and never a
# loopback address. The IPv6 answer must contain the ULA but not the
# link-local address (clients cannot use it without a zone identifier). The
# tests are skipped when dummy interfaces cannot be created (missing
# privileges).

bats_load_library 'bats-support'
bats_load_library 'bats-assert'

SRV="ftlsrv0"
CLI="ftlcli0"

setup() {
  # Creating dummy interfaces needs CAP_NET_ADMIN
  if ! ip link show "$SRV" &>/dev/null; then
    if ! ip link add "$SRV" type dummy 2>/dev/null; then
      skip "cannot create dummy interfaces (no CAP_NET_ADMIN?)"
    fi
    ip addr add 192.168.249.1/24 dev "$SRV"
    ip addr add 192.168.249.2/24 dev "$SRV"
    ip addr add 10.99.0.1/24 dev "$SRV"
    ip addr add fd43:998::1/64 dev "$SRV"
    ip link set "$SRV" up
    # Give dnsmasq time to pick the new addresses up through its netlink listener
    sleep 3
  fi
  if ! ip link show "$CLI" &>/dev/null; then
    if ! ip link add "$CLI" type dummy 2>/dev/null; then
      ip link del "$SRV" 2>/dev/null || true
      skip "cannot create dummy interfaces (no CAP_NET_ADMIN?)"
    fi
    ip addr add 192.168.249.77/24 dev "$CLI"
    ip link set "$CLI" up
    sleep 3
  fi
}

teardown() {
  # Removing the interfaces makes dnsmasq drop their addresses again (and
  # restores the single-homed state the other test files expect)
  ip link del "$SRV" 2>/dev/null || true
  ip link del "$CLI" 2>/dev/null || true
  sleep 1
}

@test "pi.hole A: reply contains all addresses of the queried interface" {
  run bash -c "dig -b 192.168.249.77 @192.168.249.1 +short +time=2 +tries=1 A pi.hole"
  assert_success
  assert_equal "${#lines[@]}" 3
  assert_line "192.168.249.1"
  assert_line "192.168.249.2"
  assert_line "10.99.0.1"
}

@test "pi.hole A: identical reply no matter which interface address is asked" {
  run bash -c "dig -b 192.168.249.77 @10.99.0.1 +short +time=2 +tries=1 A pi.hole"
  assert_success
  assert_equal "${#lines[@]}" 3
  assert_line "192.168.249.1"
  assert_line "192.168.249.2"
  assert_line "10.99.0.1"
}

@test "pi.hole A: loopback never leaks into multi-homed replies" {
  run dig -b 192.168.249.77 @192.168.249.1 +short +time=2 +tries=1 A pi.hole
  assert_success
  refute_line --regexp "^127\."
}

@test "pi.hole AAAA: ULA answered, link-local excluded" {
  run bash -c "dig -b 192.168.249.77 @192.168.249.1 +short +time=2 +tries=1 AAAA pi.hole"
  assert_success
  assert_equal "${#lines[@]}" 1
  assert_line "fd43:998::1"
  refute_line --regexp "^fe80:"
}

@test "pi.hole ANY: cross-family answer carries all IPv4 interface addresses" {
  run bash -c "dig -b 192.168.249.77 @192.168.249.1 +time=2 +tries=1 ANY pi.hole | grep -E 'IN.*(A|AAAA)[[:space:]]' "
  assert_success
  assert_line --regexp "IN[[:space:]]+A[[:space:]]+192\.168\.249\.1"
  assert_line --regexp "IN[[:space:]]+A[[:space:]]+192\.168\.249\.2"
  assert_line --regexp "IN[[:space:]]+A[[:space:]]+10\.99\.0\.1"
}
