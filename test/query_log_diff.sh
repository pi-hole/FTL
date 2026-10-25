#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine - auxiliary files
# Differential test of /api/queries, see query_log_diff.py. Runs the given
# pihole-FTL on ports of its own with its files in <dir>: once to create the
# database, then on the fixture without and with exclusion regexes. FTL still
# reads /etc/pihole, so this runs in a fresh container or in the test suite
# (QUERY_LOG_DIFF_SUITE=1), as root or as QUERY_LOG_DIFF_USER
#
# Usage: query_log_diff.sh <pihole-FTL> [<dir>] [--strict-names]
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

ftl=$(readlink -f "$1")
shift
dir=/tmp/query-log-diff
if [[ $# -gt 0 && -n "$1" && "$1" != -* ]]; then
  dir=$1
  shift
fi
here=$(dirname "$(readlink -f "$0")")
port=${QUERY_LOG_DIFF_PORT:-8099}
user=${QUERY_LOG_DIFF_USER:-$(id -un)}

if [[ ! -f "${ftl}" || ! -x "${ftl}" || $# -gt 1 || ($# -eq 1 && "$1" != --strict-names) ]]; then
  echo "Usage: $0 <pihole-FTL> [<dir>] [--strict-names]" >&2
  exit 2
fi
# FTL reads /etc/pihole/pihole.toml, what it sets up (DHCP, dnsmasq lines,
# ...) would run here too. Only the suite's and our own are used. Nor does it
# run next to an installation of v5, which is not migrated once pihole.toml
# exists
if [[ ! -f /etc/pihole/query-log-diff.created && "${QUERY_LOG_DIFF_SUITE}" != 1 ]]; then
  for f in pihole.toml setupVars.conf pihole-FTL.conf gravity.db; do
    if [[ -e "/etc/pihole/${f}" ]]; then
      echo "/etc/pihole/${f} exists, run this in a fresh container" >&2
      exit 2
    fi
  done
fi
if [[ -e "${dir}" && ! -f "${dir}/FTL.create.log" ]]; then
  echo "${dir} exists and is not from an earlier run, not removing it" >&2
  exit 2
fi

# Only the variables below apply, not those of the caller (the suite sets some)
unset "${!FTLCONF_@}"
# FTL applies FTLCONF_ variables on top of a config file only
if [[ ! -f /etc/pihole/pihole.toml ]]; then
  mkdir -p /etc/pihole && "${ftl}" --config misc.privacylevel 0 > /dev/null && touch /etc/pihole/query-log-diff.created
fi
rm -rf "${dir:?}"
mkdir -p "${dir}"
touch "${dir}"/FTL.{create,main,excludes,live1,live2,stored}.log
chown -R "${user}" "${dir}"

# <log> <excludeDomains> <excludeClients>: start FTL and wait for the import.
# Nothing else adds queries: no DNS clients, no name or NTP lookups. With
# misc.readOnly, FTL does not write these variables into pihole.toml. The
# live queries further down add ${live_env[@]} and set ${privacy}
pid=
log=
upstream=
live_env=()
start_ftl() {
  local cmd
  log=$1
  cmd=$(printf '%q ' env FTLCONF_files_database="${dir}/pihole-FTL.db" FTLCONF_files_log_ftl="$1" \
    FTLCONF_files_log_webserver="${dir}/webserver.log" FTLCONF_files_log_dnsmasq="${dir}/pihole.log" \
    FTLCONF_dns_port=5399 FTLCONF_webserver_port="127.0.0.1:${port}" FTLCONF_webserver_api_password= \
    FTLCONF_webserver_api_maxHistory=86400 FTLCONF_database_DBimport=true FTLCONF_dns_ignoreLocalhost=false \
    FTLCONF_misc_privacylevel="${privacy:-0}" FTLCONF_database_network_parseARPcache=false FTLCONF_ntp_ipv4_active=false \
    FTLCONF_resolver_resolveIPv4=false FTLCONF_resolver_resolveIPv6=false FTLCONF_resolver_networkNames=false \
    FTLCONF_ntp_ipv6_active=false FTLCONF_ntp_sync_active=false FTLCONF_webserver_api_excludeDomains="$2" \
    FTLCONF_webserver_api_excludeClients="$3" FTLCONF_misc_readOnly=true FTLCONF_dhcp_active=false \
    FTLCONF_misc_etc_dnsmasq_d=false "${live_env[@]}" "${ftl}")
  if [[ "${user}" == "$(id -un)" ]]; then bash -c "${cmd}"; else su "${user}" -s /bin/bash -c "${cmd}"; fi
  "${ftl}" wait-for "queries from the long-term database" "$1" 30 0 > /dev/null
  local ret=$?
  # Not the PID file: it is another FTL's when this one found it running
  pid=$(sed -n 's/.*PID of FTL process: \([0-9]*\).*/\1/p' "$1" | tail -n 1)
  [[ ${ret} -eq 0 ]] && return
  echo "FTL did not import the database within 30 s, the end of $1:"
  tail -n 20 "$1"
  return 1
}

# Until the process is gone, at most 30 s: its last acts are the final export
# to the database and the termination line at the end of its log
stop_ftl() {
  kill "${pid}" || return 1
  local i
  for i in $(seq 1 300); do
    [[ -d "/proc/${pid}" && "$(cut -d' ' -f3 "/proc/${pid}/stat" 2> /dev/null)" != Z ]] || break
    sleep 0.1
  done
  tail -c 65536 "$1" | grep -q "########## FTL terminated after" && pid= && log=
}

# On every exit, also Ctrl-C or kill: the FTL started last, also while it is
# still starting, found by the PIDs it logs at the start (before and after it
# forks), and the upstream
cleanup() {
  local p name
  name=$(basename "${ftl}" | cut -c1-15)
  for p in $( (echo "${pid}"; [[ -n "${log}" ]] && head -c 1048576 "${log}" |
                sed -n 's/.*PID of FTL process: \([0-9]*\).*/\1/p') | sort -u); do
    [[ "$(cat "/proc/${p}/comm" 2> /dev/null)" == "${name}" ]] && kill "${p}" 2> /dev/null
  done
  [[ -n "${upstream}" ]] && kill "${upstream}" 2> /dev/null
}
trap cleanup EXIT

start_ftl "${dir}/FTL.create.log" "" "" && stop_ftl "${dir}/FTL.create.log" || exit 1
cp "${dir}/pihole-FTL.db" "${dir}/empty.db" || exit 1
python3 "${here}/query_log_diff.py" generate "${dir}/pihole-FTL.db" && chown -R "${user}" "${dir}" || exit 1

ret=0
start_ftl "${dir}/FTL.main.log" "" "" || exit 1
python3 "${here}/query_log_diff.py" compare "http://127.0.0.1:${port}" "$@" || ret=1
python3 "${here}/query_log_diff.py" paging "http://127.0.0.1:${port}" "$@" || ret=1
stop_ftl "${dir}/FTL.main.log" || exit 1

# The same requests once more, with rows left out by exclusion regexes. They
# are matched without case, and with --strict-names against client names too
clients='^10\.0\.0\.5$;^fe80:'
[[ "$1" == --strict-names ]] && clients="${clients};^printer\.lan$"
start_ftl "${dir}/FTL.excludes.log" '(^|\.)EXAMPLE\.org$;_' "${clients}" || exit 1
python3 "${here}/query_log_diff.py" compare "http://127.0.0.1:${port}" --excludes "$@" || ret=1
stop_ftl "${dir}/FTL.excludes.log" || exit 1

# A fixture with every timestamp in ID order, where the time order is read
# straight off the queries array. Then live queries at privacy levels 1 and 2
# on top: blocked by the test gravity database, answered locally, or
# forwarded to an upstream that answers one name with a CNAME to a blocked
# domain and the others never. Their rows from memory are compared with the
# database after the next start, FTL stores everything when it exits
cp "${dir}/empty.db" "${dir}/pihole-FTL.db" || exit 1
python3 "${here}/query_log_diff.py" generate "${dir}/pihole-FTL.db" --in-order || exit 1
"${ftl}" sqlite3 "${dir}/gravity.db" < "${here}/gravity.db.sql" > /dev/null && chown -R "${user}" "${dir}" || exit 1
python3 "${here}/query_log_diff.py" upstream 5398 > "${dir}/upstream.out" 2>&1 &
upstream=$!
for i in $(seq 1 50); do grep -q ready "${dir}/upstream.out" && break; sleep 0.1; done
grep -q ready "${dir}/upstream.out" || { echo "The upstream on 127.0.0.1#5398 did not start:"; cat "${dir}/upstream.out"; exit 1; }
# Without DNSSEC, which would add queries of its own to the upstream
live_env=(FTLCONF_files_gravity="${dir}/gravity.db" FTLCONF_dns_upstreams=127.0.0.1#5398
          "FTLCONF_dns_hosts=192.168.1.50 local-a.lan;192.168.1.51 local-b.lan"
          FTLCONF_dns_dnssec=false FTLCONF_dns_showDNSSEC=false)
privacy=1 start_ftl "${dir}/FTL.live1.log" "" "" || exit 1
python3 "${here}/query_log_diff.py" time-order "http://127.0.0.1:${port}" || ret=1
python3 "${here}/query_log_diff.py" live "http://127.0.0.1:${port}" 5399 "${dir}/live1.json" || ret=1
stop_ftl "${dir}/FTL.live1.log" || exit 1
privacy=2 start_ftl "${dir}/FTL.live2.log" "" "" || exit 1
python3 "${here}/query_log_diff.py" stored "http://127.0.0.1:${port}" "${dir}/live1.json" || ret=1
python3 "${here}/query_log_diff.py" live "http://127.0.0.1:${port}" 5399 "${dir}/live2.json" || ret=1
stop_ftl "${dir}/FTL.live2.log" || exit 1
start_ftl "${dir}/FTL.stored.log" "" "" || exit 1
python3 "${here}/query_log_diff.py" stored "http://127.0.0.1:${port}" "${dir}/live2.json" || ret=1
stop_ftl "${dir}/FTL.stored.log" || exit 1

exit ${ret}
