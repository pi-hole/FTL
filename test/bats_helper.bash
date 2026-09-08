#!/usr/bin/env bats
# shellcheck disable=SC2154  # Disable warning about unreferenced variables

# In case of test failure post the whole output of the run command
bats::on_failure() {
    printf "\n"
    printf "═══════════════════════════════════════════════════════════════════════════════\n"
    printf "                              BATS TEST FAILURE DEBUG                         \n"
    printf "═══════════════════════════════════════════════════════════════════════════════\n"
    printf "\n"
    printf "   TEST DESCRIPTION:\n"
    printf "   %s\n" "${BATS_TEST_DESCRIPTION}"
    printf "\n"
    printf "   COMMAND EXECUTED:\n"
    printf "   %s\n" "${BATS_RUN_COMMAND}"
    printf "\n"
    printf "   OUTPUT CAPTURED:\n"

    printf "   %s\n" "${output}"
    printf "\n"
    printf "═══════════════════════════════════════════════════════════════════════════════\n"
    printf "\n"
}

# --- log_lines() ----------------------------------------------------------------
#
# Count lines in a log file after the asynchronous logger has caught up.
# FTL's logger thread drains records to the log files a short moment after a
# producer has emitted them, so a naive instant `grep -c` right after an
# action can momentarily miss the very last records and make a test flaky
# (especially under CI load).  log_lines() samples the size of the log until
# it has stopped growing, then greps its contents.
#
# Usage: log_lines [<grep-pattern...>] <file>
#   - <file> is always the last argument
#   - with a pattern, print the number of matching lines (like `grep -c`)
#   - without a pattern, print the total number of lines
#
# Exported so `run bash -c 'log_lines ...'` subshells can use it.
log_lines() {
    local file="${@: -1}"
    local pattern=("${@:1:$#-1}")
    local prev=-1 cur=0 i
    for i in $(seq 1 50); do
        cur="$(grep -c ^ "$file")"
        if [ "$cur" = "$prev" ]; then
            break
        fi
        prev="$cur"
        sleep 0.02
    done
    if [ ${#pattern[@]} -eq 0 ]; then
        printf '%s\n' "$cur"
    else
        grep -c "${pattern[@]}" "$file"
    fi
}
export -f log_lines
