#!./test/libs/bats/bin/bats

monitor_process() {
  TERM_TIMEOUT="3s"
  KILL_TIMEOUT="5s"
  echo 'rm -f /dev/shm/FTL-* 2> /dev/null'
  echo "timeout -k ${KILL_TIMEOUT} -s TERM ${TERM_TIMEOUT} ${@} &> /dev/null &"
  echo '
sleep 0.5
echo "Jobs:"
jobs
PID="$(pgrep pihole-FTL)"
echo "PID: ${PID:--}"

pkill pihole-FTL
sleep 0.5
echo "Jobs:"
jobs
PID="$(pgrep pihole-FTL)"
echo "PID: ${PID:--}"
'
}

@test "Running without arguments doesn't block and starts a daemon" {
  run su pihole -s /bin/bash -c "$(monitor_process /home/pihole/pihole-FTL)"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Jobs:" ]]
  [[ ${lines[1]} == "PID: "* && ${lines[1]} != "PID: -" ]]
  [[ ${lines[2]} == "Jobs:" ]]
  [[ ${lines[3]} == "PID: -" ]]
}

@test "Running with 'no-daemon' blocks untill killed" {
  run su pihole -s /bin/bash -c "$(monitor_process /home/pihole/pihole-FTL no-daemon)"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Jobs:" ]]
  [[ ${lines[1]} == "[1]+  Running"* && ${lines[1]} == *"/home/pihole/pihole-FTL no-daemon"* ]]
  [[ ${lines[2]} == "PID: "* && ${lines[2]} != "PID: -" ]]
  [[ ${lines[3]} == "Jobs:" ]]
  [[ ${lines[4]} == "PID: -" ]]
}

@test "Running with 'test' doesn't block and exits immediately" {
  run su pihole -s /bin/bash -c "$(monitor_process /home/pihole/pihole-FTL test)"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Jobs:" ]]
  [[ ${lines[1]} == "PID: -" ]]
  [[ ${lines[2]} == "Jobs:" ]]
  [[ ${lines[3]} == "PID: -" ]]
}

# Possibly unintended command?
@test "Running with '-f test' blocks but exits immediately" {
  run su pihole -s /bin/bash -c "$(monitor_process /home/pihole/pihole-FTL -f test)"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Jobs:" ]]
  [[ ${lines[1]} == "PID: -" ]]
  [[ ${lines[2]} == "Jobs:" ]]
  [[ ${lines[3]} == "PID: -" ]]
}

@test "Running with 'dnsmasq-test' doesn't block and exits immediately" {
  run su pihole -s /bin/bash -c "$(monitor_process /home/pihole/pihole-FTL dnsmasq-test)"
  printf "%s\n" "${lines[@]}"
  [[ ${lines[0]} == "Jobs:" ]]
  [[ ${lines[1]} == "PID: -" ]]
  [[ ${lines[2]} == "Jobs:" ]]
  [[ ${lines[3]} == "PID: -" ]]
}
