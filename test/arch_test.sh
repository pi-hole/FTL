#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2020 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Binary target tests
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license. */

okay=true

check_libs() {
  mapfile -t libs < <(readelf -d ./pihole-FTL | grep "Shared library" | grep -oE "\[.*\]")
  if [[ "${libs[*]}" != "${1}" ]]; then
    echo "Wrong libraries"
    echo "   Expected: ${1}"
    echo "   Found: ${libs[*]}"
    okay=false
    return
  fi
  echo "Library checks: OK (using ${#libs[*]} shared libraries)"
}

check_machine() {
  mapfile -t header < <(readelf -h ./pihole-FTL | grep -E "(Class)|(Machine)" | sed "s/.*://;s/ \{2,\}//g;")
  if [[ "${header[0]}" != "${1}" || "${header[1]}" != "${2}" ]]; then
    echo "Wrong machine"
    echo "   Expected: Class: ${1} Machine: ${2}"
    echo "   Found: Class: ${header[0]} Machine: ${header[1]}"
    okay=false
    return
  fi
  echo "Machine checks: OK (${1} binary for ${2})"
}

check_CPU_arch() {
  cpuarch="$(readelf -A ./pihole-FTL | grep "Tag_CPU_arch:" | sed "s/^ *//")"
  if [[ "${cpuarch}" != "Tag_CPU_arch: ${1}" ]]; then
    echo "Wrong CPU arch"
    echo "   Expected: Tag_CPU_arch: ${1}"
    echo "   Found: ${cpuarch}"
    okay=false
    return
  fi
  echo "CPU architecture checks: OK (${1})"
}

check_FP_arch() {
  fparch="$(readelf -A ./pihole-FTL | grep "Tag_FP_arch:" | sed "s/^ *//")"
  if [[ "${fparch}" != "Tag_FP_arch: ${1}" && -n "${1}" ]]; then
    echo "Wrong FP arch"
    echo "   Expected: Tag_FP_arch: ${1}"
    echo "   Found: ${fparch}"
    okay=false
    return
  fi
  echo "FP architecture checks: OK (${1})"
}

check_file() {
  filedetails="$(file -b pihole-FTL | sed "s/, BuildID[^,]*//g")"
  if [[ "${filedetails}" != "${1}" ]]; then
    echo "Wrong binary classification"
    echo "   Expected: ${1}"
    echo "   Found: ${filedetails}"
    okay=false
    return
  fi
  echo "Binary classification checks: OK (${1})"
}

check_static() {
  if readelf -l ./pihole-FTL | grep -q INTERP; then
    echo "Not a static executable, depends on dynamic interpreter"
    ldd ./pihole-FTL
    okay=false
    return
  fi
  echo "Static executable check: OK"
}

check_minimum_glibc_version() {
  libc="$(objdump -T ./pihole-FTL | grep GLIBC | sed 's/.*GLIBC_\([.0-9]*\).*/\1/g' | sort -Vu | tail -n1)"
  if [[ "${libc}" != "${1}" ]]; then
    echo "Wrong minimum glibc version"
    echo "   Expected: ${1}"
    echo "   Found: ${libc}"
    okay=false
    return
  fi
  echo "Minimum glibc version check: OK (${1})"
}

check_crash() {
  # Run the intentional-crash subcommand and capture combined stdout+stderr.
  # The process exits non-zero (killed by SIGSEGV), so we suppress the error.
  output="$(./pihole-FTL crash 2>&1 || true)"
  if ! echo "$output" | grep -q "FTL crashed"; then
    echo "Crash handler test: FAILED (FTL crash handler was not invoked)"
    okay=false
    return
  fi
  if ! echo "$output" | grep -q "Backtrace ("; then
    # Handler ran but no backtrace — warn rather than fail.
    # This can happen if addr2line is absent or the binary has no debug info.
    echo "Crash handler test: WARNING (crash handler invoked, no backtrace)"
    return
  fi
  echo "Crash handler test: OK (crash handler invoked, backtrace generated)"

  # On x86_64/aarch64 the crash backtrace must be collected from the
  # interrupted signal context (the preferred frame-pointer walk), not the
  # _Unwind_Backtrace fallback. Other architectures have no signal-context
  # walker and legitimately use the fallback, so only assert it where it
  # applies and runs natively/reliably (amd64 and local runs).
  case "${CI_ARCH}" in
    linux/amd64|"")
      if echo "$output" | grep -q "from signal context"; then
        echo "Crash backtrace source test: OK (collected from signal context)"
      else
        echo "Crash backtrace source test: FAILED (expected 'from signal context')"
        echo "$output" | grep "Backtrace (" || true
        okay=false
      fi
      # The handler must run to the end, including cleanup(), on its
      # alternate signal stack
      if echo "$output" | grep -q "FTL terminated"; then
        echo "Crash handler cleanup test: OK (cleanup completed)"
      else
        echo "Crash handler cleanup test: FAILED (handler did not reach cleanup)"
        echo "$output" | tail -n 5
        okay=false
      fi
      ;;
  esac
}

check_backtrace() {
  # The 'backtrace' subcommand prints a backtrace without crashing and must
  # exit cleanly.
  output="$(./pihole-FTL backtrace 2>&1)"
  status=$?
  if [[ "${status}" -ne 0 ]]; then
    echo "Backtrace subcommand test: FAILED (exit status ${status})"
    okay=false
    return
  fi
  if echo "$output" | grep -q "Backtrace (" && echo "$output" | grep -q -- "--- end of backtrace"; then
    echo "Backtrace subcommand test: OK (backtrace generated)"
  else
    echo "Backtrace subcommand test: FAILED (no backtrace produced)"
    echo "$output"
    okay=false
  fi
}

if [[ "${CI_ARCH}" == "linux/amd64" || "${CI_ARCH}" == "" ]]; then

  if [[ "${STATIC}" == "true" ]]; then
    check_machine "ELF64" "Advanced Micro Devices X86-64"
    check_static # Binary should not rely on any dynamic interpreter
    check_libs "" # No dependency on any shared library is intended
    check_file "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, with debug_info, not stripped"
else
    check_machine "ELF64" "Advanced Micro Devices X86-64"
    check_libs "[libgmp.so.10] [libidn2.so.0] [libgcc_s.so.1] [libc.musl-x86_64.so.1]"
    check_file "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-musl-x86_64.so.1, with debug_info, not stripped"
  fi

elif [[ "${CI_ARCH}" == "linux/386" ]]; then

  check_machine "ELF32" "Intel 80386"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 32-bit LSB pie executable, Intel i386, version 1 (SYSV), static-pie linked, with debug_info, not stripped"

elif [[ "${CI_ARCH}" == "linux/arm/v5" ]]; then

  check_machine "ELF32" "ARM"
  check_libs "[libm.so.6] [librt.so.1] [libgcc_s.so.1] [libpthread.so.0] [libc.so.6] [ld-linux.so.3]"
  check_file "ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, for GNU/Linux 3.2.0, not stripped"

  check_CPU_arch "v4T"
  check_FP_arch ""

  check_minimum_glibc_version "2.15"

elif [[ "${CI_ARCH}" == "linux/arm/v6" ]]; then

  check_machine "ELF32" "ARM"

  # Alpine Builder
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV), static-pie linked, with debug_info, not stripped"

  check_CPU_arch "v6KZ"
  # VFPv3 is backwards compatible with VFPv2
  check_FP_arch "VFPv3"

elif [[ "${CI_ARCH}" == "linux/arm/v7" ]]; then

  check_machine "ELF32" "ARM"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV), static-pie linked, with debug_info, not stripped"

  check_CPU_arch "v7"
  check_FP_arch "VFPv3"

elif [[ "${CI_ARCH}" == "linux/arm64/v8" || "${CI_ARCH}" == "linux/arm64" ]]; then

  check_machine "ELF64" "AArch64"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), static-pie linked, with debug_info, not stripped"

elif [[ "${CI_ARCH}" == "linux/riscv64" ]]; then

  check_machine "ELF64" "RISC-V"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 64-bit LSB pie executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), static-pie linked, with debug_info, not stripped"

else

  echo "Unknown architecture '${CI_ARCH}'"
  exit 1

fi

check_backtrace
check_crash

if [[ "${okay}" == "false" ]]; then
  echo "Binary checks failed"
  exit 1
fi

exit 0
