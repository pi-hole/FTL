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

check_libs() {
  mapfile -t libs < <(readelf -d ./pihole-FTL | grep "Shared library" | grep -oE "\[.*\]")
  if [[ "${libs[*]}" != "${1}" ]]; then
    echo "Wrong libraries"
    echo "Found: ${libs[*]}"
    echo "Expected: ${1}"
    exit 1
  fi
  echo "Library checks: OK (using ${#libs[*]} shared libraries)"
}

check_machine() {
  mapfile -t header < <(readelf -h ./pihole-FTL | grep -E "(Class)|(Machine)" | sed "s/.*://;s/ \{2,\}//g;")
  if [[ "${header[0]}" != "${1}" || "${header[1]}" != "${2}" ]]; then
    echo "Wrong machine"
    echo "Expected: Class: ${1} Machine: ${2}"
    echo "Found: Class: ${header[0]} Machine: ${header[1]}"
    exit 1
  fi
  echo "Machine checks: OK (${1} binary for ${2})"
}

check_CPU_arch() {
  cpuarch="$(readelf -A ./pihole-FTL | grep "Tag_CPU_arch:" | sed "s/^ *//")"
  if [[ "${cpuarch}" != "Tag_CPU_arch: ${1}" ]]; then
    echo "Wrong CPU arch"
    echo "Expected: Tag_CPU_arch: ${1}"
    echo "Found: ${cpuarch}"
    exit 1
  fi
  echo "CPU architecture checks: OK (${1})"
}

check_FP_arch() {
  fparch="$(readelf -A ./pihole-FTL | grep "Tag_FP_arch:" | sed "s/^ *//")"
  if [[ "${fparch}" != "Tag_FP_arch: ${1}" && -n "${1}" ]]; then
    echo "Wrong FP arch"
    echo "Expected: Tag_FP_arch: ${1}"
    echo "Found: ${fparch}"
    exit 1
  fi
  echo "FP architecture checks: OK (${1})"
}

check_file() {
  filedetails="$(file -b pihole-FTL | sed "s/, BuildID[^,]*//g")"
  if [[ "${filedetails}" != "${1}" ]]; then
    echo "Wrong binary classification"
    echo "Expected: ${1}"
    echo "Found: ${filedetails}"
    exit 1
  fi
  echo "Binary classification checks: OK (${1})"
}

check_static() {
  if readelf -l ./pihole-FTL | grep -q INTERP; then
    echo "Not a static executable, depends on dynamic interpreter"
    ldd ./pihole-FTL
    exit 1
  fi
  echo "Static executable check: OK"
}

if [[ "${CI_ARCH}" == "linux/amd64" ]]; then

  check_machine "ELF64" "Advanced Micro Devices X86-64"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped"

elif [[ "${CI_ARCH}" == "linux/386" ]]; then

  check_machine "ELF32" "Intel 80386"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, with debug_info, not stripped"

elif [[ "${CI_ARCH}" == "linux/arm64/v8" || "${CI_ARCH}" == "linux/arm64" ]]; then

  check_machine "ELF64" "AArch64"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, with debug_info, not stripped"

elif [[ "${CI_ARCH}" == "linux/arm/v6" ]]; then

  check_machine "ELF32" "ARM"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, with debug_info, not stripped"

  check_CPU_arch "v6"
  check_FP_arch "VFPv2"

elif [[ "${CI_ARCH}" == "linux/arm/v7" ]]; then

  check_machine "ELF32" "ARM"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, with debug_info, not stripped"

  check_CPU_arch "v7"
  check_FP_arch "VFPv3-D16"

elif [[ "${CI_ARCH}" == "linux/riscv64" ]]; then

  check_machine "ELF64" "RISC-V"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), statically linked, with debug_info, not stripped"

else

  echo "Invalid job ${CI_ARCH}"
  exit 1

fi

exit 0
