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
    echo "Wrong binary clasification"
    echo "Expected: ${1}"
    echo "Found: ${filedetails}"
    exit 1
  fi
  echo "Binary classification checks: OK (${1})"
}

if [[ "${CIRCLE_JOB}" == "x86_64" ]]; then

  check_machine "ELF64" "Advanced Micro Devices X86-64"
  check_libs "[librt.so.1] [libpthread.so.0] [libc.so.6]"
  check_file "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, not stripped"

elif [[ "${CIRCLE_JOB}" == "x86_64-musl" ]]; then

  check_machine "ELF64" "Advanced Micro Devices X86-64"
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, with debug_info, not stripped"

elif [[ "${CIRCLE_JOB}" == "x86_32" ]]; then

  check_machine "ELF32" "Intel 80386"
  check_libs "[librt.so.1] [libpthread.so.0] [libc.so.6]"
  check_file "ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, not stripped"

elif [[ "${CIRCLE_JOB}" == "aarch64" ]]; then

  check_machine "ELF64" "AArch64"
  check_libs "[librt.so.1] [libpthread.so.0] [libc.so.6] [ld-linux-aarch64.so.1]"
  check_file "ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, not stripped"

elif [[ "${CIRCLE_JOB}" == "armv4t" ]]; then

  check_machine "ELF32" "ARM"
  check_libs "[librt.so.1] [libgcc_s.so.1] [libpthread.so.0] [libc.so.6] [ld-linux.so.3]"
  check_file "ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, for GNU/Linux 3.2.0, not stripped"

  check_CPU_arch "v4T"
  check_FP_arch "" # No specified FP arch

elif [[ "${CIRCLE_JOB}" == "armv5te" ]]; then

  check_machine "ELF32" "ARM"
  check_libs "[librt.so.1] [libgcc_s.so.1] [libpthread.so.0] [libc.so.6] [ld-linux.so.3]"
  check_file "ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, for GNU/Linux 3.2.0, with debug_info, not stripped"

  check_CPU_arch "v5TE"
  check_FP_arch "" # No specified FP arch

elif [[ "${CIRCLE_JOB}" == "armv6hf" ]]; then

  check_machine "ELF32" "ARM"
  check_libs "[librt.so.1] [libgcc_s.so.1] [libpthread.so.0] [libc.so.6] [ld-linux-armhf.so.3]"
  check_file "ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, for GNU/Linux 2.6.32, with debug_info, not stripped"

  check_CPU_arch "v6"
  check_FP_arch "VFPv2"

elif [[ "${CIRCLE_JOB}" == "armv7hf" ]]; then

  check_machine "ELF32" "ARM"
  check_libs "[librt.so.1] [libgcc_s.so.1] [libpthread.so.0] [libc.so.6] [ld-linux-armhf.so.3]"
  check_file "ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-armhf.so.3, for GNU/Linux 3.2.0, with debug_info, not stripped"

  check_CPU_arch "v7"
  check_FP_arch "VFPv3-D16"

else

  echo "Invalid job ${CIRCLE_JOB}"
  exit 1

fi

exit 0