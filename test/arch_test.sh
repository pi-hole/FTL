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
  check_file "ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, with debug_info, not stripped"

  check_CPU_arch "v6KZ"
  # VFPv3 is backwards compatible with VFPv2
  check_FP_arch "VFPv3"

elif [[ "${CI_ARCH}" == "linux/arm/v7" ]]; then

  check_machine "ELF32" "ARM"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, with debug_info, not stripped"

  check_CPU_arch "v7"
  check_FP_arch "VFPv3"

elif [[ "${CI_ARCH}" == "linux/arm64/v8" || "${CI_ARCH}" == "linux/arm64" ]]; then

  check_machine "ELF64" "AArch64"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, with debug_info, not stripped"

elif [[ "${CI_ARCH}" == "linux/riscv64" ]]; then

  check_machine "ELF64" "RISC-V"
  check_static # Binary should not rely on any dynamic interpreter
  check_libs "" # No dependency on any shared library is intended
  check_file "ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), statically linked, with debug_info, not stripped"

else

  echo "Unknown architecture '${CI_ARCH}'"
  exit 1

fi

if [[ "${okay}" == "false" ]]; then
  echo "Binary checks failed"
  exit 1
fi

exit 0
