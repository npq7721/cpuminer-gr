#!/bin/bash

rm -v build.log 2>/dev/null

make distclean | tee build.log

rm -f config.status | tee -a build.log
./autogen.sh | tee -a build.log


ARCH=""
MFPU=""


if [[ $(uname -m) =~ "armv7" ]]; then
  if [[ $(uname -m) != "armv7l" ]]; then
    echo "Detected unknown ARMv7 processor $(uname -m)" | tee -a build.log
  fi
  echo "Detected ARMv7 (arm) system" | tee -a build.log
  ARCH="armv7-a"
  if [[ ! -z "$(cat /proc/cpuinfo | grep "vfpv4")" ]]; then
    echo "Detected vfpv4 instruction set. Changing to -mfpu=neon-vfpv4" | tee -a build.log
    MFPU="-mfpu=neon-vfpv4"
  else
    echo $(cat /proc/cpuinfo | grep "vfpv4") | tee -a build.log
    echo "Using default -mfpu=neon" | tee -a build.log
    MFPU="-mfpu=neon"
  fi
elif [[ $(uname -m) =~ "aarch64" ]]; then
  echo "Detected ARMv8 (aarch64) system" | tee -a build.log
  ARCH="armv8-a+simd"
else
  echo "Architecture $(uname -m). Compile as native" | tee -a build.log
  ARCH="native"
  MFPU=""
fi

CFLAGS="-O3 -march=${ARCH} ${MFPU} -mtune=native" CXXFLAGS="$CFLAGS -std=c++11" ./configure --with-curl | tee -a build.log

make -j 4 | tee -a build.log

strip -s cpuminer | tee -a build.log
