#!/bin/bash

#if [ "$OS" = "Windows_NT" ]; then
#    ./mingw64.sh
#    exit 0
#fi

# Linux build

make distclean || echo clean

rm -f config.status
./autogen.sh || echo done

# For ARMv7-A
CFLAGS="-Ofast -march=armv7-a -mfpu=neon -mtune=native -Wall" CXXFLAGS="$CFLAGS -std=c++17" ./configure --with-curl

# For ARMv8-A
#CFLAGS="-O3 -march=armv8-a -mtune=native -Wall" CXXFLAGS="$CFLAGS -std=c++11" ./configure --with-curl
#CFLAGS="-O3 -march=armv8-a+crypto -mtune=native -Wall" CXXFLAGS="$CFLAGS -std=c++11" ./configure --with-curl

make -j 4

strip -s cpuminer
