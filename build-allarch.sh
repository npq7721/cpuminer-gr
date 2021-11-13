#!/bin/bash
#
# This script is not intended for users, it is only used for compile testing
# during develpment. However the information contained may provide compilation
# tips to users.

rm -r bin/unix 2>/dev/null
rm cpuminer 2>/dev/null
mkdir -p bin/{win,unix} 2>/dev/null

DFLAGS="-Wall -fno-common -Wno-comment -Wno-maybe-uninitialized"

# 1 - Architecture
# 2 - Output suffix
# 3 - Additional options
compile() {

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=${1} ${3} ${DFLAGS}" ./configure --with-curl
make -j 8
strip -s cpuminer
mv cpuminer bin/unix/cpuminer-${2}

}

# Icelake AVX512 SHA VAES
compile "icelake-client" "avx512-sha-vaes"

# Rocketlake AVX512 SHA AES
compile "cascadelake" "avx512-sha" "-msha"

# Slylake-X AVX512 AES
compile "skylake-avx512" "avx512"

# Haswell AVX2 AES
# GCC 9 doesn't include AES with core-avx2
compile "core-avx2" "avx2" "-maes"

# Sandybridge AVX AES
compile "corei7-avx" "avx" "-maes"

# Westmere SSE4.2 AES
compile "westmere" "aes-sse42"

# Nehalem SSE4.2
compile "corei7" "sse42"

# Core2 SSSE3
compile "core2" "ssse3"

# Generic SSE2
compile "x86-64" "sse2" "-msse2"

# AMD Zen1 AVX2 SHA
compile "znver1" "zen"

# AMD Zen3 AVX2 SHA VAES
compile "znver2" "zen3" "-mvaes"

# Build native
./build.sh

ls -l bin/unix
if (( $(ls bin/unix/ | wc -l) != "11" )); then
    echo "Some binaries did not compile?"
fi
