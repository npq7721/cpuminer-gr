#!/bin/bash
#
# Script for building Windows binaries release package using mingw.
# Requires a custom mingw environment, not intended for users.
#
# Compiles Windows EXE files for selected CPU architectures, copies them
# as well as some DLLs that aren't available in most Windows environments
# into a release folder ready to be zipped and uploaded.

# define some local variables

export LOCAL_LIB="$HOME/usr/lib"
export CONFIGURE_ARGS="--with-curl=$LOCAL_LIB/curl --with-crypto=$LOCAL_LIB/openssl --host=x86_64-w64-mingw32"
export MINGW_LIB="/usr/x86_64-w64-mingw32/lib"
# set correct gcc version
export GCC_MINGW_LIB="/usr/lib/gcc/x86_64-w64-mingw32/10-win32"
# used by GCC
export LDFLAGS="-L$LOCAL_LIB/curl/lib/.libs -L$LOCAL_LIB/gmp/.libs -L$LOCAL_LIB/openssl"

# make link to local gmp header file.
ln -s $LOCAL_LIB/gmp/gmp.h ./gmp.h

# edit configure to fix pthread lib name for Windows.
#sed -i 's/"-lpthread"/"-lpthreadGC2"/g' configure.ac

# make release directory and copy selected DLLs.

rm -rf bin/win/ > /dev/null

mkdir -p bin/win
cp $MINGW_LIB/zlib1.dll bin/win/
cp $MINGW_LIB/libwinpthread-1.dll bin/win/
cp $GCC_MINGW_LIB/libstdc++-6.dll bin/win/
cp $GCC_MINGW_LIB/libgcc_s_seh-1.dll bin/win/
cp $LOCAL_LIB/openssl/libcrypto-1_1-x64.dll bin/win/
cp $LOCAL_LIB/curl/lib/.libs/libcurl-4.dll bin/win/

DFLAGS="-Wall -fno-common -Wno-comment -Wno-maybe-uninitialized"

# Start building...

# 1 - Architecture
# 2 - Output suffix
# 3 - Additional options
compile() {

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done
CFLAGS="-O3 -march=${1} ${3} ${DFLAGS}" ./configure ${CONFIGURE_ARGS}
make -j 8
strip -s cpuminer.exe
cp cpuminer.exe bin/win/cpuminer-${2}.exe

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
compile "native" "native" "-mtune=native"

ls -l bin/win
if ( $(ls bin/win/*.exe | wc -l) != 12 ); then
    echo "Some binaries did not compile?"
fi
