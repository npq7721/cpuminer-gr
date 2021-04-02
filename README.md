This version was created to support ARMv7 (ARM) and ARMv8 (Aarch64).
Code was stripped from any unnecessary algorithms and currently only
supports Ghost Rider (gr, Raptoreum) algorithm.
Algorithm removal was done to minimize size and reduce compilation time
as it **should** be compiled locally to achieve the best performance possible.


Requirements
------------

1. 64 or 32 bit Linux OS. Raspbian (Debian) is known to work and have all dependencies in their repositories. Others may work but may require more effort.

2. Stratum pool supporting stratum+tcp:// or stratum+ssl:// protocols or RPC getwork using http:// or https://. GBT is YMMV.

Supported Algorithms
--------------------

                          gr            Gr Hash (RTM)
  
Changes
--------------------

Due to missing instructions such as SSE2 on ARM architecture processors some
code had to be modified (mostly includes).

sse2neon (https://github.com/DLTcollab/sse2neon) was used as an alternative 
and easy solution to port required functionality and make it work on ARM.

Main modifications compared to the original release:

simd-utils.h - use sse2neon. Disable most of the includes.

algo/lyra2/sponge.c - use sse2neon

util.c - Remove mentions and variables used by X16, PHI2 and LBRY

miner.h - Remove mention of other algorithms.

algo-gate-api.c - Remove mention of other algorithms.

cpu-miner.c - Remove requirement for SSE2 check.

Makefile.am - Remove source files for unused algorithms.

Install
--------------------

It is HIGHLY recommended to compile the code on the local machine.
The most important information can be found in **INSTALL_LINUX** file.

Example for Raspbian:
1. Install depenencies:

`sudo apt-get update && sudo apt-get install build-essential libssl-dev libcurl4-openssl-dev libjansson-dev libgmp-dev automake zlib1g-dev texinfo`
2. Get a repository. Either zipped file or `git clone https://github.com/michal-zurkowski/cpuminer-gr`
3. Build: The basic process is inside `build.sh` file and can also be used. You will have to choose one line depending on if you want to compile it as ARMv7 (default) or ARMv8.
```
./autogen.sh
-------------- ARMv7 (ARM)
CFLAGS="-O3 -march=armv7-a -mfpu=neon -mtune=native -Wall" CXXFLAGS="$CFLAGS -std=c++11" ./configure --with-curl
-------------- ARMv8 (Aarch64)
CFLAGS="-O3 -march=armv8-a -mtune=native -Wall" CXXFLAGS="$CFLAGS -std=c++11" ./configure --with-curl
-------------- -march= can be changed if you have higher version like armv8.1-a or armv8-a+fp+simd and so on. Refferr to https://gcc.gnu.org/onlinedocs/gcc/AArch64-Options.html
make -j 4
strip -s cpuminer
```

Tested Systems
------------
```
Hardware           System          Notes
Raspberry Pi 3     Raspbian        
Raspberry Pi 4     Raspbian        See Troubleshooting section. Compiled as ARMv7.
```

Troubleshooting
------------
Raspberry Pi 4     Raspbian
There is an alignment problem with Raspberry Pi 4. To fix it run followinf command: `sudo echo 0 > /proc/cpu/alignment`

Note from Jay D Dee. repository
------------
https://github.com/JayDDee/cpuminer-opt
cpuminer-opt is a fork of cpuminer-multi by TPruvot with optimizations imported from other miners developped by lucas Jones, djm34, Wolf0, pooler, Jeff garzik, ig0tik3d, elmad, palmd, and Optiminer, with additional optimizations by Jay D Dee.

All of the code is believed to be open and free. If anyone has a claim to any of it post your case in the cpuminer-opt Bitcoin Talk forum or by email.

Miner programs are often flagged as malware by antivirus programs. This is a false positive, they are flagged simply because they are cryptocurrency miners. The source code is open for anyone to inspect. If you don't trust the software, don't use it.

New thread:

https://bitcointalk.org/index.php?topic=5226770.msg53865575#msg53865575

Old thread:

https://bitcointalk.org/index.php?topic=1326803.0

mailto://jayddee246@gmail.com

This note is to confirm that bitcointalk users JayDDee and joblo are the same person.

I created a new BCT user JayDDee to match my github user id. The old thread has been locked but still contains useful information for reading.

See file RELEASE_NOTES for change log and INSTALL_LINUX or INSTALL_WINDOWS for compile instructions.
  
Bugs
----

Users are encouraged to post their bug reports on the Bitcoin Talk
forum at:

https://bitcointalk.org/index.php?topic=1326803.0

All problem reports must be accompanied by a proper definition.
This should include how the problem occurred, the command line and
output from the miner showing the startup and any errors.

Donations
---------

cpuminer-opt has no fees of any kind but donations are accepted.

BTC: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT

Happy mining!

