#!/bin/bash

lava_install="lava-install"
dir="${1}"
mode="${2}"
cd "$dir"
if [ -d $lava_install ]; then
    echo "delete lava-install..."
    rm -rf $lava_install
fi
make clean
autoreconf -i
./configure --enable-static --disable-shared --prefix=`pwd`/lava-install LIBS="-lparam" CC="/home/ubuntu/workspace/angora/bin/angora-clang"
make clean
export ANGORA_TAINT_RULE_LIST=/home/ubuntu/workspace/testing_fuzzer/testing_fuzzer/zlib_abilist.txt
if [ $mode == "TRACK" ]; then
    ANGORA_USE_ASAN=1 ASAN_OPTIONS=detect_leaks=0 USE_TRACK=1 make
elif [ $mode == "FAST" ]; then
    ANGORA_USE_ASAN=1 ASAN_OPTIONS=detect_leaks=0 make
fi
make install
