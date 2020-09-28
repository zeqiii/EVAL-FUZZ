#!/bin/bash

dir="${1}"
mode="${2}"
cd "$dir"
cd coreutils-8.24-lava-safe
make clean &> /dev/null
if [ $mode == "AFL" ]; then
    ./configure --prefix=`pwd`/lava-install LIBS="-lacl" CC="afl-clang" &> /dev/null
    AFL_USE_ASAN=1 make
elif [ $mode == "ORIG" ]; then
    ./configure --prefix=`pwd`/lava-install LIBS="-lacl" CC="gcc" &> /dev/null
    make
fi
make install
