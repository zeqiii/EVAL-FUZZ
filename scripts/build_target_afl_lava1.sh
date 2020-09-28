#!/bin/bash

dir="${1}"
mode="${2}"
cd "$dir"
autoreconf -f -i
if [ $mode == "AFL" ]; then
    ./configure --enable-static --disable-shared --prefix=`pwd`/lava-install CFLAGS="-fvisibility=default -ggdb -O0" LIBS="-lparam" CC="afl-clang"
    make clean
    AFL_DONT_OPTIMIZE=1 AFL_USE_ASAN=1 make
elif [ $mode == "ORIG" ]; then
    ./configure --enable-static --disable-shared --prefix=`pwd`/lava-install CFLAGS="-fvisibility=default -ggdb -O0" LIBS="-lparam" CC="gcc"
    make clean
    make
fi
make install
