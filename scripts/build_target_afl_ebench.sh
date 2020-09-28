#!/bin/bash

dir="${1}"
mode="${2}"
cd "$dir"
make clean
if [ $mode == "AFL" ]; then
    CC=afl-clang AFL_DONT_OPTIMIZE=1 AFL_USE_ASAN=1 make
elif [ $mode == "ORIG" ]; then
    CC=gcc make
elif [ $mode == "TORTOISE" ]; then
    CC=/home/varas/workspace/TortoiseFuzz/bb_metric/afl-clang-fast AFL_DONT_OPTIMIZE=1 AFL_USE_ASAN=1 make
fi
