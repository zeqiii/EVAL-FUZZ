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
elif [ $mode == "FAIRFUZZ" ]; then
	CC=/home/varas/workspace/afl-rb/afl-clang AFL_DONT_OPTIMIZE=1 AFL_USE_ASAN=1 make
elif [ $mode == "HONGGFUZZ" ]; then
	CC=/home/varas/workspace/honggfuzz/hfuzz_cc/hfuzz-clang make
fi
