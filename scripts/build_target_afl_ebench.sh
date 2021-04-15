#!/bin/bash

dir="${1}"
mode="${2}"
cd "$dir"

if [ $mode == "AFL" ]; then
	make clean
    CC=afl-clang AFL_DONT_OPTIMIZE=1 AFL_USE_ASAN=1 make
elif [ $mode == "ORIG" ]; then
	make clean
    CC=gcc make
elif [ $mode == "TORTOISE" ]; then
	make clean
    CC=/home/varas/workspace/TortoiseFuzz/bb_metric/afl-clang-fast AFL_DONT_OPTIMIZE=1 AFL_USE_ASAN=1 make
elif [ $mode == "FAIRFUZZ" ]; then
	make clean
	CC=/home/varas/workspace/afl-rb/afl-clang AFL_DONT_OPTIMIZE=1 AFL_USE_ASAN=1 make
elif [ $mode == "HONGGFUZZ" ]; then
	make clean
	CC=/home/varas/workspace/honggfuzz/hfuzz_cc/hfuzz-clang make
elif [ $mode == "SANITIZER" ]; then
	rm sanitizer_a.out
	clang -fsanitize=address *.c -o sanitizer_a.out
fi
