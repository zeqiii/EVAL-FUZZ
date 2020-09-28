#!/bin/bash

dir="${1}"
mode="${2}"
cd "$dir"
make clean
#export ANGORA_TAINT_RULE_LIST=/home/ubuntu/workspace/testing_fuzzer/testing_fuzzer/zlib_abilist.txt
if [ $mode == "TRACK" ]; then
    CC=/home/ubuntu/workspace/angora/bin/angora-clang ANGORA_USE_ASAN=1 ASAN_OPTIONS=detect_leaks=0 USE_TRACK=1 make
elif [ $mode == "FAST" ]; then
    CC=/home/ubuntu/workspace/angora/bin/angora-clang ANGORA_USE_ASAN=1 ASAN_OPTIONS=detect_leaks=0 make
fi
