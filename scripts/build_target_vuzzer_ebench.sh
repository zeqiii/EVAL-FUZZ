#!/bin/bash

dir="${1}"
mode="${2}"
cd "$dir"
make clean
if [ $mode == "AFL" ]; then
    CC=afl-clang AFL_DONT_OPTIMIZE=1 AFL_USE_ASAN=1 make
elif [ $mode == "ORIG" ]; then
    CC=gcc make
elif [ $mode == "GHIDRA" ]; then
    CC=gcc make
    binary="${1}"/a.out
    project_loc="${3}"
    project_name="${4}"
    VUzzer="${5}"
    analyzeHeadless $project_loc $project_name -import $binary -postScript $VUzzer/fuzzer-code/ghidra_BB_weight.py
fi
