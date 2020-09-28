#!/bin/bash

binfile=$1
profraw=$2
profdata=$3
lcov=$4

llvm-profdata merge -sparse $profraw -o $profdata
llvm-cov export $binfile --format=lcov --instr-profile=$profdata > $lcov
