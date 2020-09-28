#!/bin/bash
vuzzer_fuzzer_code=$1
cmd=$2
seed=$3
pkl_file=$4
names_file=$5
cd $vuzzer_fuzzer_code
python runfuzzer.py -s "${cmd}" -i ${seed} -w ${pkl_file} -n ${names_file}
