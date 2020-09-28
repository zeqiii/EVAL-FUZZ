# -*- coding: utf-8 -*-
import subprocess, os
import Global
from fuzzing import *

# 适用于afl, aflfast, mopt
class Runner_afl(Runner):
    def __init__(self, fuzzer_name, target_path, seed_dir, round_num):
        Runner.__init__(self, fuzzer_name, target_path, seed_dir, round_num)

    def compile(self):
        self.target_binary = self.do_compile(Global.SCRIPT, self.target_path, args="AFL", binary_postfix=Global.BINARY_POSTFIX)

    def start_fuzz_afl(self, extra_args):
        self.finish = False
        self.keywords.append("afl-fuzz")
        # aflplusplus with no extra options
        run_cmd = self.gen_run_cmd(target_binary=self.target_binary, input_file="@@")
        cmd = "%s -i %s -o %s -m none -- %s 1>/dev/null 2>&1" %(Global.PATH[self.fuzzer_name], self.seed_dir, self.one_output_dir, run_cmd)
        print(cmd)
        self.process.append(subprocess.Popen(cmd, shell=True))

    def start_fuzz_aflfast(self, extra_args):
        self.finish = False
        self.keywords.append("afl-fuzz")
        run_cmd = self.gen_run_cmd(target_binary=self.target_binary, input_file="@@")
        cmd = "%s -i %s -o %s -m none -p fast -- %s 1>/dev/null 2>&1" %(Global.PATH[self.fuzzer_name], self.seed_dir, self.one_output_dir, run_cmd)
        self.process.append(subprocess.Popen(cmd, shell=True))

    def start_fuzz_mopt(self, extra_args):
        self.finish = False
        self.keywords.append("afl-fuzz")
        # aflplusplus with mmopt mode
        run_cmd = self.gen_run_cmd(target_binary=self.target_binary, input_file="@@")
        cmd = "%s -i %s -o %s -m none -L 0 -- %s 1>/dev/null 2>&1" %(Global.PATH[self.fuzzer_name], self.seed_dir, self.one_output_dir, run_cmd)
        self.process.append(subprocess.Popen(cmd, shell=True))

    def start_fuzz(self, extra_args=[]):
        self.crash_dir = os.path.join(self.one_output_dir, "crashes")
        if self.fuzzer_name == "afl":
            self.start_fuzz_afl(extra_args)
        elif self.fuzzer_name == "aflfast":
            self.start_fuzz_aflfast(extra_args)
        elif self.fuzzer_name == "mopt":
            self.start_fuzz_mopt(extra_args)
        


