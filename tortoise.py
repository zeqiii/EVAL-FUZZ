# -*- coding: utf-8 -*-
import Global, os
from fuzzing import *

# 适用于afl, aflfast, mopt
class Runner_tortoise(Runner):
    def __init__(self, fuzzer_name, target_path, seed_dir, round_num):
        Runner.__init__(self, fuzzer_name, target_path, seed_dir, round_num)

    def compile(self):
        self.target_binary = self.do_compile(Global.SCRIPT, self.target_path, args="TORTOISE", binary_postfix=Global.BINARY_POSTFIX)
        self.target_binary_sanitizer = self.target_binary
        
    def start_fuzz_tortoise(self, extra_args):
        self.finish = False
        self.keywords = []  # 先清除内存
        self.keywords.append("afl-fuzz")
        run_cmd = self.gen_run_cmd(target_binary=self.target_binary, input_file="@@")
        cmd = "%s -i %s -o %s -s -m none -- %s 1>/dev/null 2>&1" %(Global.PATH[self.fuzzer_name], self.seed_dir, self.one_output_dir, run_cmd)
        self.process.append(subprocess.Popen(cmd, shell=True))

    def start_fuzz(self, extra_args=[]):
        self.crash_dir = os.path.join(one_output_dir, "crashes")
        self.start_fuzz_tortoise(extra_args)

