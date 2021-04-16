# -*- coding: utf-8 -*-
import Global, os
from fuzzing import *

class Runner_honggfuzz(Runner):
    def __init__(self, fuzzer_name, target_path, seed_dir, round_num):
        Runner.__init__(self, fuzzer_name, target_path, seed_dir, round_num)

    def compile(self):
        self.target_binary = self.do_compile(Global.SCRIPT, self.target_path, args="HONGGFUZZ", binary_postfix=Global.BINARY_POSTFIX)
        self.target_binary_sanitizer = self.do_compile(Global.SCRIPT, self.target_path, args="SANITIZER", binary_postfix="sanitizer_"+Global.BINARY_POSTFIX)
        
    def start_fuzz_honggfuzz(self, extra_args):
        self.finish = False
        self.keywords.append("crashdir")
        run_cmd = self.gen_run_cmd(target_binary=self.target_binary, input_file="___FILE___")
        os.makedirs(self.one_output_dir)  # 首先创建文件
        cmd = "%s -i %s -W %s -o %s --crashdir %s -l %s -- %s 1>/dev/null 2>&1" %(Global.PATH[self.fuzzer_name], self.seed_dir, self.one_output_dir, \
            self.one_output_dir, os.path.join(self.one_output_dir, "crashes"), os.path.join(self.one_output_dir, "log"), run_cmd)
        self.process.append(subprocess.Popen(cmd, shell=True))

    def start_fuzz(self, extra_args=[]):
        self.crash_dir = os.path.join(self.one_output_dir, "crashes")
        self.start_fuzz_honggfuzz(extra_args)