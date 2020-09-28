# -*- coding: utf-8 -*-
import Global, os
from fuzzing import *

# 适用于qsym
class Runner_qsym(Runner):
    def __init__(self, fuzzer_name, target_path, seed_dir, round_num):
        Runner.__init__(self, fuzzer_name, target_path, seed_dir, round_num)
        self.orig_binary = ""

    def copy_for_qsym_original_mode(self):
        print("Copy project for original mode")
        target_path_orig = os.path.join(os.path.dirname(self.target_path), os.path.basename(self.target_path) + "-orig")
        if os.path.exists(target_path_orig):
            print("deleting existing dir %s" %(target_path_orig))
            os.system("rm -rf %s" %(target_path_orig))
        os.system("cp -r %s %s 1>/dev/null" %(target_path, target_path_orig))
        return target_path_orig

    def compile(self):
        target_path_orig = self.copy_for_qsym_original_mode()
        self.target_binary = self.do_compile(Global.SCRIPT, self.target_path, args="AFL", binary_postfix=Global.BINARY_POSTFIX)
        self.orig_binary = do_compile(Global.SCRIPT, target_path_orig, args="ORIG", binary_postfix=Global.BINARY_POSTFIX)

    def start_fuzz_qsym(self, extra_args):
        self.finish = False
        self.keywords.append("afl-fuzz")
        self.keywords.append("run_qsym_afl.py")
        run_cmd1 = self.gen_run_cmd(target_binary=self.target_binary, input_file="@@")
        cmd1 = "afl-fuzz -M master -i %s -o %s -m none -- %s 1>/dev/null 2>&1" %(self.seed_dir, self.one_output_dir, run_cmd1)
        self.process.append(subprocess.Popen(cmd1, shell=True))
        time.sleep(5) # 等待afl启动完毕
        run_cmd2 = self.gen_run_cmd(target_binary=self.orig_binary, input_file="@@")
        cmd2 = [Global.PATH[self.fuzzer_name], "-a", "master", "-n", "qsym", "-o", self.one_output_dir, "--", run_cmd2]
        self.process.append(subprocess.Popen(cmd2))

    def start_fuzz(self, extra_args=[]):
        self.crash_dir = os.path.join(self.one_output_dir, "master/crashes")
        self.start_fuzz_qsym(extra_args)

