# -*- coding: utf-8 -*-
import Global, os
from fuzzing import *

class Runner_angora(Runner):
    def __init__(self, fuzzer_name, target_path, seed_dir, round_num):
        Runner.__init__(self, fuzzer_name, target_path, seed_dir, round_num)
        self.track_binary = ""

    def copy_for_angora_track_mode(self):
        print("Copy project for track mode")
        target_path_track = os.path.join(os.path.dirname(target_path), os.path.basename(target_path) + "-track")
        if os.path.exists(target_path_track):
            print("deleting existing dir %s" %(target_path_track))
            os.system("rm -rf %s" %(target_path_track))
        os.system("cp -r %s %s 1>/dev/null" %(target_path, target_path_track))
        return target_path_track

    def compile(self):
        target_path_track = self.copy_for_angora_track_mode()
        self.target_binary = self.do_compile(Global.SCRIPT, self.target_path, args="FAST", binary_postfix=Global.BINARY_POSTFIX)
        self.track_binary = do_compile(Global.SCRIPT, target_path_orig, args="TAINT", binary_postfix=Global.BINARY_POSTFIX)
        self.target_binary_sanitizer = self.target_binary

    def start_fuzz_angora(self, extra_args):
        self.finish = False
        self.keywords.append("release/fuzzer")
        run_cmd = self.gen_run_cmd(target_binary=self.target_binary, input_file="@@")
        cmd = "%s -i %s -o %s -t %s -- %s" %(PATH[self.fuzzer_name], self.seed_dir, self.one_output_dir, self.track_binary, run_cmd)
        self.process.append(subprocess.Popen(cmd, shell=True))

    def start_fuzz(self, extra_args=[]):
        self.crash_dir = os.path.join(one_output_dir, "crashes")
        self.start_fuzz_angora(extra_args)
