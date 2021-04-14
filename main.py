# -*- coding: utf-8 -*-
import sys, os
import Global
from afl import *
from qsym import *
from angora import *
from tortoise import *
from fairfuzz import *

def run(bucket_file, seed_dir, fuzzer_name, round_num):
    seed_dir = os.path.abspath(seed_dir)
    if not os.path.exists(seed_dir):
        os.makedirs(seed_dir)
    runner = None
    if fuzzer_name == "afl" or fuzzer_name == "aflfast" or fuzzer_name == "mopt":
        runner = Runner_afl(fuzzer_name, "", seed_dir, round_num)
    elif fuzzer_name == "qsym":
        runner = Runner_qsym(fuzzer_name, "", seed_dir, round_num)
    elif fuzzer_name == "angora":
        runner = Runner_angora(fuzzer_name, "", seed_dir, round_num)
    elif fuzzer_name == "tortoise":
        runner = Runner_tortoise(fuzzer_name, "", seed_dir, round_num)
    elif fuzzer_name == "fairfuzz":
        runner = Runner_fairfuzz(fuzzer_name, "", seed_dir, round_num)
    # read target projects from bucket
    with open(bucket_file) as f:
        lines = f.readlines()
        for target_path in lines:
            target_path = target_path.strip()
            runner.setTargetPath(target_path)
            retry = 0
            while retry <= 3:
                finish = runner.run_one()
                if finish: # 正常结束
                    break
                retry = retry + 1
            print("sleep 10s after waiting...")
            time.sleep(10)

    # bench4i能够记录代码触发时空分布数据
    # 将/run/shm中的代码触发时空分布记录文件拷贝到输出文件夹中
    if Global.TESTSET == "bench4i":
        time_space_dir = os.path.join(runner.round_n_output, "temporal_spatial_distribution")
        if not os.path.exists(time_space_dir):
            os.makedirs(time_space_dir)
        cmd = "mv /run/shm/IS* %s" %(time_space_dir)
        os.system(cmd)

if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("Usage: python main.py [compile_script] [fuzzer_name] [testset_name] [targets_list] [timeout(hour)] [number of rounds]")
        print("[fuzzer_name] can be: %s" %(str(Global.PATH.keys())))
        print("[testset_name] can be: %s" %(str(Global.testset_info.keys())))
        exit(0)

    # 根据参数初始化全局变量
    Global.SCRIPT = sys.argv[1]
    Global.FUZZER = sys.argv[2]
    Global.TESTSET = sys.argv[3]
    Global.TIMEOUT = int(sys.argv[5]) * 3600
    Global.BINARY_POSTFIX = Global.testset_info[Global.TESTSET]["binary"]
    Global.ROUNDS = int(sys.argv[6])

    # targets_list_file里存储了被测工具需要执行模糊测试的目标程序列表
    targets_list_file = sys.argv[4]

    # tmp_seed_dir是测评过程中暂存种子文件的文件夹
    tmp_seed_dir = os.path.join(Global.seed_dir, "seed_for_%s"%(Global.TESTSET))

    # 运行
    for round_num in range(1, Global.ROUNDS+1):
        run(targets_list_file, tmp_seed_dir, Global.FUZZER, round_num)
    os.system("echo all_finished > finish_flag")