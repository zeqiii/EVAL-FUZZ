# -*- coding: utf-8 -*-
import os, json
# 全局通用常量
home_dir = os.path.abspath(os.path.dirname(__file__))
tmp_dir = os.path.join(home_dir, "tmp")
script_dir = os.path.join(home_dir, "scripts")
backtrace_dir = os.path.join(home_dir, "backtraces")
output_dir = os.path.join(home_dir, "outputs")
result_dir = os.path.join(home_dir, "results")
config_dir = os.path.join(home_dir, "configs")
seed_dir = os.path.join(home_dir, "seeds")

# 存储当前被测评的模糊测试工具信息
FUZZER = ""    # 模糊测试工具名称
SCRIPT = ""    # 目标程序的编译脚本
TIMEOUT = 7200 # 默认为2小时的超时时限
TESTSET = ""   # 测试集

# 读取configs文件夹下的配置信息
PATH = {} # 模糊测试工具运行路径信息, dict的结构为{fuzzer_name: execution_path}
path_file = os.path.join(config_dir, "path.conf")
with open(path_file) as fp:
    path_content = fp.readlines()
    for line in path_content:
        line = line.strip()
        if line.startswith('#') or not line:
            continue
        PATH[line.split("=")[0].strip()] = line.split("=")[1].strip()

# 读取测试集的配置信息
testset_info = json.loads(open(os.path.join(config_dir, "testset.json")).read())

# 目标程序二进制文件名，根据测试集名称进行初始化
BINARY_POSTFIX = ""
GROUND_TRUTH = os.path.join(backtrace_dir, "ground_truth")
