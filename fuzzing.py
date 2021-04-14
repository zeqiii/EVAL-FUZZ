# -*- coding: utf-8 -*- 
import sys, os, threading, time, subprocess, json
import Global
from multiprocessing import Process
from watchdog.observers import Observer
from watchdog.events import *

# 解析崩溃栈信息
def parse_backtrace(backtrace_file):
    backtrace = []
    flag = 0
    with open(backtrace_file) as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line.startswith("#"):
                if flag == 0:
                    flag = 1
                backtrace.append(line)
            else:
                if flag == 1:
                    break
                else:
                    continue
    result = []
    for one in backtrace:
        parts = one.split(" ")
        stack_position = parts[0]
        source_location = parts[-1]
        function_name = parts[-2]
        result.append((stack_position, function_name, source_location)) 
    return result


# 对比两个崩溃栈文件，看它们是否是同一个崩溃
def compare_backtraces(backtrace_file1, backtrace_file2):
    backtrace1 = parse_backtrace(backtrace_file1)
    backtrace2 = parse_backtrace(backtrace_file2)
    if len(backtrace1) != len(backtrace2):
        return False
    for i in range(0, len(backtrace1)):
        pos1, func1, sl1 = backtrace1[i]
        pos2, func2, sl2 = backtrace2[i]
        if pos1 != pos2:
            return False
        if func1 != func2:
            return False
        if sl1.startswith("(") and sl1.endswith(")") and sl2.startswith("(") and sl2.endswith(")"):
            continue
        if sl1 == sl2:
            continue
    return True


# 以input_file作为输入，调用target_binary触发崩溃，并生成崩溃栈文件
def __gen_backtrace_asan(cmd, output_backtrace):
    cmd = cmd + " 2> " + output_backtrace
    os.system(cmd)
    return output_backtrace

def gen_backtrace_asan(testsetname, backtrace_file, target_binary, poc, args=[]):
    trigger_cmd = ""
    if testsetname == "lava1":
        trigger_cmd = bug_trigger_lava1(target_binary, poc, args)
    elif testsetname == "ebench":
        trigger_cmd = bug_trigger_ebench(target_binary, poc, args)
    return __gen_backtrace_asan(trigger_cmd, backtrace_file)


class FileEventHandler(FileSystemEventHandler):
    watcher = None
    def __init__(self):
        FileSystemEventHandler.__init__(self)

    def setWatcher(self, watcher):
        self.watcher = watcher

    def on_created(self, event):
        if event.is_directory:
            pass
        else:
            print("file created:{0}".format(event.src_path))
            self.watcher.lock.acquire()
            self.watcher.event_queue.append(event.src_path)
            self.watcher.lock.release()

    def on_modified(self, event):
        if event.is_directory:
            pass
        else:
            print("file modified:{0}".format(event.src_path))
            self.watcher.lock.acquire()
            self.watcher.event_queue.append(event.src_path)
            self.watcher.lock.release()


# 监控新crash文件的生成，并检测新产生的crash文件是否能够触发ground truth漏洞
class Watcher:
    def __init__(self, fuzz_process):
        self.lock = threading.Lock()
        self.event_queue = []
        self.the_right_crash_input = ""
        self.fuzz_process = fuzz_process
        self.abnormal_stop = False
        self.start_time = time.time()
        self.now = time.time()
        self.observer = None

    # 启动文件监控线程，把新产生的crash文件存储到queue队列中
    def watch(self, crash_dir):
        for one in os.listdir(crash_dir):
            f = os.path.join(crash_dir, one)
            self.event_queue.append(f)
        self.observer = Observer()
        event_handler = FileEventHandler()
        event_handler.setWatcher(self)
        self.observer.schedule(event_handler, crash_dir)
        self.observer.start()
        print("|||| Start watching crash dir")

    # 从queue中取crash文件，检测其是否能够触发ground truth漏洞
    def __process_queue(self, target_binary, ground_truth_backtrace):
        same = False
        self.now = time.time()
        # fuzz超过TIMEOUT自动超时
        while (not self.abnormal_stop and not same and self.now - self.start_time < Global.TIMEOUT):
            if self.event_queue:
                # 从queue中取出crash文件
                self.lock.acquire()
                poc = self.event_queue.pop()
                print("new crash file found: %s" %(poc))
                self.lock.release()
                # 以crash为输入生成crash backtrace
                backtrace = os.path.join(Global.backtrace_dir, "backtrace")
                self.fuzz_process.gen_backtrace_asan(backtrace, target_binary, poc)
                # 对比生成的backtrace与ground truth backtrace
                same = compare_backtraces(backtrace, Global.GROUND_TRUTH)
                if same:
                    self.the_right_crash_input = poc
                    self.observer.stop()
                    break
                else:
                    pass
            time.sleep(1)
            self.now = time.time()

        self.observer.stop()
        # 结束模糊测试，并进行后续处理
        if not self.abnormal_stop:
            self.fuzz_process.stop_fuzz()
        # 将发现的crash输入重命名为xxx_the-right-crash
        if same:
            os.system("mv %s %s" %(self.the_right_crash_input, self.the_right_crash_input+"_the-right-crash"))

    def process_queue(self, target_binary, ground_truth_backtrace):
        t = threading.Thread(target=self.__process_queue, args=(target_binary, ground_truth_backtrace))
        t.start()


class Runner():
    def __init__(self, fuzzer_name, target_path, seed_dir, round_num):
        self.fuzzer_name = fuzzer_name      # fuzzer名称
        self.target_path = target_path # 目标程序的源码路径
        self.target_binary = None      # 目标程序的二进制文件路径
        self.seed_dir = seed_dir       # 种子文件路径
        self.crash_dir = ""            # 模糊测试工具的crash目录
        self.round_num = round_num     # 模糊测试的独立重复实验次数

        self.run_args = Global.testset_info[Global.TESTSET]["args"]
        self.run_cmd = Global.testset_info[Global.TESTSET]["cmd"]
        self.poc = Global.testset_info[Global.TESTSET]["poc"]
        self.poc = os.path.join(self.target_path, self.poc)

        self.process = []    # 模糊测试进程列表
        self.keywords = []   # 模糊测试进程名关键词
        self.finish = False  # 模糊测试是否正常结束
        self.round_n_output = "" # 一轮模糊测试的输出目录
        self.one_output_dir = "" # 模糊测试输出目录
        self.result_file = "" #记录结果数据的文件

        pass

    def setTargetPath(self, target_path):
        self.target_path = target_path
        self.poc = Global.testset_info[Global.TESTSET]["poc"]
        self.poc = os.path.join(self.target_path, self.poc)

    def setTargetBinary(self, target_binary):
        self.target_binary = target_binary

    # 编译目标工程
    # 参数1：编译脚本文件
    # 参数2：编译目标文件夹
    # 参数3：传递给编译脚本文件的额外参数，默认为空
    # 参数4：二进制文件的相对路径，默认为 a.out
    def do_compile(self, script, target_path, args="", binary_postfix="a.out"):
        target_path = os.path.abspath(target_path)
        cmd = "%s %s" %(script, target_path)
        cmd = cmd + " " + args
        print(cmd)
        os.system(cmd)
        binary = os.path.join(target_path, binary_postfix)
        if os.path.exists(binary):
            return binary
        else:
            return None

    # 生成目标程序运行命令
    def gen_run_cmd(self, target_binary, input_file="", args=""):
        cmd = Global.testset_info[Global.TESTSET]["cmd"]
        cmd = cmd.replace("$binary", target_binary)
        cmd = cmd.replace("$input", input_file)
        cmd = cmd.replace("$args", args)
        return cmd

    def gen_backtrace_asan(self, output_backtrace, target_binary, input_file, args=""):
        cmd = self.gen_run_cmd(target_binary, input_file, args=args)
        cmd = cmd + " 2> " + output_backtrace
        print(cmd)
        os.system(cmd)

    # 重写该方法
    def compile(self):
        # self.target_binary需要在此确定
        print("compiling...")
        pass
    
    # 有需要则重写该方法
    def gen_groundtruth_backtrace(self):
        self.gen_backtrace_asan(Global.GROUND_TRUTH, self.target_binary, self.poc, args=self.run_args)

    # 重写该方法
    def start_fuzz(self):
        pass

    def wait(self):
        print("|||| Wait process")
        for p in self.process:
            p.wait()
        time.sleep(10)

    def stop_fuzz(self):
        print("============kill fuzzer===============")
        for keyword in self.keywords:
            subprocess.Popen(["pkill", "-f", "%s"%(keyword)])
        self.finish = True

    # 开始运行一个模糊测试
    def run_one(self):
        # 把seeds_source下的所有种子文件拷贝到self.seed_dir下
        os.system("rm -r %s" %(self.seed_dir))
        os.makedirs(self.seed_dir)
        seeds_source = os.path.join(self.target_path, Global.testset_info[Global.TESTSET]["seeds"]) + "/*"
        os.system("cp %s %s"%(seeds_source, self.seed_dir))
        # 编译
        self.compile()
        # 记录crash调用栈
        self.gen_groundtruth_backtrace()
        # 第n次独立重复实验的输出文件夹
        self.round_n_output = os.path.join(Global.output_dir, "%s_%s_round%s"%(self.fuzzer_name, Global.TESTSET, str(self.round_num)))
        if not os.path.exists(self.round_n_output):
            os.makedirs(self.round_n_output)
        # 目标程序的模糊测试结果输出目录
        self.one_output_dir = os.path.join(self.round_n_output, "output_"+self.target_path.strip('/').split('/')[-1])
        self.finish = False
        self.start_fuzz()
        print("%s started, watch on crash dir..." %(self.fuzzer_name))
        watcher = Watcher(self)
        while True:    # 确保crash路径能够被正确地监控
            if os.path.exists(self.crash_dir):
                watcher.watch(self.crash_dir)
                watcher.process_queue(self.target_binary, Global.GROUND_TRUTH)
                break
            time.sleep(1)
        self.wait()
        if not self.finish:
            watcher.abnormal_stop = True
            os.system("rm -rf %s" %(self.one_output_dir))
            time.sleep(5)
        return self.finish
