# -*- coding: utf-8 -*- 
import os, sys, json, math
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import functools

def get_right_crash(crash_dir):
    for one in os.listdir(crash_dir):
        if one.find("the-right-crash") >= 0:
            return one
    return None

def if_has_crash(crash_dir):
    i = 0
    for one in os.listdir(crash_dir):
        i = i + 1
    if i > 0:
        return True
    else:
        return False

def get_fuzz_time(fuzz_stats):
    start_time = None
    last_update = None
    with open(fuzz_stats) as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith("start_time"):
                start_time = line.split(":")[-1].strip()
            if line.startswith("last_update"):
                last_update = line.split(":")[-1].strip()
    return int(last_update) - int(start_time)

def get_fuzz_time_angora(fuzz_stat_json):
    fuzz_stat_json_str = ""
    with open(fuzz_stat_json) as fp:
        fuzz_stat_json_str = fp.read()
    stat = json.loads(fuzz_stat_json_str)
    track_time = stat["track_time"]["secs"] + stat["track_time"]["nanos"]*0.000000001
    fuzz_time = 0
    fuzzes = stat["fuzz"]
    for fuzz in fuzzes:
        fuzz_time = fuzz_time + fuzz["time"]["secs"] + fuzz["time"]["nanos"]*0.000000001
    return track_time, fuzz_time

def get_exec_num(fuzz_stats):
    exec_num = None
    with open(fuzz_stats) as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith("execs_done"):
                exec_num = line.split(":")[-1].strip()
    return int(exec_num)

def get_exec_num_angora(fuzz_stat_json):
    exec_num = None
    fuzz_stat_json_str = ""
    with open(fuzz_stat_json) as fp:
        fuzz_stat_json_str = fp.read()
    stat = json.loads(fuzz_stat_json_str)
    track_execs = stat["num_exec"]
    fuzz_execs = 0
    fuzzes = stat["fuzz"]
    for fuzz in fuzzes:
        fuzz_execs = fuzz_execs + fuzz["num_exec"]
    return track_execs, fuzz_execs

# output_dir为结果存访文件夹
def collect_results(output_dir="./outputs", fuzzer_name="afl"):
    # list dir
    outputs = []
    for one in os.listdir(output_dir):
        output = os.path.join(output_dir, one)
        if os.path.isdir(output):
            outputs.append(output)

    results = []
    for orig_output in outputs:
        output = orig_output
        print(output)
        if not os.path.exists(os.path.join(output, "crashes")):
            output = os.path.join(output, "master")

        crash_dir = os.path.join(output, "crashes")
        print(crash_dir)
        plot_data = os.path.join(output, "plot_data")
        fuzzer_stats = ""
        if fuzzer_name == "angora":
            fuzzer_stats = os.path.join(output, "chart_stat.json")
        else:
            fuzzer_stats = os.path.join(output, "fuzzer_stats")
        result_0 = get_right_crash(crash_dir)

        track_time, track_execs = -1, -1
        if fuzzer_name == "angora":
            track_time, result_1 = get_fuzz_time_angora(fuzzer_stats)
            track_execs, result_2 = get_exec_num_angora(fuzzer_stats)
        else:
            result_1 = get_fuzz_time(fuzzer_stats)
            result_2 = get_exec_num(fuzzer_stats)
        result = {}
        result["id"] = os.path.basename(orig_output).split("output_")[-1]
        result["output_path"] = os.path.abspath(output)
        result["crash_path"] = result_0
        if result_0:
            result["time"] = str(result_1)
        else:
            result["time"] = str(result_1) + ":timeout"
        result["execs"] = result_2
        result["track_time"] = track_time
        result["track_execs"] = track_execs
        results.append(result)
        #print(result["id"])
        #print(result["output_path"])
        #print(result_0)
        #print(result["time"])
        #print(result_2)
        #print("===================================")
    return results


INPUT_BYTES = "INPUT_BYTES"
TAINTED_BYTES = "TAINTED_BYTES"
TAINTED_VARIABLES_NUM = "TAINTED_VARIABLES_NUM"
BUG_TRIGGERING_SPACE = "BUG_TRIGGERING_SPACE"
BUG_TRIGGERING_SPACE_STR = "BUG_TRIGGERING_SPACE_STR"
CONDITIONAL_BRANCH_STMT_NUM = "CONDITIONAL_BRANCH_STMT_NUM"
BUG_UNRELATED_CONSTRAINTS_NUM = "BUG_UNRELATED_CONSTRAINTS_NUM"

def _parse_result_get_testcase_name(line):
    for part in line.split("/"):
        if re.search('IS[0-9]*_TS[0-9]*_TV[0-9]*', part):
            part = part.split("output_")[-1]
            part = part.split("-asan")[0]
            return part

def _parse_result_get_testcase_dir_name(line):
    for part in line.split("/"):
        if re.search('IS[0-9]*_TS[0-9]*_TV[0-9]*', part):
            part = part.split("output_")[-1]
            return part

def _compute(triggering_space):
    parts = triggering_space.split('*')
    r = 1
    for one in parts:
        r = r * int(one, 16)
    return r

def _parse_hardness(hardness_file):
    content = ""
    hardness = {}
    with open(hardness_file) as fp:
        content = fp.readlines()
    for line in content:
        parts = line.split('=')
        hardness[parts[0].strip()] = parts[1].strip()
    hardness[BUG_TRIGGERING_SPACE_STR] = hardness[BUG_TRIGGERING_SPACE]
    hardness[BUG_TRIGGERING_SPACE] = _compute(hardness[BUG_TRIGGERING_SPACE])
    return hardness

def countup(results, ebench_dir):
    result_countup = {}
    for result in results:
        for one in result:
            if one["id"] not in result_countup.keys():
                countup = {}
                countup["time"] = []
                countup["execs"] = []
                countup["track_time"] = []
                countup["output_path"] = []
                result_countup[one["id"]] = countup
                testcase_dir = os.path.join(ebench_dir, one["id"])
                hardness = _parse_hardness(os.path.join(testcase_dir, "hardness"))
                countup["testcase_dir"] = testcase_dir
                countup["hardness"] = hardness
            result_countup[one["id"]]["time"].append(one["time"])
            result_countup[one["id"]]["execs"].append(one["execs"])
            result_countup[one["id"]]["track_time"].append(one["track_time"])
            result_countup[one["id"]]["output_path"].append(one["output_path"])

    total_testcases = 0
    timeout_testcases = 0

    # 计算平均漏洞触发耗时
    # 计算平均运行次数
    # 并观察是否有时而超时时而成功触发的目标程序
    for key in result_countup.keys():
        n = 0
        mt = 0
        me = 0
        mtt = 0
        ot = 0
        oe = 0
        triggered = False
        result_countup[key]["strange"] = False
        for i in range(0, len(result_countup[key]["time"])):
            t = result_countup[key]["time"][i]
            e = result_countup[key]["execs"][i]
            tt = result_countup[key]["track_time"][i]
            if t.find("timeout") < 0:
                triggered = True
                mt = mt + float(t)
                me = me + int(e)
                mtt = mtt + float(tt)
                n = n + 1
            else:
                result_countup[key]["mean_time"] = result_countup[key]["time"][i]
                ot = ot + 1
                oe = oe + result_countup[key]["execs"][i]
                if triggered:
                    result_countup[key]["strange"] = True

        if ot < len(result_countup[key]["time"]) :
            mt = mt / n
            mtt = mtt / n
            me = me / n
            result_countup[key]["mean_time"] = mt
            result_countup[key]["mean_execs"] = me
            result_countup[key]["mean_track_time"] = mtt
        else:
            #result_countup[key]["mean_time"] = -1
            result_countup[key]["mean_execs"] = oe / ot
            result_countup[key]["mean_track_time"] = -1

    # 计算漏洞触发难度
    for key in result_countup.keys():
        bn = result_countup[key]["hardness"][TAINTED_BYTES]
        ts = result_countup[key]["hardness"][BUG_TRIGGERING_SPACE]
        result_countup[key]["space"] = pow(2,int(bn)*8)/int(ts)
    # 计算目标程序被运行次数期望
    #for key in result_countup.keys():
    #    ib = result_countup[key]["hardness"][INPUT_BYTES]
    #    bn = result_countup[key]["hardness"][TAINTED_BYTES]
    #    ts = result_countup[key]["hardness"][BUG_TRIGGERING_SPACE]
    #    S = pow(2, int(ib)*8)
    #    N = ts * pow(2, (int(ib)-int(bn))*8)
    #    E = 0
    #    print(S)
    #    print(N)
    #    for k in range(1, int(S-N+1)):
    #        tmp = 1.0
    #        for i in range(0, k-1):
    #            tmp = tmp * (S-N-k)/(S-k)
    #        E = E + k * tmp
    #    result_countup[key]["expectation"] = E

    return result_countup


def display(result):
    sorted_result = sorted(result.items(), key=lambda d:(d[1]["space"], d[1]["hardness"][TAINTED_VARIABLES_NUM]))
    y = []
    x_label = []
    for one in sorted_result:
        key = one[0]
        #if int(result[key]["hardness"][TAINTED_VARIABLES_NUM]) == 1:
        #if result[key]["mean_time"] == -1:
        if True:
            #print(key)
            print("%s -- exectime:%s(%s), execs:%s(%d), space:%s, %d, isstrange:%s" %(key, str(result[key]["time"]), str(result[key]["mean_time"]), str(result[key]["execs"]), result[key]["mean_execs"], result_countup[key]["hardness"][BUG_TRIGGERING_SPACE_STR], result_countup[key]["space"], str(result_countup[key]["strange"])))
            if type(result[key]["mean_time"]) != type(""):
                y.append(round(math.log10(result[key]["mean_time"]), 2))
                x_label.append(key)

    bar_width = 0.35
    x = np.arange(len(x_label))
    plt.bar(x, y, bar_width, hatch='/', align="center", color="red", alpha=0.5)
    plt.savefig("tt.pdf", format="pdf")
    


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("python show_result.py output_dir, benchmark_dir, fuzzer_name")
        exit(0)
    output_dir = sys.argv[1]
    ebench_dir = sys.argv[2]
    fuzzer_name = sys.argv[3]
    results = []
    for d in os.listdir(output_dir):
        d = os.path.join(output_dir, d)
        print(d)
        result = collect_results(d, fuzzer_name)
        results.append(result)
    result_countup = countup(results, ebench_dir)
    display(result_countup)
