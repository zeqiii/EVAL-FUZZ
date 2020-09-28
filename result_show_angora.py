# -*- coding: utf-8 -*- 
import os, sys, json


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
    track_time = stat["track_time"]["secs"]
    fuzz_time = 0
    fuzzes = stat["fuzz"]
    for fuzz in fuzzes:
        fuzz_time = fuzz_time + fuzz["time"]["secs"]
    return track_time + fuzz_time


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
    return track_execs + fuzz_execs

def find_missing(output_dir="./outputs"):
    outputs = []
    LAVA1 = []
    for one in os.listdir(output_dir):
        _id = one.split("output_")[-1].strip()
        outputs.append(_id)
    for one in os.listdir("./LAVA-1"):
        if one.startswith("file-5.22."):
            LAVA1.append(one)
    for one in LAVA1:
        if one not in outputs:
            print("##################")
            print(one)
            print("##################")


# output_dir为结果存访文件夹
def collect_results(output_dir="./outputs"):
    # list dir
    outputs = []
    for one in os.listdir(output_dir):
        output = os.path.join(output_dir, one)
        if os.path.isdir(output):
            outputs.append(output)

    _id = 0
    results = []
    for output in outputs:
        if not os.path.exists(os.path.join(output, "crashes")):
            output = os.path.join(output, "master")
        crash_dir = os.path.join(output, "crashes")
        fuzzer_stats = os.path.join(output, "chart_stat.json")
        plot_data = os.path.join(output, "plot_data")
        result_0 = get_right_crash(crash_dir)
        #result_0 = if_has_crash(crash_dir)
        result_1 = get_fuzz_time_angora(fuzzer_stats)
        result_2 = get_exec_num_angora(fuzzer_stats)
        result = {}
        result["id"] = _id
        result["output_path"] = os.path.abspath(output)
        result["crash_path"] = result_0
        if result_0:
            result["time"] = result_1
        else:
            result["time"] = str(result_1) + ":timeout"
        result["execs"] = result_2
        results.append(result)
        _id = _id + 1
        print(_id)
        print(result["output_path"])
        print(result_0)
        print(result["time"])
        print(result_2)
        print("===================================")
    return results


if __name__ == "__main__":
    outputs = sys.argv[1]
    result2 = collect_results(outputs)
    #find_missing(outputs)
