import sys, os


def gen_buckets_for_EBench(dir_to_ebench, vol, prefix):
    files = os.listdir(dir_to_ebench)
    index = 0
    num = len(files)/vol + 1
    for one in files:
        one = os.path.join(dir_to_ebench, one)
        with open("%s_%d"%(prefix, index/vol), "a+") as fp:
            fp.write(one + "\n")
        index = index + 1


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("USE: python bucket.py PATH BUCKET_VOLUME NAME")
        exit(0)
    path = sys.argv[1]
    vol = int(sys.argv[2])
    prefix = sys.argv[3]
    gen_buckets_for_EBench(path, vol, prefix)
