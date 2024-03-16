#!/usr/bin/python3
import pickle, re, os,sqlite3,json

## ========= match statictics using unix `time` command

# return in seconds
def convert_time(ts) -> float:
    return sum(float(x.strip()) * 60 ** i for i, x in enumerate(reversed(ts.split(':'))))

def match_unix_time(path):
    path = os.path.join(path, 'stderr.txt')
    return convert_time( match_in_file(r'Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): (.*)$', path)[0] )

# return in bytes
def match_unix_time_mem(path):
    path = os.path.join(path, 'stderr.txt')
    return int( match_in_file(r'Maximum resident set size \(kbytes\): (.*)$', path)[0] ) * 1000

def match_unix_time_file(path):
    return convert_time( match_in_file(r'Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): (.*)$', path)[0] )

# return in bytes
def match_unix_time_mem_file(path):
    return int( match_in_file(r'Maximum resident set size \(kbytes\): (.*)$', path)[0] ) * 1000


##========== file operations ==============

def line_match_first(pat, path):
    with open(path, 'r') as f:
        for line in f:
            if ret := re.findall(pat, line):
                return ret

def match_in_file(pat, path):
    return re.findall(pat, read_file(path), re.MULTILINE)

def load_obj(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_json(path):
    with open(path, "rb") as f:
        return json.load(f)

def dump_obj(path, data):
    with open(path, "wb") as f:
        pickle.dump(data, f)

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def read_file_bytes(path):
    with open(path, 'rb') as f:
        return f.read()

def load_py_file(path):
    with open(path, 'r') as f:
        return eval(f.read())

def match_in_str(pat, s):
    import re
    return re.findall(pat, s, re.MULTILINE)

def match_in_file(pat, path):
    import re
    return re.findall(pat, read_file(path), re.MULTILINE)

def match_in_file_bytes(pat, path):
    import re
    return re.findall(pat, read_file_bytes(path), re.MULTILINE)

## ======= other ==========

def average(lst):
    return sum(lst) / len(lst)

def listdir(dataset):
    dataset = dataset.removesuffix('/')
    return [dataset+'/'+i for i in os.listdir(dataset)]

def match_time_stat(filep):
    mem = match_unix_time_mem_file(filep)
    time = match_unix_time_file(filep)
    return time, mem

def match_datas(filep):
    total_stat = match_unix_time_mem_file(f'{filep}/docker_stderr.txt')
    # time = match_unix_time_mem_file(f'{filep}/pre_analysis.log')
    # time = match_unix_time_mem_file(f'{filep}/ghidra_runner.log')
    # time = match_unix_time_mem_file(f'{filep}/java_analysis.log')
    has_apk = os.path.exists(f"{filep}/repacked_apks/repacked.apk")
    # check for run error

def get_percent_from_cov_str(s):
    import re
    mat = re.search(r'block \(([-0-9.]+)\)', s)
    if mat is None:
        print(f"wtf: {s}")
        return -1
    return float(mat[1])

def stats_get_coverage(func_stat):
    return func_stat['coverage_percentage']


def get_so_time_one(fp):
    logf = fp.removesuffix('.so.txt')+'.so.log'
    result = {}
    try:
        result['total'] = float( read_file(fp) )
    except IndexError:
        print(f"Cannot find .so.txt for {fp}")
        raise
    try:
        result['total_script'] = int( match_in_file(r'NativeSummary script execution time: (.*)ms.', logf)[0] ) / 1000.0
    except IndexError:
        print(f"Cannot find script exec time for {logf}")
        raise
        result['total_script'] = None
    return result


def get_so_times(fp):
    result = {}
    for file in os.listdir(fp):
        if file.endswith('.so.txt'):
            result[file.removesuffix('.txt')] = get_so_time_one(os.path.join(fp, file))
    return result
