#!/usr/bin/python3
import pickle, re, os,sqlite3,json,sys

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

from pprint import PrettyPrinter

class NoStringWrappingPrettyPrinter(PrettyPrinter):
    def _format(self, object, *args):
        if isinstance(object, str):
            width = self._width
            self._width = sys.maxsize
            try:
                super()._format(object, *args)
            finally:
                self._width = width
        else:
            super()._format(object, *args)

def pprint_obj(path, obj):
    with open(path, 'w') as f:
        f.write(NoStringWrappingPrettyPrinter().pformat(obj))

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

def write_json_file(path, obj):
    with open(path, 'w') as f:
        json.dump(obj, f)

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

def flatten_dict_list(obj):
    ret = []
    for key, arr in obj.items():
        for val in arr:
            ret.append((key, val))
    return ret

def random_sample_dict(d, count):
    import random
    out = {}
    for i in random.sample(list(d), count):
        out[i] = d[i]
    return out


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

def multiline_input():
    contents = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        contents.append(line)
    return '\n'.join(contents)


def dialog_input(title='title', prompt='input', default=None):
    """
    Example:
    >>> strinput("RIG CONFIG", "Insert RE com port:", default="COM")
    """
    import tkinter as tk
    from tkinter import simpledialog
    root = tk.Tk()
    root.withdraw()
    ans = simpledialog.askstring(title, prompt, initialvalue=default)
    return ans

class TextInputPopup:
    def __init__(self, root):
        import tkinter as tk
        self.root = root
        self.root.title("Input")
        self.user_input = ""

        # 创建一个 Text 组件用于多行文本输入
        self.text = tk.Text(self.root, height=10, width=50)
        self.text.pack()

        # 创建一个确定按钮，当点击时会调用 self.close 方法
        self.button = tk.Button(self.root, text="Confirm", command=self.close)
        self.button.pack()

    def close(self):
        # 获取 Text 组件中的所有文本并去除尾部的换行符
        self.user_input = self.text.get("1.0", "end-1c")
        self.root.destroy()

    def show(self):
        self.root.mainloop()
        return self.user_input  # 返回用户输入的内容

def dialog_input_multiline():
    import tkinter as tk
    root = tk.Tk()
    popup = TextInputPopup(root)
    user_input = popup.show()
    return user_input


def vscode_input(path,prompt, default = None):
    print(prompt)
    if default is not None:
        write_file(path, default)
    else:
        # truncate
        os.system(f"> {path}")
    os.system(f"code -r -w {path}")
    return read_file(path)

def open_in_vscode(path):
    os.system(f"code -r {path}")

def input_with_default(prompt, default):
    res = input(prompt)
    if len(res.strip()) == 0:
        return default
    return res

def input_sth(prompt):
    res = ''
    while len(res.strip()) <= 0:
        res = input(prompt)
    return res.strip()
