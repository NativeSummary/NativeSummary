import pickle,os,collections
import xml.etree.ElementTree as ET
from functools import cached_property
from .utils import *

class NSDataDict(dict):
    def __missing__(self, key):
        self[key] = NSStats(key)
        return self[key]

ns_data_dict = NSDataDict()

class NSStats:
    native_methods = None
    def __init__(self, result_path:str, debug:bool=False) -> None:
        self.result_path = result_path
        self.debug = debug
        self.data = {}

    @cached_property
    def time(self):
        try:
            return match_unix_time_file(f"{self.result_path}/docker_stderr.txt")
        except IndexError:
            raise
            print(f"Cannot find time mem.??!! {filep}/docker_stderr.txt")

    @cached_property
    def memory(self):
        try:
            return match_unix_time_mem_file(f"{self.result_path}/docker_stderr.txt")
        except IndexError:
            raise
            print(f"Cannot find time mem.??!! {filep}/docker_stderr.txt")

    @cached_property
    def has_apk(self):
        ret = os.path.exists(f"{self.result_path}/repacked_apks/repacked.apk")
        if ret == False and self.debug:
            if not os.path.exists(f'{self.result_path}/java_analysis.log'):
                print("No apk: java not run.")
                # shutil.rmtree(dir)
            else:
                path = f'{self.result_path}/java_analysis.log'
                if (match_in_file(r'StackOverflowError', path)):
                    print(f"No apk: stackoverflow error {path}")
                elif match_in_file(r'Unexpected inner class annotation element', path):
                    print(f'soot error: Unexpected inner class. {path}')
                elif match_in_file(r'Trying to cast reference type java\.lang\.Object to a primitive', path):
                    print(f'soot error: cast reference type java\.lang\.Object to a primitive {path}')
                elif match_in_file(r'StmtSwitch: type of throw argument is not a RefType', path):
                    print(f'soot error: type of throw argument is not a RefType {path}')
                elif match_in_file(r'cannot set active body for phantom class', path):
                    print(f'apk packer: cannot set active body for phantom class {path}')
                elif match_in_file(r'Load semantic summary failed', path):
                    pass
                    # print(f'No apk: no summary: {path}')
                else:
                    print(f"No apk: {path}")
        return ret

    @cached_property
    def has_xml(self):
        fd_xml_path = f"{self.result_path}/repacked_apks/fd.xml"
        ret = os.path.exists(fd_xml_path) and os.path.getsize(fd_xml_path) > 0
        if self.debug:
            self.debug = False; has_apk = self.has_apk(); self.debug = True
            if has_apk and not ret:
                path = f'{self.result_path}/repacked_apks/fd.stderr.txt'
                if match_in_file(r'because "targetVal" is null', path):
                    print(f'error: no xml: because "targetVal" is null {path}')
                    # shutil.rmtree(filep)
                elif match_in_file(r'Attempt to create VarNode', path):
                    print(f'error: Attempt to create VarNode: {path}')
                elif match_in_file(r'Found 0 leaks', path):
                    print(f'error: no xml: no leak {path}')
                elif (ns_time := self.time()) > 7199:
                    print(f"error: no xml: timeout.")
                else:
                    print(f"error: no xml ({ns_time}): {path}")
        return ret

    @cached_property
    def time_pre(self):
        '''
        Pre-analysis time
        '''
        return match_unix_time_file(f'{self.result_path}/pre_analysis.log')
    @cached_property
    def time_binary(self):
        '''
        Binary analysis time = Ghidra Loading Time + BinAbsInspector Time
        '''
        return match_unix_time_file(f'{self.result_path}/ghidra_runner.log')
    @cached_property
    def time_bai(self):
        '''BinAbsInspector Time'''
        detailed_time = self.time_share_objects
        script_times = []
        for so_name, so_detailed_time in detailed_time.items():
            script_times.append(so_detailed_time['total_script'])
        return sum(script_times)
    @cached_property
    def time_ghidra(self):
        '''Ghidra Loading Time'''
        return self.time_binary - self.time_bai
    @cached_property
    def time_java(self):
        return match_unix_time_file(f'{self.result_path}/java_analysis.log')
    @cached_property
    def time_fd(self):
        return match_unix_time_file(f'{self.result_path}/repacked_apks/fd.stderr.txt')
    @cached_property
    def time_share_objects(self):
        return get_so_times(self.result_path)
    @cached_property
    def ns_edges(self):
        '''
        returns j2n_find_count(Native Method Analyzed), j2n_success_count(Native Method Succeeded), n2j_find_count, n2j_success_count(Native Edges Created)
        '''
        ana, t = parse_ns_edges_analyzed(self.result_path)
        jimp = os.path.join(self.result_path, '02-built-bodies.jimple')
        m, p, c, con =parse_jimple_edges_count(read_file(jimp))
        return ana, m, c+con, c+con
    @cached_property
    def jni_times(self):
        return ns_get_jni_times(self.result_path)
    @cached_property
    def flow_count(self):
        return len(get_flow_set(f'{self.result_path}/repacked_apks/fd.xml'))
    @cached_property
    def native_flow_count(self):
        '''
        native related flow count
        '''
        # assume the apk name is the result folder name
        apk_name = os.path.dirname(self.result_path)
        return len(get_native_flow(f'{self.result_path}/repacked_apks/fd.xml', apk_name, NSStats.native_methods))
    # ========jimple and IR============
    @cached_property
    def jimple_path(self):
        return f'{self.result_path}/02-built-bodies.jimple'
    @cached_property
    def summary_ir_paths(self):
        return [i for i in listdir(self.result_path) if i.endswith('.ll')]
    @cached_property
    def jimple_funcs(self):
        jimple = read_file(self.jimple_path)
        formated = jimple.replace('\n\n', '\n')
        funcs = formated.split('}\n')[:-1]
        return [f + '}' for f in funcs]
    @cached_property
    def summary_ir_funcs(self):
        result = {}
        for file in self.summary_ir_paths:
            ir = read_file(file)
            formated = re.sub(r'\s+;.*', '', ir)
            funcs = formated.split('\ndefine ')[1:]
            result[os.path.basename(file)] = funcs
        return result

def is_ir_func(func, func_name):
    '''
    check if this ir func string's func name is func_name
    '''
    return func_name + '(' in func.split('\n')[0]

def is_jimple_func(jimple, func_name):
    '''
    check if this jimple func string's func name is func_name
    '''
    return f" {func_name}(" in jimple.split('\n')[0]

def get_func_from_invoke(native_part):
    # 匹配空格，字符，左括号
    return re.search(r' ([^\(\)<> {}]+)\(', native_part).group(1)

def convert_source_or_sink(elem):
    return (elem.attrib['Method'], elem.attrib['Statement'])


def get_flow_set(path):
    root = ET.parse(path).getroot()
    ret = set()
    for result in root.findall('./Results/Result'):
        assert result[0].tag == 'Sink'
        assert result[1].tag == 'Sources'
        sink = convert_source_or_sink(result[0])
        # sources = []
        for sour in result[1]:
            assert sour.tag == 'Source'
            # sources.append(convert_source_or_sink(sour))
            ret.add((sink, convert_source_or_sink(sour)))
    return ret


def get_flow_set_iter(path):
    root = ET.parse(path).getroot()
    for result in root.findall('./Results/Result'):
        assert result[0].tag == 'Sink'
        assert result[1].tag == 'Sources'
        sink = convert_source_or_sink(result[0])
        # sources = []
        for sour in result[1]:
            assert sour.tag == 'Source'
            # sources.append(convert_source_or_sink(sour))
            yield (sink, convert_source_or_sink(sour))


# 为每个apk的结果，找出里面和native相关的部分。
# map: flow set -> [(native flow xml, native part)]
def get_native_flow(path, apkname, native_methods, filter_set=None):
    ret = collections.defaultdict(lambda:[])
    # print(path)
    nms = native_methods[apkname]
    root = ET.parse(path).getroot()

    for result in root.findall('./Results/Result'):
        assert result[0].tag == 'Sink'
        assert result[1].tag == 'Sources'
        sink = convert_source_or_sink(result[0])
        # sources = []
        for sour in result[1]:
            assert sour.tag == 'Source'
            # sources.append(convert_source_or_sink(sour))
            sspair = (sink, convert_source_or_sink(sour))
            if filter_set is not None:
                if sspair not in filter_set:
                    continue
            native_parts = []
            for pe in sour.findall('./TaintPath/PathElement'):
                call_stmt = pe.attrib['Statement']
                if contains_native_method(nms, call_stmt):
                    native_parts.append(call_stmt)
            if len(native_parts) != 0:
                ret[sspair].append(native_parts) # ET.tostring(sour)
    return dict(ret)

def dot2sig(clz):
    return f"L{clz.replace('.','/')};"

def contains_native_method(nms, stmt):
    for clz,name,desc,access in nms:
        if 'NativeSummary' in stmt:
            return True
        if f'<{clz}' in stmt and f'{name}(' in stmt: # todo
            return True
    return False


def ns_get_jni_times(path):
    ret = {}
    timeout_map = {}
    # to_remove = set()
    for file in os.listdir(path):
        if not file.endswith('.perf.json'):
            continue
        fp = os.path.join(path, file)
        json_data = load_json(fp)
        for func in json_data['functions']:
            if func['name'] == 'JNI_OnLoad': continue
            methodname = func['name'].encode()
            signature = func['signature'].replace(' ', '').encode()
            if 'class' not in func:
                # if (methodname, signature) in ret:
                #     to_remove.add((methodname, signature))
                ret[(methodname, signature)] = func['time_ms'] / 1000.0
                timeout_map[(methodname, signature)] = func['is_timeout']
            else: # normal
                classname = func['class'].removeprefix('L').removesuffix(';').replace('/', '.').encode()
                ret[(classname, methodname, signature)] = func['time_ms'] / 1000.0
                timeout_map[(classname, methodname, signature)] = func['is_timeout']
    return ret, timeout_map


# parse analyzed edge in log
# remove trivial edge.
def parse_ns_edges_analyzed(dir):
    times = []
    analyzed = set()
    for f in os.listdir(dir):
        if not f.endswith('.so.log'): continue
        fd = os.path.join(dir, f)
        data = read_file_bytes(fd)
        # 给java_的去重，其他的不去重
        times_lj = {}
        times_l = []
        analyzed_l = set()
        for mat in match_in_str(rb'Analysis spent (.*) ms for (\S*)', data):
            if b'JNI_OnLoad' in mat[1]: continue
            if mat[1].startswith(b'Java_'):
                times_lj[mat[1]] = float(mat[0]) / 1000
            else:
                times_l.append(float(mat[0]) / 1000)
            # 
        for mat in match_in_str(rb'Running solver on (.*) function', data):
            if b'JNI_OnLoad' in mat: continue
            analyzed_l.add(mat)
        # assert abs(len(analyzed_l) - len(times_lj) - len(times_l)) <= 1
        times += list(times_lj.values())
        times += times_l
        analyzed.update(analyzed_l)
    return len(analyzed), times

def function_has_edges(jimp):
    funcs = jimp.split('}')[:-1]
    total_count = len(funcs)
    has_edges = []
    for func in funcs:
        m, p, c, con = parse_jimple_edges_count(func)
        if c+con > 0:
            has_edges.append(func)
    return total_count, has_edges

def parse_jimple_edges(jimp):
    import re
    jimp = re.sub(r'public static .* JNI_OnLoad\(.*\)$\n\s*{[^}]*}', "", jimp) # exclude jni_onload
    mths = match_in_str(r'^ *(.*\))\s*{', jimp)
    mths = set([i for i in mths if 'JNI_OnLoad' not in i and '"' not in i])
    all_possible_calls = match_in_str(r'^ *(([^\(]* = )?(.*))\(.*\);', jimp)
    specialinvokes = [i for i in all_possible_calls if 'specialinvoke' in i[2]]
    possible_calls = set([i[2] for i in all_possible_calls if 'NativeSummary' not in i[2] and 'valueOf' not in i[2] and 'toString' not in i[2]])
    for i in all_possible_calls:
        assert len(i[2]) > 0
    calls = set([i for i in possible_calls if 'specialinvoke' not in i and 'android.util.Log.' not in i])
    # calls = match_in_str(r'^ *((.* = )?([a-zA-Z0-9_.$]*))\(.*\);', jimp)
    # calls = set([i[2] for i in calls if 'NativeSummary' not in i[2] and 'valueOf' not in i[2] and 'toString' not in i[2]])
    special_calls = match_in_str(r'new (.*);\n+ *specialinvoke .*\.<init>', jimp)
    scc = len(special_calls)
    special_calls = set(special_calls)

    # todo_set = possible_calls.difference(calls)

    assert len(specialinvokes) == scc

    # if len(todo_set) > 0:
    #     pass
    return mths, possible_calls, calls, special_calls

# parse successfully created edge in jimple file
# remove trivial edge.
def parse_jimple_edges_count(jimp):
    mths, possible_calls, calls, special_calls = parse_jimple_edges(jimp)
    return len(mths), len(possible_calls), len(calls), len(special_calls)


def load_native_methods(path):
    with open(path, "rb") as f:
        NSStats.native_methods = pickle.load(f)

