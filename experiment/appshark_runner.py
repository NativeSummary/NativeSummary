from .utils import *
import os

limit_cmd_template = 'systemd-run --scope --same-dir --collect {} bash -c "{}"'  # --wait
time_cmd_template = '/usr/bin/time -v {} {} 1> {} 2> {}'
tool_cmd_template = '/usr/lib/jvm/java-11-openjdk-amd64/bin/java {} -jar /home/user/ns/tools/appshark-0.1.2/AppShark-0.1.2-all.jar {}'


def run_appshark(fpath, out_path, ss_file, max_memory=None, max_cpu=None, timeout=None, timeout_kill_after='60s',
                 max_pointer_analyze_time='1800', max_thread='1', trace_depth='10', print_for_xargs=True, jvm_max_heap=None,
                 rerun=True):
    '''
    max_memory: example: 6G
    max_cpu: in percentage, for example: 100%
    '''
    if not rerun:
        # check if already run
        if os.path.exists(os.path.join(out_path, 'vulnerability','0-InfoFlow.html')):
            return None
    ss_file = convert_ss_file(out_path, ss_file, trace_depth=trace_depth)
    config_file = gen_run_config(
        fpath, out_path, ss_file, max_pointer_analyze_time=max_pointer_analyze_time, max_thread=max_thread)
    stdout_path = os.path.join(out_path, 'stdout.txt')
    stderr_path = os.path.join(out_path, 'stderr.txt')

    jvm_args = ''
    if jvm_max_heap is not None:
        jvm_args += f'  -Xmx{jvm_max_heap} '
    tool_cmd = tool_cmd_template.format(jvm_args, config_file)

    timeout_args = ''
    if timeout is not None:
        timeout_args += ' /usr/bin/timeout '
        if timeout_kill_after is not None:
            timeout_args += f' --kill-after={timeout_kill_after} '
        timeout_args += f' {timeout} '
    time_cmd = time_cmd_template.format(
        timeout_args, tool_cmd, stdout_path, stderr_path)

    # limit memory and cpu
    limit_cmd_args = ''
    if max_memory is not None:
        limit_cmd_args += f' -p MemoryMax={max_memory} '
    if max_cpu is not None:
        limit_cmd_args += f' -p CPUQuota={max_cpu} '
    if len(limit_cmd_args) > 0:
        time_cmd = limit_cmd_template.format(limit_cmd_args, time_cmd)

    if print_for_xargs:
        print(time_cmd, end='\x00')
    return time_cmd


run_config_template = '''{{
  "apkPath": "{}",
  "out": "{}",
  "rules": "{}",
  "maxPointerAnalyzeTime": {},
  "configPath": "/home/user/ns/tools/appshark-0.1.2/config",
  "maxThread": {}
}}'''
rule_path = "/home/user/ns/tools/appshark-0.1.2/config/rules"

taint_config_base = '''{
  "native_summary": {
    "SliceMode": true,
    "PrimTypeAsTaint": true,
    "source": {
      "Return": [
        ]
    },
    "traceDepth": 10,
    "desc": {
      "name": "InfoFlow",
      "category": "Common",
      "detail": "no detail.",
      "wiki": "",
      "possibility": "4",
      "model": "middle"
    },
    "sink": {
      "<android.util.Log: * d(*)>": {
        "TaintCheck": [
          "p*"
        ]
      },
      "<android.util.Log: * e(*)>": {
        "TaintCheck": [
          "p*"
        ]
      },
      "<android.util.Log: * i(*)>": {
        "TaintCheck": [
          "p*"
        ]
      },
      "<android.util.Log: * w(*)>": {
        "TaintCheck": [
          "p*"
        ]
      },
      "<android.util.Log: * v(*)>": {
        "TaintCheck": [
          "p*"
        ]
      }
    }
  }
}'''

taint_sink_obj = '''{
    "TaintCheck": [
        "p*"
    ]
}'''


def convert_ss_file(out_path, ss_file, trace_depth='10'):
    ss = read_file(ss_file)
    obj = convert_ss(ss)
    obj["native_summary"]["traceDepth"] = trace_depth
    os.makedirs(os.path.join(out_path, "taint"), exist_ok=True)
    out_path = os.path.join(out_path, "taint", "taint_rule.json")
    write_json_file(out_path, obj)
    return out_path


def convert_ss(ss):
    ss = parse_ss(ss.split('\n'))
    base_obj = json.loads(taint_config_base)
    for sig, ty in ss:
        # print(f'{sig} is {ty}',file=sys.stderr)
        if ty == '_SOURCE_':
            base_obj["native_summary"]["source"]["Return"].append(sig)
        elif ty == '_SINK_':
            base_obj["native_summary"]["sink"][sig] = json.loads(
                taint_sink_obj)
        else:
            print(f'error!: Unknown Type {ty} ( {sig} )', file=sys.stderr)
            raise RuntimeError()
    return base_obj


def parse_ss(lines):
    ret = []
    for line in lines:
        line = line.strip()
        if len(line) == 0:
            continue
        if line.startswith("%"):
            continue
        # fix: no single quotes
        line = line.replace("'", "")
        parts = line.split('->', 1)
        parts = (p.strip() for p in parts)
        ret.append(parts)
    return ret


def gen_run_config(fpath, out_path, ss_file, max_pointer_analyze_time='1800', max_thread='1'):
    ss_file = os.path.relpath(ss_file, start=rule_path)
    config_str = run_config_template.format(
        fpath, out_path, ss_file, max_pointer_analyze_time, max_thread)
    out_path = os.path.join(out_path, "run.json5")
    write_file(out_path, config_str)
    return out_path
