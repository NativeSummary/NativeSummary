#!/usr/bin/python3

import sys
import subprocess
import os
import time

# set PYTHON3c=python
# set JAVA=C:\Program Files\Java\jdk-13\bin\java.exe
# set JAVA8=C:\Program Files\Java\jre1.8.0_341\bin\java.exe
python3_path = os.getenv("PYTHON3", default='/usr/bin/python3')
java_path = os.getenv("JAVA", default='/usr/bin/java')
BINARY_TIMEOUT = os.getenv("BINARY_TIMEOUT", default=None)
# java8_path = os.getenv("JAVA8", default='/usr/lib/jvm/java-8-openjdk-amd64/bin/java')
cmd = sys.argv[1] if len(sys.argv) >= 2 else None
args = sys.argv[2:] if len(sys.argv) >= 2 else []
if cmd is not None and cmd[0] == '-':
    args = [cmd] + args
    cmd = None

project_root = os.path.dirname(os.path.realpath(__file__))

# print(f"cmd: {cmd}, args:{args}, argv: {sys.argv}")
def main():
    if cmd == "pre":
        pre_analysis(*args)
    elif cmd == "bin":
        binary_analysis(*args)
    elif cmd == "java":
        java_analysis(*args)
    elif cmd == "all" or cmd == None:
        analyze(*args)
    else:
        print_help()

def print_help():
    help_text = '''arg1: command
possible commands:
1. "pre" pre-analysis
2. "bin" binary analysis
3. "java" java analysis
4. "all" run all analysis
'''
    print(help_text)

def run_command(args):
    print(' '.join(args))
    return subprocess.run(args)

def run_and_save_output(args, log_file):
    print(' '.join(args))
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    with open(log_file, 'w') as f:
        while True:
            data = proc.stdout.readline()
            if not data:
                break
            # write to both stdout and file.
            sys.stdout.write(data)
            sys.stdout.flush()
            f.write(data)
    return proc.wait()


def pre_analysis(*args, log_file=None):
    if log_file:
        ret = run_and_save_output(["/usr/bin/time", "-v", python3_path, "/root/preana.py"] + list(args), log_file)
    else:
        ret = run_command(["/usr/bin/time", "-v", python3_path, "/root/preana.py"] + list(args))
    return ret

# "C:\Users\xxx\NativeFlowBenchPreAnalysis32\native_complexdata.native_summary\project" "native_summary" -import "C:\Users\xxx\NativeFlowBenchPreAnalysis32\native_complexdata.native_summary\libdata.so" "-postScript" "NativeSummary"
def binary_analysis(*args, log_file=None):
    runner_path = os.path.join(project_root, "runner.py")
    cmd_prefix = []
    if BINARY_TIMEOUT:
        assert log_file, "BINARY_TIMEOUT set but log_file not set."
        cmd_prefix = ["/usr/bin/timeout", "--kill-after=60s", BINARY_TIMEOUT]
    if log_file:
        ret = run_and_save_output(["/usr/bin/time", "-v"] + cmd_prefix + [python3_path, runner_path]+list(args), log_file)
    else:
        ret = run_command(["/usr/bin/time", "-v", python3_path, runner_path]+list(args))
    return ret

def java_analysis(*args, log_file=None):
    jar_path = os.path.join(project_root, "native_summary-1.0-SNAPSHOT.jar")
    if log_file:
        ret = run_and_save_output(["/usr/bin/time", "-v", java_path, "-Xss4m", "-jar", jar_path]+list(args), log_file)
    else:
        ret = run_command(["/usr/bin/time", "-v", java_path, "-Xss4m", "-jar", jar_path]+list(args))
    return ret

def analyze(*args):
    start = time.time()
    import argparse
    parser = argparse.ArgumentParser(description=f'NativeSummary project - docker entrypoint')
    parser.add_argument('--apk', type=str, default='/apk', help='apk path')
    parser.add_argument('--out', type=str, default='/out', help='output path')
    parser.add_argument('--process', default=1, type=int, help="multiprocessing process count. default: 1 (single process) (depricated)")
    parser.add_argument('--taint', action='store_true', help="run flowdroid after the analysis")
    args = parser.parse_args(args)
    input_path = args.apk
    out_path = args.out
    apk_out_path = os.path.join(out_path, "repacked_apks")
    process = str(args.process)
    platforms = os.path.join(project_root, "platforms")
    if not os.path.exists(out_path):
        os.makedirs(out_path, exist_ok=True)
    path1 = os.path.join(out_path, "pre_analysis.log")
    pre_analysis(input_path, out_path, "--process", process, log_file=path1)
    path3 = os.path.join(out_path, "ghidra_runner.log")
    binary_analysis(out_path, '--process', process, log_file=path3)
    path2 = os.path.join(out_path, "java_analysis.log")
    java_analysis(input_path, out_path, platforms, "--out", apk_out_path, "--debug-jimple", log_file=path2)
    print("NativeSummary docker script running time: " + str(time.time() - start))
    # if args.taint:
    #     run_command(["bash", "/root/run_flowdroid.sh", "/out"])

if __name__ == '__main__':
    main()
