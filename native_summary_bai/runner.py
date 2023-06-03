import os,sys,time
from shutil import rmtree

# analyzeHeadless <project_location> <project_name>[/<folder_path>] 
# [[-import [<directory>|<file>]+] | [-process [<project_file>]]]
#         [-preScript <ScriptName> [<arg>]*]
#         [-postScript <ScriptName> [<arg>]*]

# project_folder binary_path
GHIDRA_DIR = os.getenv("GHIDRA_INSTALL_DIR", "/opt/ghidra_10.1.2_PUBLIC")


if sys.platform == 'win32':
    tee_template = 'powershell "{} | tee {}"'
    cmd = GHIDRA_DIR + '/support/analyzeHeadless.bat {} native_summary -import {} -postScript NativeSummary'
else:
    tee_template = 'bash -c "{} | tee {}"'
    cmd = GHIDRA_DIR + '/support/analyzeHeadless {} native_summary -import {} -postScript NativeSummary'



def analyze_one(p, proj_path):
    os.makedirs(proj_path, exist_ok=True)
    t = time.time()
    preana_folder = os.path.dirname(p)
    # proj_path = os.path.join(preana_folder, 'project')
    # if (os.path.exists(proj_path)):
    #     if exist == 'redo':
    #         rmtree(proj_path)
    #     elif exist == 'skip':
    #         return
    # # return # here and repo can delete all project folder
    # os.makedirs(proj_path, exist_ok=True)
    cmd_ = cmd.format(proj_path, p)
    print(cmd_)
    cmd_ = tee_template.format(cmd_, p+'.log')
    os.system(cmd_)
    t = time.time() - t
    with open(p+'.txt', 'w') as f:
        f.write(str(t))

def get_project(folder_path):
    proj_path = os.path.join(folder_path, 'project')
    return proj_path

def check_analyzed(folder_path):
    return os.path.exists(get_project(folder_path))

def mp_run(args_list, process_count):
    from multiprocessing import Process, Queue
    processes = [None for i in range(process_count)]
    folders = [None for i in range(process_count)]
    times = [None for i in range(process_count)]
    try:
        for i in range(process_count):
            if len(args_list) > 0:
                # TODO arg
                args = args_list.pop(0)
                processes[i] = Process(target=analyze_apk_folder, args=args)
                processes[i].start()
                folders[i] = args[0]
                times[i] = time.time()
        # keep checking process state, processed the return value, and a new process will be started
        while processes.count(None) < process_count:
            for i in range(process_count):
                process = processes[i] #type: Process
                if process != None and (not process.is_alive()):
                    # process terminates
                    if len(args_list) > 0:
                        args = args_list.pop(0)
                        processes[i] = Process(target=analyze_apk_folder, args=args)
                        processes[i].start()
                        folders[i] = args[0]
                        times[i] = time.time()
                    else:
                        processes[i] = None
                        times[i] = None
                        folders[i] = None
                    break
            else:
                time.sleep(3)
    except KeyboardInterrupt:
        # Terminates all processes and deletes their progress if an exception is encountered
        for i in range(process_count):
            process = processes[i] #type: Process
            if process != None:
                process.terminate()
                time.sleep(1)
                print(f"deleting {get_project(folders[i])}")
                rmtree(get_project(folders[i]))

def analyze_apk_folder(folder_path, exist='skip'):
    proj_path = get_project(folder_path)
    if check_analyzed(folder_path):
        if exist == 'redo':
            rmtree(proj_path)
        elif exist == 'skip':
            print(f"skip {folder_path}.")
            return
    for f in os.listdir(folder_path):
        if not f.endswith('.so'):
            continue
        if not os.path.exists(os.path.join(folder_path, f+'.funcs.json')):
            print(f"funcs.json not exist for {f}")
            continue
        print(f"[!] ================== Analyzing {f} ============================")
        analyze_one(os.path.join(folder_path, f), proj_path)

def analyze_apks(folder, process_count=1, exist='skip'):
    mp_to_run = [] # for multiprocessing

    dirs = os.listdir(folder)
    dirs.sort()
    for apk_folder in dirs:
        apk_folder = os.path.join(folder, apk_folder)
        if not os.path.isdir(apk_folder):
            continue
        # if apk_folder[:7] <= '00dc701':
        #     continue

        proj_path = get_project(apk_folder)
        if check_analyzed(apk_folder):
            if exist == 'redo':
                rmtree(proj_path)
            elif exist == 'skip':
                print(f"skip {apk_folder}.")
                continue
        if not (process_count > 1): # single process
            print(f"Analyzing apk {apk_folder}")
            analyze_apk_folder(apk_folder, exist)
        else:
            mp_to_run.append((apk_folder, exist))
    if process_count > 1:
        mp_run(mp_to_run, process_count)

def remve_all_project_folder(folder):
    for apk_folder in os.listdir(folder):
        apk_folder = os.path.join(folder, apk_folder)
        if not os.path.isdir(apk_folder):
            continue
        proj_path = get_project(apk_folder)
        if check_analyzed(apk_folder):
            rmtree(proj_path)
        remove_all_serialized_obj(apk_folder)

def remove_all_serialized_obj(apk_folder):
    for file in os.listdir(apk_folder):
        if file.endswith('.summary.java_serialize'):
            os.remove(os.path.join(apk_folder, file))

def main():
    import argparse
    parser = argparse.ArgumentParser(description=f'NativeSummary project - binary analysis')
    parser.add_argument('path', metavar='path', type=str, help='native_summary path after pre analysis')
    parser.add_argument('--process', default=1, type=int, help="multiprocessing process count. default: 1 (single process)")
    parser.add_argument('--redo', default=False, help="delete previous result and redo analysis", action='store_true')
    parser.add_argument('--delete', default=False, help="not perform analysis, but delete all analysis results", action='store_true')
    args = parser.parse_args()
    apk_path_or_folder = args.path #type: str
    redo = 'redo' if args.redo else 'skip'
    if args.delete:
        remve_all_project_folder(apk_path_or_folder)
    elif os.path.exists(os.path.join(apk_path_or_folder, "native_summay.preanalysis.progress")): # bulk mode
        print("bulk analysis mode")
        process_count = args.process
        analyze_apks(apk_path_or_folder, process_count, redo)
    else:
        analyze_apk_folder(apk_path_or_folder, redo)

if __name__ == '__main__':
    # analyze_apks(sys.argv[1])
    # remve_all_project_folder(r'F:\native_summary\malradar-preana')
    # analyze_apks(r'F:\native_summary\malradar-preana', 5, 'skip')
    main()

