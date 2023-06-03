# pre-analysis for Ghidra + BinAbsInspector + NativeSummay module
# extract shared objects in apk and generate `<soname>.funcs.json` file specifying jni methods to analysis.

import os,shutil,json,zipfile,sys,time
from zipfile import ZipFile

from native_summary.pre_analysis.__main__ import apk_pre_analysis
from native_summary.pre_analysis.dex_analysis import DexAnalysisCenter, format_method

PREFER_32 = None

PROGRESS_FILENAME = "native_summay.preanalysis.progress"
GLOBAL_STATE = {
        'progress': set(), # filenames that finished analyzing
        'apk_stat': dict(), # APK => 是否为flutter应用，静态成功解析的比例，解析失败的集合，成功解析的集合，解析失败的Native符号，每个so的信息
        'bad_count': [], # apk that failed to analyse
    }


# from https://github.com/evilpan/jni_helper
def get_type(atype):
    """
    Retrieve the java type of a descriptor (e.g : I -> jint)
    """
    from androguard.decompiler.dad.util import TYPE_DESCRIPTOR
    res = TYPE_DESCRIPTOR.get(atype)
    if res:
        if res == 'void':
            return res
        else:
            return 'j' + res
    if atype[0] == 'L':
        if atype == 'Ljava/lang/String;':
            res = 'jstring'
        else:
            res = 'jobject'
    elif atype[0] == '[':
        if len(atype) == 2 and atype[1] in 'ZBSCIJFD':
            res = TYPE_DESCRIPTOR.get(atype[1])
        else:
            res = 'object'
        res = 'j%sArray' % res
    else:
        print('Unknown descriptor: "%s".', atype)
        res = 'void'
    return res

def get_multi_mapping(dex: DexAnalysisCenter):
    ret = {}
    for java_mth, resolve_list in dex.mappings.items():
        if java_mth == DexAnalysisCenter.UNRESOLVED: continue
        if len(resolve_list) <= 1: continue
        resolve_list_ = []
        for it in resolve_list:
            resolve_list_.append(list(it))
        ret[format_method(java_mth)] = list(resolve_list)
    return ret

def tag2index(has_so, has_javasym, has_native):
    # tags = {'is_flutter': is_flutter, 'has_so':has_so, 'has_javasym':has_javasym}
    if has_so:
        if has_javasym:
            so = 0
        else:
            so = 1
    else:
        so = 2
    if has_native:
        native = 0
    else:
        native = 1
    return so*2+native

def pre_analysis(apk_path, out_path):
    t = time.time()
    if not os.path.exists(out_path):
        os.makedirs(out_path,exist_ok=True)
    apk_name = os.path.basename(apk_path)

    try:
        apk, dex, arch_selected, so_stat, tags = apk_pre_analysis(apk_path, analyse_dex=True, prefer_32=PREFER_32)
    except zipfile.BadZipFile:
        print("Bad zip file: " + apk_path)
        GLOBAL_STATE['bad_count'].append(apk_name)
        GLOBAL_STATE['progress'].add(apk_name)
        return
    except Exception:
        print("Other error: ")
        import traceback
        print (traceback.format_exc())
        GLOBAL_STATE['bad_count'].append(apk_name)
        GLOBAL_STATE['progress'].add(apk_name)
        return
    zip = apk.zip #type: ZipFile
    so_mappings = dex.get_mappings_by_so()
    print(f"Selected arch is {arch_selected}")
    extracted_so = set()

    for so_name, symb_map_list in so_mappings.items():
        so_zip_path = '/'.join(['lib', arch_selected, so_name])
        # extract to folder
        # zip.extract(so_zip_path, out_path)
        extracted_so.add(so_name)
        source = zip.open(so_zip_path)
        target = open(os.path.join(out_path, so_name), "wb")
        with source, target:
            shutil.copyfileobj(source, target)
        
        # generate json object
        out_json = dict()
        for symbol, jmethod in symb_map_list:
            d = dict()
            # d['sig_with_tabs'] = f'{jmethod.get_method().get_class_name()}\t{jmethod.name}\t{jmethod.descriptor}'
            d["className"] = jmethod.get_method().get_class_name()
            d['name'] = jmethod.name
            d['descriptor'] = jmethod.descriptor
            args, ret = jmethod.descriptor[1:].rsplit(')', 1)
            args = str(args).split()
            ret = str(ret)
            arg_t = ['JNIEnv *']
            if 'static' in jmethod.access:
                arg_t.append('jclass')
            else:
                arg_t.append('jobject')
            d['argumentTypes'] = arg_t + [get_type(arg) for arg in args]
            d['returnType'] = get_type(ret)
            out_json[symbol] = d
        # dump json to file
        json_f = os.path.join(out_path, so_name+'.funcs.json')
        with open(json_f, 'w') as f:
            json.dump(out_json, f, indent=2, ensure_ascii=False)

    # extract so that contains JNI_OnLoad
    for so_name in so_stat:
        # if already extracted, skip
        if so_name in extracted_so:
            continue
        exp_sym = so_stat[so_name][3]
        if exp_sym != None and "JNI_OnLoad" in exp_sym:
            # extract so
            so_zip_path = '/'.join(['lib', arch_selected, so_name])
            source = zip.open(so_zip_path)
            target = open(os.path.join(out_path, so_name), "wb")
            with source, target:
                shutil.copyfileobj(source, target)
            # make an "empty" .funcs.json
            json_f = os.path.join(out_path, so_name+'.funcs.json')
            with open(json_f, 'w') as f:
                json.dump({}, f, indent=2, ensure_ascii=False)
    
    # tags = {'is_flutter': is_flutter, 'has_so':has_so, 'has_javasym':has_javasym}
    has_native = len(dex.native_methods) > 0
    type_index = tag2index(has_so=tags['has_so'], has_javasym=tags['has_javasym'], has_native=has_native)
    if tags['is_flutter']:
        print(f'flutter is of type: {type_index}') # TODO debug

    # statistics
    stat = {}
    stat['6type_ind'] = type_index
    stat['is_flutter'] = tags['is_flutter']
    stat['selected_arch'] = arch_selected
    if True: # analyze_dex
        stat['resolve_percentage'] = dex.resolved_percentage()
        stat['failed_native_symbol'] = dex.mappings[DexAnalysisCenter.UNRESOLVED]
        stat['failed_java_mth'] = list(map(format_method, dex.unresolved_java()))
        stat['success_java_mth'] = list(map(format_method, dex.resolved_java()))
        stat['multimapping_java_mth'] = get_multi_mapping(dex)
    stat['so_stat'] = so_stat
    stat['analysis_time'] = time.time() - t
    GLOBAL_STATE['apk_stat'][apk_name] = stat
    # only change progress after everything
    GLOBAL_STATE['progress'].add(apk_name)

def analyze_one(apk_path, out_path=None, redo=False):
    print(f"Processing {apk_path}")
    if out_path is None:
        out_path = apk_path.removesuffix('.apk') + '.native_summary'
    if redo and os.path.exists(out_path):
        from shutil import rmtree
        print(f'deleting {out_path}')
        rmtree(out_path)
    pre_analysis(apk_path, out_path)
    if len(os.listdir(out_path)) == 0:
        print("empty folder. removing...")
        os.rmdir(out_path)

def restore_progress(path):
    import pickle, os
    global GLOBAL_STATE
    prog_file = os.path.join(path, PROGRESS_FILENAME)
    if os.path.exists(prog_file):
        with open(prog_file, "rb") as f:
            GLOBAL_STATE = pickle.load(f)

def backup_progress(path):
    import pickle, os
    prog_file = os.path.join(path, PROGRESS_FILENAME)
    with open(prog_file, "wb") as f:
        pickle.dump(GLOBAL_STATE, f)

def finalize(path):
    apk_result = os.path.join(path, "apk_result.json")
    with open(apk_result, 'w') as f:
        json.dump(GLOBAL_STATE['apk_stat'], f, indent=4)
    backup_progress(path)
    print(f'analysis spent {time.time() - analysis_start_time}s.')


def set_exc_hook(path):
    import sys
    def my_except_hook(exctype, value, traceback):
        if issubclass(exctype, KeyboardInterrupt):
            finalize(path)
        sys.__excepthook__(exctype, value, traceback)
    sys.excepthook = my_except_hook

def analyze_one_mp_wrapper(arg, q):
    global GLOBAL_STATE
    GLOBAL_STATE = {
        'progress': set(),
        'apk_stat': dict(),
        'bad_count': [],
    }
    analyze_one(*arg)
    q.put(GLOBAL_STATE)

def handle_result(global_state):
    assert len(global_state['progress']) == 1

    for name in global_state['progress']:
        if name in global_state['bad_count']: continue
        GLOBAL_STATE['apk_stat'][name] = global_state['apk_stat'][name]
    GLOBAL_STATE['bad_count'].extend(global_state['bad_count'])
    GLOBAL_STATE['progress'].update(global_state['progress'])


def mp_run(args_list, process_count, out_path):
    from multiprocessing import Process, Queue
    queues = [None for i in range(process_count)]
    processes = [None for i in range(process_count)]
    try:
        for i in range(process_count):
            if len(args_list) > 0:
                queues[i] = Queue()
                # TODO arg
                processes[i] = Process(target=analyze_one_mp_wrapper, args=(args_list.pop(0), queues[i]))
                processes[i].start()
        # 轮询是否结束，结束则处理返回值，并启动新的进程
        while processes.count(None) < process_count:
            for i in range(process_count):
                process = processes[i] #type: Process
                queue = queues[i] #type: Queue
                if process != None and (not queue.empty()):
                    result = queue.get_nowait()
                    handle_result(result)
                    if len(args_list) > 0:
                        queues[i] = Queue()
                        processes[i] = Process(target=analyze_one_mp_wrapper, args=(args_list.pop(0), queues[i]))
                        processes[i].start()
                    else:
                        processes[i] = None
                        queues[i] = None
                    break
            else:
                time.sleep(3)
    except KeyboardInterrupt:
        # 如果遇到异常，则终止所有进程并finalize
        for i in range(process_count):
            process = processes[i] #type: Process
            if process != None:
                process.terminate()
    finally:
        finalize(out_path)

analysis_start_time = None

def main():
    global analysis_start_time
    analysis_start_time = time.time()
    global PREFER_32
    apk_path = None
    out_path = None
    import argparse
    parser = argparse.ArgumentParser(description=f'Process some apks, extract so and export related entrypoint to json. this tool will save progress (by apk name) to {PROGRESS_FILENAME}')
    parser.add_argument('apk_path_or_folder', metavar='apk_path_or_folder', type=str, help='APK path or APK folder path for batch processing')
    parser.add_argument('out_folder', nargs='?', metavar='out_folder', type=str, help='output folder path. can be omitted to auto generate when analysing single apk')
    parser.add_argument('--prefer-32', nargs='?', default=None, const="yes", type=str, help="whether to prefer 32 (=yes), or prefer 64 if =no.")
    parser.add_argument('--process', default=1, type=int, help="multiprocessing process count. default: 1 (single process)")

    # if len(sys.argv) == 1:
    #     print(f"Usage: {sys.argv[0]} apk_path_or_folder [out_folder]")
    #     exit(-1)

    args = parser.parse_args()

    if args.prefer_32 == "yes" or args.prefer_32 == "true":
        PREFER_32 = True
    elif args.prefer_32 == "no" or args.prefer_32 == "false":
        PREFER_32 = False
    elif args.prefer_32 is not None:
        print("error, cannot regnize --prefer-32 option")
    apk_path = args.apk_path_or_folder
    out_path = args.out_folder
    if os.path.isfile(apk_path):
        analyze_one(apk_path, out_path)
    else: # bulk analysis mode
        assert out_path != None
        restore_progress(out_path) # restore previous progress
        if not (args.process > 1):
            set_exc_hook(out_path)
        progress = GLOBAL_STATE['progress']
        mp_to_run = [] # for multiprocessing
        for file in os.listdir(apk_path):
            if not file.endswith('.apk'):
                continue
            # if file[:7] <= '5886316':
            #     print("skipping...")
            #     continue
            if file in progress:
                continue

            fpath = os.path.join(apk_path, file)
            out_path_one = None
            if len(sys.argv) > 2: # 为每个apk文件生成一个文件夹名
                out_path_one = os.path.join(out_path, file.removesuffix('.apk') + '.native_summary')

            if args.process > 1:
                mp_to_run.append((fpath, out_path_one, True))
            else: # single_process
                analyze_one(fpath, out_path_one, redo=True)
        if args.process > 1:
            mp_run(mp_to_run, args.process, out_path)
        else:
            finalize(out_path)

if __name__ == '__main__':
    main()
