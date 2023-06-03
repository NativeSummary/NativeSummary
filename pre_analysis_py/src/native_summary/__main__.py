import argparse
import logging
import multiprocessing as mp
import multiprocessing.pool
import os
import sys
from typing import TYPE_CHECKING

import angr
import networkx as nx
from angrutils import plot_cfg
from sympy import EX

from .common import set_alarm, TimeoutException

from .api_record import clear_call_records
from .pre_analysis.__main__ import apk_pre_analysis, print_resolve_report
from .pre_analysis.elf_analysis import is_skip_libs, so_analysis
from .pre_analysis.symbol_parser import extract_names
from .sematic_summary import dump_sematic_summary, init_sematic_summary
from .simprocedure.java_jni import (clear_maps_in_project,
                                    get_global_map_in_project)
from .simprocedure.unimplemented_import import hookAllImportSymbols
from .utils import (JNI_LOADER, analyze_jni_function, analyze_jni_onload,
                    initialize_project)
from .profile import Performance

if TYPE_CHECKING:
    from .pre_analysis.dex_analysis import DexAnalysisCenter

# when set to true, not using multiprocessing
MULTI_PROCESSING_RUN = False

# skip known library funtion that not helpful
NO_SKIP_LIBS = 'NO_SKIP_LIBS'

# raise some exception for debugging
DEBUG = 'DEBUG'
VSA_TIMEOUT = 'VSA_TIMEOUT'
CFG_TIMEOUT = 'CFG_TIMEOUT'

# when debug is true, not timeout is set at all.
OPTS = {'VSA_TIMEOUT': 60*2, 'NO_SKIP_LIBS': False, 'DEBUG': False, 'CFG_TIMEOUT': 60*3}

# the longest time in seconds to analyze 1 JNI function.
WAIT_TIME = 99999 # 180
# the longest time in seconds for dynamic registration analysis
DYNAMIC_ANALYSIS_TIME = 999999 # 600

# Directory for different ABIs, refer to: https://developer.android.com/ndk/guides/abis
# currently mainly support aarch64
# ABI_DIRS = ['lib/arm64-v8a/', 'lib/armeabi-v7a/', 'lib/x86/', 'lib/x86_64/', 'lib/armeabi/', 'lib/mips/', 'lib/mips64/']
ABI_DIRS = ['lib/arm64-v8a/', 'lib/armeabi-v7a/', 'lib/armeabi/', 'lib/mips/', 'lib/mips64/']
FDROID_DIR = '../fdroid_crawler'
NATIVE_FILE = os.path.join(FDROID_DIR, 'natives')
# OUT_DIR = 'fdroid_result'
OUT_DIR = os.path.expandvars('$SCRATCH/native_lin')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# uncomment below to output log information
# logging.disable(level=logging.CRITICAL)

logger.info("angr import finished.")


class NoDaemonProcess(mp.Process):
    # make 'daemon' attribute always return False
    def _get_daemon(self):
        return False
    def _set_daemon(self, value):
        pass
    daemon = property(_get_daemon, _set_daemon)


# Make Pool with none daemon process in order to have children process.
# We sub-class multiprocessing.pool.Pool instead of multiprocessing.Pool
# because the latter is only a wrapper function, not a proper class.
class MyPool(multiprocessing.pool.Pool):
    Process = NoDaemonProcess


def lineage_run():
    lin_file = sys.argv[1]
    shas = list()
    with open(lin_file) as f:
        for l in f:
            l = l.strip()
            shas.append(l)
    if not os.path.exists(OUT_DIR):
        os.makedirs(OUT_DIR)
    with MyPool() as p:
        p.map(sha_run, shas)


def filter_out_exists(apks):
    if not os.path.exists(OUT_DIR):
        return apks
    exists = list()
    for i in os.listdir(OUT_DIR):
        if i.endswith('_result'):
            exists.append(i.rstrip('_result'))
    noexists = list()
    for apk in apks:
        ne = True
        name = apk.split('/')[-1]
        for e in exists:
            if name.rstrip('.apk') == e:
                ne = False
                break
        if ne:
            noexists.append(apk)
    return noexists


def print_performance(perf, out):
    file_name = os.path.join(out, 'performance')
    with open(file_name, 'w') as f:
        print(perf, file=f)


def main():
    desc = 'Analysis APKs for native and Java inter-invocations'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('apk', type=str, help='path to the APK file, or single .so ELF file')
    parser.add_argument('--out', type=str, default=None, help='the output directory')
    parser.add_argument('--mp', help='Enable multiprocess run', action='store_true')
    parser.add_argument('--dynamic_resolve', help='Analyse JNI_OnLoad to find new jni function.', action='store_true')
    parser.add_argument('--all_libs', help='not skip known libraries.', action='store_true')
    parser.add_argument('--cfg', help='Enable the output of binary control flow graph as a png file. but this can take too long', action='store_true')
    parser.add_argument('--fcfg', help='Enable the output of function cfg(only registered function) as a png file. this can take some time to generate.', action='store_true')
    parser.add_argument('--fddg', help='Enable the output of function vsa_ddg(only registered function) as a png file. this can take some time to generate.', action='store_true')
    parser.add_argument('--debug', help='not catch some exception', action='store_true')

    args = parser.parse_args()
    OPTS['args'] = args
    if args.mp:
        # TODO
        global MULTI_PROCESSING_RUN
        MULTI_PROCESSING_RUN = True

    if args.all_libs:
        OPTS[NO_SKIP_LIBS] = True

    if args.debug:
        OPTS[DEBUG] = True

    if args.out is None:
        # output locally with the same name of the apk.
        args.out = '.'

    if not os.path.exists(args.apk):
        logger.error('APK file does not exist!')
        sys.exit(-1)

    
    if os.path.isdir(args.apk):
        logger.info("Enter folder processing mode.")
        dir_path = args.apk
        apk_paths = []
        for file in os.listdir(dir_path):
            apk_paths.append(os.path.join(dir_path, file))
        for p in apk_paths:
            fname = os.path.basename(p)
            # if not fname.startswith("agersant.polaris"):
            #     continue
            prefix = 'com.agateau.tinywheels'
            if fname[:len(prefix)] > prefix:
                continue
            out_dir = prepare_dir(p, args.out)
            apk_run(p, out_dir, args.cfg, args.dynamic_resolve)
    elif os.path.isfile(args.apk): # single so or apk file
        # put results in apkname_result dir
        args.out = prepare_dir(args.apk, args.out)
        if args.apk.endswith('.so'):
            so_run(args.apk, args.out, args.cfg, args.dynamic_resolve)
        else:
            apk_run(args.apk, args.out, args.cfg, args.dynamic_resolve)

    return args



def get_return_address(state):
    return_addr = None
    arch = state.arch.name
    # for ARM, ARM64, get it from lr (i.e., link register) register.
    if 'ARMEL' in arch or 'AARCH64' in arch:
        return_addr = state.solver.eval(state.regs.lr)
    # for MIPS, get it from ra (i.e., return address) register.
    elif 'MIPS' in arch:
        return_addr = state.solver.eval(state.regs.ra)
    # for x86 or x86_64, the return address is stored on the stack which is pointed by the esp register.
    elif 'X86' in arch or 'AMD64' in arch:
        return_addr = state.memory.load(state.regs.esp, state.arch.bytes, endness=state.arch.memory_endness)
        return_addr = state.solver.eval(return_addr)
    else:
        logger.warning(f'Retrieve return address of architecture {state.arch.name} has not been implemented!')
    return return_addr


def find_func(addr, f_info, addr_type):
    types = ('enter', 'exit')
    the_func = None
    if not addr_type in types:
        logger.warning(f'"find_func" does not support the "addr_type": {addr_type}!')
        return the_func
    for func, addrs in f_info.items():
        if addr_type == types[0]:
            func_addr = addrs[0]
        else:
            func_addr = addrs[1] if len(addrs) == 2 else None
        if addr == func_addr:
            the_func = func
            break
    return the_func


def get_function_addresses(proj, output_cg=False, path=None):
    funcs_addrs = list()
    cfg = proj.analyses.CFGFast()
    for addr in cfg.functions:
        f = cfg.functions[addr]
        if not f.is_simprocedure and not f.is_syscall and not f.is_plt and not proj.is_hooked(addr):
            funcs_addrs.append((f.name, addr))
    if output_cg:
        file_name_cg = proj.filename.split('/')[-1] + '.dot'
        file_name_map = proj.filename.split('/')[-1] + '.map'
        path = '.' if path is None else path
        if not os.path.exists(path):
            os.makedirs(path)
        cg_path = os.path.join(path, file_name_cg)
        map_path = os.path.join(path, file_name_map)
        # output the function name to address mapping. Since in CG, only addresses are provided.
        with open(map_path, 'w') as f:
            for func, addr in funcs_addrs:
                print(f'{func}:{addr}', file=f)
        # output the CG as a dot file. Can use the "dot" command of Graphviz access.
        dot = nx.nx_pydot.to_pydot(cfg.functions.callgraph)
        dot.write(cg_path)
    return (funcs_addrs, cfg)

def recover_CFG(proj, fname, base_state=None, emulated=False, verbose=False, plot=False):
    """
    plot the whole CFG for big binaries can take too long.
    """
    if verbose:
        print('start recover CFG')
    # func_starts = [rec.func_ptr for rec in Record.RECORDS.values()]
    # static binding only analyse export symbols, which should have been utilized by angr
    func_starts = None # TODO add Dynamic binding info as func_starts?
    if fname == None:
        fname = proj.filename.split('/')[-1]
    if emulated:
        cfg = proj.analyses.CFGEmulated(fail_fast=True, starts=func_starts, initial_state=base_state)
        if plot:
            plot_cfg(cfg, fname, asminst=True, remove_imports=True, remove_path_terminator=True)
    else:
        cfg = proj.analyses.CFGFast(fail_fast=True, function_starts=func_starts, base_state=base_state, normalize=True, resolve_indirect_jumps=True, detect_tail_calls=True, indirect_jump_target_limit=256)
        if plot:
            plot_cfg(cfg, fname, asminst=True, debug_info=False, remove_imports=True, remove_path_terminator=True, comments=False)
    return cfg


# put results in apkname_result dir
def prepare_dir(path, out=None):
    apk_name = os.path.basename(path)
    result_dir = os.path.splitext(apk_name)[0] + '_result'
    if out is None: # when run from internal function
        out = os.path.join(OUT_DIR, result_dir)
    else: # when cmd run, path='.' by default
        out = os.path.join(out, result_dir)
    if not os.path.exists(out):
        os.makedirs(out)
    return out


def so_run(path, out, output_cfg=False, dynamic_resolve=False):
    perf = Performance()
    so_name = os.path.basename(path)

    f = open(path, 'rb')
    java_syms, imp, exp = so_analysis(f)


    proj, jvm, jenv = prepare_project(f, so_name, None)
    if proj is None:
        logger.error(f'Project object generation failed for {so_name}')
        return

    logger.info(f"Starting CFGFast for {so_name}...")
    cfg = recover_CFG(proj, fname=os.path.join(out, so_name + '.cfg'), plot=output_cfg)
    logger.info(f"CFGFast finished for {so_name}...")
    perf.add_analyzed_so()

    for sym in java_syms:
        func_addr = proj.loader.find_symbol(sym).rebased_addr
        clazz, name, argsig = extract_names(sym)
        if type(argsig) is str:
            argsig = f'({argsig})'
        other_info = (clazz, name, argsig)

        returns = dict()
        clear_call_records()
        clear_maps_in_project(proj)

        # start analyzing
        analyze_jni_function(returns, (func_addr, sym, other_info), proj, jvm, jenv, cfg, (out, so_name), (True, True))

    f.close()


def multi_process_run(target_func, args, perf):
    """
    target_func's first arg must be a dict to return.
    """
    # TODO check useable and multiprocessing parallel
    with mp.Manager() as mgr:
        returns = mgr.dict()

        # for jni_func, record in Record.RECORDS.items():

        # wrap the analysis with its own process to limit the
        # analysis time.
        p = mp.Process(target=analyze_jni_function, args=(returns, *args))
        p.start()
        perf.add_analyzed_func()
        # For analysis of each .so file, we wait for 3mins at most.
        p.join(WAIT_TIME)
        if p.is_alive():
            perf.add_timeout()
            p.terminate()
            p.join()
            logger.warning(f'Timeout when analyzing...')
        # TODO is it right?
        returns = dict(returns)
    return returns

log_handler = None

def apk_run(path, out, output_cfg=False, dynamic_resolve=False):
    # Tee result to logfile
    global log_handler
    if log_handler is None:
        log_handler = logging.FileHandler(os.path.join(out, "log.txt"), 'w')
        log_handler.setFormatter(logging.Formatter('%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'))
        log = logging.getLogger()
        log.addHandler(log_handler)
    else:
        log_handler.close()
        log_handler.baseFilename = os.path.abspath(os.path.join(out, "log.txt"))
    # outf = open(os.path.join(out, "stdout.log"), 'w')
    # errf = open(os.path.join(out, "stderr.log"), 'w')
    # tee = TeeObject(outf, errf)
    # tee.__enter__()

    logger.info(f"[!] Current APK: {path}")
    perf = Performance()
    apk_name = os.path.basename(path)

    sematic_summary = init_sematic_summary(apk_name)

    perf.start(); perf.start_dex()
    dex: DexAnalysisCenter
    apk, dex, arch_selected, so_stat, is_flutter = apk_pre_analysis(path, analyse_dex=True)
    report = print_resolve_report(os.path.join(out, "resolve_report.json"), path, dex, arch_selected, so_stat)
    logger.info(f"JNI Reg statically resolved percentage: {report['resolve_percentage']}")
    logger.warning(f"Selected arch: {arch_selected}")
    if not arch_selected.startswith("arm64"):
        logger.error("Arm32 is currently not supported... Aborting")
        del perf # not recording
        return 

    if dynamic_resolve:
        logger.error("Dynamic Resolution is not implemented. (Under construction).")
        # 那边分析的时候就记录下JNI_OnLoad在so中的分布。
        # 之后分析so前再遍历每个so去分析

    so_mappings = dex.get_mappings_by_so()
    perf.end_dex()
    for so_name, symb_map_list in so_mappings.items():
        so_zip_path = '/'.join(['lib', arch_selected, so_name])

        perf.start_cfg()
        # TODO Custom loading of multiple .so file that rely on each other.
        # TODO use state after JNI_OnLoad for later analysis ?
        from io import BytesIO
        stream = BytesIO(apk.zip.open(so_zip_path).read())
        proj, jvm, jenv = prepare_project(stream, so_name, dex)
        del stream
        if proj is None:
            logger.warning(f'Project object generation failed for {so_name}')
            continue

        # shortcut path: if all symbol skipped, skip cfg.
        if OPTS[NO_SKIP_LIBS] is False:
            skip = True
            for symbol, _ in symb_map_list:
                if type(symbol) is not str:
                    skip = False
                    continue
                if not is_skip_libs(symbol):
                    skip = False
            if so_name in ['libgdx.so', 'libjingle_peerconnection_so.so', 'libgdx-freetype.so', 'libgdx-box2d.so', 'libobjectbox-jni.so', 'libovpn3.so', 'libsodiumjni.so']:
                skip = True
            if skip:
                logger.warning(f"Skipping library so: {so_name}")
                continue


        logger.info(f"Starting CFGFast for {so_name}...")
        try:
            if not OPTS[DEBUG]: set_alarm(OPTS[CFG_TIMEOUT])
            cfg = recover_CFG(proj, fname=os.path.join(out, so_name + '.cfg'), plot=output_cfg)
        except TimeoutException:
            logger.error(f"Timeout when building CFG for {so_name}")
            perf.end_cfg()
            continue
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error("CFGFast Failed. Aborting")
            perf.end_cfg()
            continue
        finally:
            if not OPTS[DEBUG]: set_alarm(0)
        logger.info(f"CFGFast finished for {so_name}...")
        perf.end_cfg()
        perf.add_analyzed_so()
        # eg: callobjectmethod's argument count analysis
        get_global_map_in_project(proj)['cfg'] = cfg

        # TODO 遍历每个so的JNI_OnLoad
        # 然后往symb_map_list增加项。

        for symbol, java_method in symb_map_list:
            func_addr = None
            symbol_name = None
            if type(symbol) is str:
                if OPTS[NO_SKIP_LIBS] is False and is_skip_libs(symbol): # TODO add option
                    logger.warning(f"Skipping library: {symbol}")
                    continue
                symbol_name = symbol
                func_addr = proj.loader.find_symbol(symbol).rebased_addr
                assert func_addr is not None, f"Cannot find symbol {symbol} in {so_zip_path}"
            elif type(symbol) is int:
                symbol_name = f'{so_name}-{hex(symbol)}'
                func_addr = symbol
            else:
                raise "Unknown symbol type"

            if MULTI_PROCESSING_RUN:
                raise "Unimplemented"
                # TODO collect args and parallel
                args = ((func_addr, symbol_name, java_method), proj, jvm, jenv, cfg, (out, so_name), (True, True))
                returns = multi_process_run(analyze_jni_function, args, perf=perf)
            else: # MULTI_PROCESSING_RUN == False
                returns = dict()
                # start analyzing
                clear_maps_in_project(proj)
                clear_call_records()

                is_plot_cfg, is_plot_ddg = OPTS['args'].fcfg, OPTS['args'].fddg
                perf_times, status = analyze_jni_function(returns, (func_addr, symbol_name, java_method), proj, jvm, jenv, cfg, (out, so_name), (is_plot_cfg, is_plot_ddg))
                if status == 'failed':
                    perf.add_failed_javamth(so_name, symbol)
                    perf.add_failed()
                elif status == 'timeout':
                    perf.add_timeout()
                elif status == 'ok':
                    perf.add_so_times(*perf_times)
                else:
                    assert False

            # 整理返回值，放到里面
            sematic_summary['mth_logs'][java_method] = returns
            perf.add_analyzed_func()

        # TODO do something with `returns`
        logger.info(f"Finished analyzing {so_name}")

    # 语义信息导出
    logger.warning("Exporting sematic summary to json...")
    # if len(sematic_summary['mth_logs']) > 0:
    dump_sematic_summary(sematic_summary, os.path.join(out, 'ss.json'))

    # with apk.zip as zf:
    #     chosen_abi_dir = select_abi_dir(zf.namelist())
    #     if chosen_abi_dir is None:
    #         logger.debug(f'No ABI directories were found for .so file in {path}')
    #         return
    #     logger.debug(f'Use shared library (i.e., .so) files from {chosen_abi_dir}')
    #     for n in zf.namelist():
    #         if n.endswith('.so') and n.startswith(chosen_abi_dir):
    #             logger.debug(f'Start to analyze {n}')
    #             so_file = zf.open(n)
    #             so_name = n.split('/')[-1]

    #             clean_records()
    #             # TODO refactor to pre_analysis
    #             record_static_jni_functions(proj, dex)
    #             # clear_maps_in_project(proj) # proj just got created

    #             # Dynamic Register Resolution TODO
    #             dynamic_timeout = False
    #             if jni_onload := proj.loader.find_symbol(JNI_LOADER):
    #                 # Dynamic Register Resolution
    #                 logger.warning("JNI_OnLoad found!! Start dynamic register resolution.")
    #                 # wrap the analysis with its own process to limit the analysis time.
    #                 if MULTI_PROCESSING_RUN:
    #                     with mp.Manager() as mgr:
    #                         records = mgr.dict()
    #                         p = mp.Process(target=analyze_jni_onload,
    #                                 args=(jni_onload.rebased_addr, proj, jvm, jenv, cfg, (out, so_name), records, (True, True)))
    #                         p.start()
    #                         p.join(DYNAMIC_ANALYSIS_TIME)
    #                         if p.is_alive():
    #                             dynamic_timeout = True
    #                             p.terminate()
    #                             p.join()
    #                             logger.warning('Timeout when analyzing dynamic registration')
    #                         Record.RECORDS.update(records)
    #                 else: # MULTI_PROCESSING_RUN = False
    #                     records = dict()
    #                     analyze_jni_onload(jni_onload.rebased_addr, proj, jvm, jenv, cfg, (out, so_name), records, (True, True))
    #                     # within same process
    #                     # Record.RECORDS.update(records)
    #                     clear_maps_in_project(proj)
    #                     clear_call_records()


    #             if dynamic_timeout:
    #                 logger.warning("Timeout on dynamic register resolution.")
    #                 perf.add_dynamic_reg_timeout()
    #             else:
    #                 logger.warning("Dynamic register resolution finished.")



    perf.end()
    print_performance(perf, out)

    # end tee
    # tee.exit()
    # outf.close()
    # errf.close()


def refactor_cls_name(raw_name):
    return raw_name.lstrip('L').rstrip(';').replace('/', '.')


def prepare_project(so_file, so_name, dex):
    proj, jvm_ptr, jenv_ptr = None, None, None
    # Mark whether the analysis for dynamic registration is timeout.
    try:
        proj = angr.Project(so_file, auto_load_libs=False)
    except Exception as e:
        if OPTS[DEBUG]: raise
        logger.warning(f'{so_file} cause angr loading error: {e}')
        import traceback
        traceback.print_exc()
        # raise e
    else:
        hookAllImportSymbols(proj)
        jvm_ptr, jenv_ptr = initialize_project(proj, dex)
        proj.filename = so_name # due to load from stream

    return proj, jvm_ptr, jenv_ptr


if __name__ == '__main__':
    main()

