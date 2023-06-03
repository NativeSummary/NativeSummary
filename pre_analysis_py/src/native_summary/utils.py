import logging
import os

import androguard
import angr
import angr.sim_options as o
from angr.sim_type import parse_type, register_types
from angrutils import plot_cfg
from claripy import BVS, BVV

from native_summary.pre_analysis.dex_analysis import format_method
from native_summary.pre_analysis.symbol_parser import parse_params_from_sig
from native_summary.profile import SubPerformance

from .api_record import add_ret_to_records, print_call_records
from .arg_resolve import (basic_arg_resolve, basic_JNINativeMethod_resolve,
                          get_callsite_from_state, print_dyn_reg_result)
from .common import HeapObject, TimeoutException, set_alarm
from .simprocedure import JNI_PROCEDURES
# from .jni_native import jni_native_interface as jenv
from .simprocedure.java_jni import (get_global_map_in_project, get_ref_map_in_project, jni_functions,
                                    jni_type_size, jvm_functions,
                                    prepare_value_map_in_project)

JNI_LOADER = 'JNI_OnLoad'
# value for "LengthLimiter" to limit the length of path a state goes through.
# refer to: https://docs.angr.io/core-concepts/pathgroups
MAX_LENGTH = 50000
DYNAMIC_ANALYSIS_LENGTH = 1000
MAX_LOOP_ITER = 10

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def initialize_project(proj, dex):
    jvm_ptr, jenv_ptr, update = jni_env_prepare_in_object(proj)
    # register related map
    prepare_value_map_in_project(proj, jvm_ptr, jenv_ptr, dex, update=update)
    return jvm_ptr, jenv_ptr


def jni_env_prepare_in_object(proj):
    """
    update: a dict to update proj global dict
    """
    update = dict()
    native_addr_size = proj.arch.bits // 8
    jvm_size = native_addr_size * len(jvm_functions)
    function_table_size = native_addr_size*len(jni_functions)
    jvm_ptr = proj.loader.extern_object.allocate(jvm_size)
    jenv_ptr = proj.loader.extern_object.allocate(function_table_size)
    for idx, name in enumerate(jvm_functions.values()):
        addr = jvm_ptr + idx * native_addr_size
        proj.hook(addr, JNI_PROCEDURES['java_jni'][name]())
    for idx, name in enumerate(jni_functions.values()):
        addr = jenv_ptr + idx * native_addr_size
        if name == 'RegisterNatives':
            update['RegisterNatives'] = addr
        proj.hook(addr, JNI_PROCEDURES['java_jni'][name]())
    register_jni_relevant_data_type()
    return jvm_ptr, jenv_ptr, update


def jni_env_prepare_in_state(state, jvm_ptr, jenv_ptr):
    addr_size = state.project.arch.bits
    for idx in range(len(jvm_functions)):
        jvm_func_addr = jvm_ptr + idx * addr_size // 8
        state.memory.store(addr=jvm_func_addr,
                           data=state.solver.BVV(jvm_func_addr, addr_size),
                           endness=state.project.arch.memory_endness)
    # for idx in range(len(jenv)):
    #     jenv_func_addr = jenv_ptr + idx * addr_size // 8
    #     state.memory.store(addr=jenv_func_addr,
    #                        data=state.solver.BVV(jenv_func_addr, addr_size),
    #                        endness=state.project.arch.memory_endness)
    for idx in range(len(jni_functions)):
        jni_function_addr = jenv_ptr + idx * addr_size // 8
        state.memory.store(addr=jni_function_addr,
                            data=BVV(jni_function_addr, addr_size),
                            endness=state.project.arch.memory_endness)


# TODO Refactor with analyze_jni_function
def analyze_jni_onload(func_addr, proj, jvm_ptr, jenv_ptr, cfg, out_paths=None, records=None, is_plots=(True, True)):
    raise "UnImplemented"
    is_plot_cfg, is_plot_ddg = is_plots
    out_dir, so_name = out_paths
    if func_addr == None:
        func_addr = proj.loader.find_symbol(JNI_LOADER).rebased_addr
    
    if is_plot_cfg:
        plot_cfg(cfg, os.path.join(out_dir, JNI_LOADER) + '.cfg', func_addr={func_addr:True}, asminst=True, debug_info=False, remove_imports=True, remove_path_terminator=True, comments=False)

    # TODO prototype=SimTypeFunction
    state = proj.factory.call_state(func_addr, jvm_ptr, mode="static", add_options={o.TRACK_MEMORY_ACTIONS, o.TRACK_REGISTER_ACTIONS, o.TRACK_TMP_ACTIONS})

    jni_env_prepare_in_state(state, jvm_ptr, jenv_ptr)
    resolved_ret = None
    # try:
    vfg = proj.analyses.VFG(
                            cfg,
                            initial_state=state,
                            start=func_addr,
                            context_sensitivity_level=5,
                            interfunction_level=999,
                            record_function_final_states=True,
                            remove_options={angr.options.OPTIMIZE_IR},
                            # max_iterations=80,
                        )
    # function_final_states is a defaultdict, so use get
    if final_states := vfg.function_final_states.get(func_addr, None):
        resolved_ret = set()
        for final_state in final_states.values():
            ret_ = basic_arg_resolve(final_state, final_state.regs.x0, get_ref_map_in_project(proj), 'int', 'ReturnValueResolution')
            resolved_ret.update(ret_)
    
    print_call_records(CALL_RECORDS, os.path.join(out_dir, so_name + '.result'), func_addr, proj.loader, resolved_ret, JNI_LOADER)

    # resolve register_natives
    # find the state at the call of RegisterNatives
    from .simprocedure.java_jni import get_global_map_in_project
    reg_native_addr = get_global_map_in_project(proj)['RegisterNatives']
    reg_native_states = vfg.function_initial_states.get(reg_native_addr, None)
    reg_result = dict()
    # TODO 2-callsite sensitive??
    for func_key, state in reg_native_states.items():
        cc = proj.factory.cc()
        arg_session = cc.arg_session(ret_ty=None)
        from angr.sim_type import SimTypeChar, SimTypePointer
        ptr_ty = SimTypePointer(SimTypeChar())
        ptr_ty = ptr_ty.with_arch(proj.arch)
        args = [cc.next_arg(arg_session, ptr_ty).get_value(state) for i in range(4)]
        # symbolic to concrete
        args = [basic_arg_resolve(state, item, get_ref_map_in_project(proj), 'reference', 'RegisterNatives') for item in args]

        ptr_env, obj_class_, ptr_methods, num_methods = args
        if len(ptr_methods) != 1 or type(next(iter(ptr_methods))) is not int:
            logger.error(f'RegisterNatives: Unable to concretize `JNINativeMethod *methods`: {ptr_methods}')
        num_mth = 0
        if len(num_methods) != 1 or type(next(iter(num_methods))) is not int:
            logger.error(f'RegisterNatives: Unable to concretize `jint nMethods`: {num_methods}')
            logger.error(f'RegisterNatives: stopping basic dynamic registers resolution.')
            # now: num_mth == 0
            # TODO use smallest value in num_methods
        elif len(num_methods) > 0:
            num_mth = next(iter(num_methods))
        is_jclass_failed = False
        # TODO multi jclass. match class based on infomation on java side.
        # eg: collect all native func to a map, from funcname to class
        if len(obj_class_) != 1 or type(next(iter(obj_class_))) is not HeapObject:
            logger.error(f'RegisterNatives: Unable to concretize `jclass clazz`: {obj_class_}')
            logger.error(f'RegisterNatives: stopping basic dynamic registers resolution.')
            is_jclass_failed = True
        else:
            obj_class_ = next(iter(obj_class_))
            assert obj_class_.source[0] == 'ret' and obj_class_.source[2] == 'FindClass'
            find_class_callsite = obj_class_.source[1]
            find_class_arg_resolved = CALL_RECORDS.get((find_class_callsite, obj_class_.source[2]))[1]
            if len(find_class_arg_resolved) != 1 or type(next(iter(find_class_arg_resolved))) is not str:
                logger.error(f"RegisterNatives: `jclass clazz`'s FindClass call cannot concretize: {find_class_arg_resolved}")
                is_jclass_failed = True
            else:
                find_class_arg_resolved = next(iter(find_class_arg_resolved))
        # resolve ptr_methods part to JNINativeMethod and print
        mths = set()
        for ptr_ in ptr_methods:
            mths.update(basic_JNINativeMethod_resolve(state, ptr_, num_mth))
        reg_result[func_key] = mths
        
        # TODO temporary store callsite in func_key for later print
        # callsite in FuncKey is inaccurate(basic block level)
        callsite = get_callsite_from_state(proj, state)
        func_key.native_summary_callsite = callsite

        # refer to dex and register related methods to RECORDS
        # TODO class_name format
        if not is_jclass_failed:
            cls_name = find_class_arg_resolved
        else:
            cls_name = None
        for mth in mths:
            symb_name = None
            if (symb := proj.loader.find_symbol(mth.ptr)):
                symb_name = symb.name
            # TODO recheck with dex and warn, set is_static
            Record(cls_name, mth.name, mth.sig, mth.ptr, symbol_name=symb_name)

    # print out results in reg_result
    print_dyn_reg_result(reg_result, os.path.join(out_dir, so_name + '.result'), proj.loader)


    # except Exception as e:
    #     logger.warning(f'Collect dynamically registered JNI function failed: {e}')


    if is_plot_ddg:
        ddg = proj.analyses.VSA_DDG(vfg=vfg, start_addr=func_addr,
                                    interfunction_level=999,
                                    context_sensitivity_level=5,
                                    keep_data=True)
        plot_vsa_ddg(ddg.graph, os.path.join(out_dir, JNI_LOADER) + '.ddg', format='png', project=proj, asminst=True)


    # pass new RECORDS back to main process. not passing ref map
    if records is not None:
        records.update(Record.RECORDS)
    
def call_filter(vfg, job, call_state, fakeret_state):
    proj = call_state.project
    # try pretty print call target
    target_addr = job.call_target
    try:
        real_func = proj.kb.functions.get_by_addr(target_addr)
    except KeyError:
        # the real function does not exist for some reason
        real_func = None
    if real_func is not None:
        logger.info(f"VFG call filter: calling {real_func.name}.")
    else:
        logger.info(f"VFG call filter: calling {hex(target_addr) if target_addr != None else 'unknown'}.")

    jenv = get_global_map_in_project(proj)['jenv_ptr']
    try:
        concretized = call_state.solver.eval_exact(call_state.regs.x0, 1)[0]
    except (angr.errors.SimValueError, TypeError) as e:
        concretized = None

    if target_addr != None:
        if proj.is_hooked(target_addr):
            logger.info(f"VFG call filter: enter {proj.hooked_by(target_addr)}.")
            return False # enter hooked addr
        if not proj.loader.main_object.contains_addr(target_addr): 
            logger.info(f"VFG call filter: not within main object range.")
            return False # enter non object addr

        if concretized != jenv: # isinstance(concretized, int) and
            logger.warn("VFG call filter: skipping!")
            return True
            # simprocedure?
    else:
        logger.warn("VFG call filter: unknown target. skipping!")
        return True
    return False

# main function for analyzing single JNI function
def analyze_jni_function(returns, func_info, proj, jvm_ptr, jenv_ptr, cfg, out_paths=None, is_plots=(True, False)):
    from .__main__ import OPTS,DEBUG, VSA_TIMEOUT
    func_addr, symbol_name, other_info = func_info # other_info is AndroGuard method, or (class, mth_name, sig) when java is not present(only so file)
    is_plot_cfg, is_plot_ddg = is_plots
    out_dir, so_name = out_paths

    if type(other_info) is androguard.core.analysis.analysis.MethodClassAnalysis:
        func_sig = other_info.descriptor
        mth_info = format_method(other_info)
        clazz = other_info.get_method().get_class_name()
    elif type(other_info) is tuple:
        clazz, mth_name, func_sig = other_info
        mth_info = symbol_name
    else:
        # TODO only so file mode
        raise "UnImplemented"
        func_sig = None

    logger.info(f"Start analyzing {mth_info} ({proj.loader.describe_addr(func_addr)})")
    perf = SubPerformance()

    if is_plot_cfg:
        perf.start_cfg()
        plot_cfg(cfg, os.path.join(out_dir, symbol_name) + '.cfg', func_addr={func_addr:True}, asminst=True, debug_info=False, remove_imports=True, remove_path_terminator=True, comments=False)
        perf.end_cfg()

    perf.start_vfg()
    func_params, updates = get_jni_function_params(proj, func_addr, clazz, func_sig, jenv_ptr)
    # TODO prototype=SimTypeFunction
    state = proj.factory.call_state(func_addr, *func_params, mode="static", add_options={o.TRACK_MEMORY_ACTIONS, o.TRACK_REGISTER_ACTIONS, o.TRACK_TMP_ACTIONS, o.CONSERVATIVE_READ_STRATEGY, o.CONSERVATIVE_WRITE_STRATEGY})
    get_ref_map_in_project(proj).update(updates)
    jni_env_prepare_in_state(state, jvm_ptr, jenv_ptr)

    analysis_status = 'ok' # 'ok', 'timeout', 'failed'
    try:
        if not OPTS[DEBUG]: set_alarm(OPTS[VSA_TIMEOUT])
        vfg = proj.analyses.VFG(
                                cfg,
                                initial_state=state,
                                start=func_addr,
                                context_sensitivity_level=9,
                                interfunction_level=9,
                                record_function_final_states=True,
                                remove_options={angr.options.OPTIMIZE_IR},
                                interfunction_hook=call_filter,
                                max_iterations_before_widening=4,
                                max_iterations=20,
                                widening_interval=3,
                            )

        # function_final_states is a defaultdict, so use get
        if final_states := vfg.function_final_states.get(func_addr, None):
            resolved_ret = set()
            for final_state in final_states.values():
                ret_ = basic_arg_resolve(final_state, final_state.regs.x0, get_ref_map_in_project(proj), 'reference', 'ReturnValueResolution')
                resolved_ret.update(ret_)
            add_ret_to_records(func_addr, (resolved_ret,))
        else: logger.warning("Function final state not found. Return value is not resolved.")

    except TimeoutException:
        analysis_status = 'timeout'
        logger.error(f"Timeout when analyzing {mth_info} ({proj.loader.describe_addr(func_addr)})")

    except Exception as e:
        analysis_status = 'failed'
        
        if OPTS[DEBUG]: raise
        import traceback
        traceback.print_exc()
        logger.error(f"Failed to analyze {mth_info} ({proj.loader.describe_addr(func_addr)})")
    finally:
        if not OPTS[DEBUG]: set_alarm(0)

    # requires import again when needed
    from .api_record import CALL_RECORDS
    print_call_records(CALL_RECORDS, os.path.join(out_dir, so_name + '.result'), func_addr, proj.loader, symbol_name)
    perf.end_vfg()

    try:
        if is_plot_ddg:
            perf.start_ddg()
            ddg = proj.analyses.VSA_DDG(vfg=vfg, start_addr=func_addr,
                                        interfunction_level=9,
                                        context_sensitivity_level=9,
                                        keep_data=True)
            # plot_common(ddg.graph, out_filename + '.ddg', format='png')
            plot_vsa_ddg(ddg.graph, os.path.join(out_dir, symbol_name) + '.ddg', format='png', project=proj, asminst=True)
            perf.end_ddg()
    except Exception as e:
        # TODO debug and fix
        # 好像是variable比较的时候出错，addr是Value set的情况。按照sp取栈变量的时候？
        logger.error(f'VSA_DDG failed for {mth_info}.')
        perf.end_ddg()


    # for st in simgr.stashes['deadended']:
    #     Record.RECORDS.get(func_addr).add_return_value(st.regs.r0, guard_condition=st.cond_hist)

    # for multiprocess running. param "returns" should be a        
    # multiprocessing.Manager().dict()
    if returns is not None:
        returns.update(CALL_RECORDS)
    logger.info(f"Finished analyzing {symbol_name}")
    return perf.get_times(), analysis_status

# TODO return SimTypeFunction for initial call_state?
def get_jni_function_params(proj, func_addr, clazz, sig, jenv_ptr):
    # for user's JNI function, the first 2 parameters are hidden from Java side
    # and the first one will always be the JNIEnv pointer.
    params = [jenv_ptr]
    # Some parameters need to be cooperated with state update, this dict will
    # be returned for this purpose.
    refmap_updates = dict()
    ref = proj.loader.extern_object.allocate()
    hobj = HeapObject(ref, 'reference', ('arg', func_addr, 1), True, clazz)
    # The second hidden parameter is either a jclass or jobject of the current
    # Java class where the native method lives. If it is a static method in
    # Java side, it will be a jclass otherwise a jobject.
    params.append(ref)
    refmap_updates.update({ref: hobj})
    # prepare for the none hidden parameters
    plist, has_obj = parse_params_from_sig(sig)
    logger.debug(f"Args: {plist}")
    if plist is not None:
        type_table = {
                'Z': 'boolean',
                'B': 'byte',
                'C': 'char',
                'S': 'short',
                'I': 'int',
                'J': 'long',
                'F': 'float',
                'D': 'double',
        }
        array_table = {
                '[Z': 'boolean_array',
                '[B': 'byte_array',
                '[C': 'char_array',
                '[S': 'short_array',
                '[I': 'int_array',
                '[J': 'long_array',
                '[F': 'float_array',
                '[D': 'double_array',
        }
        for ind, p in enumerate(plist):
            # first two arg is jenv, thisObj
            source = ('arg', func_addr, ind + 2)

            if p in type_table:
                type_str = type_table[p]
                value = BVS(f'{type_str}:{hex(func_addr)}arg{ind+2}', jni_type_size[type_str])
                hobj = HeapObject(value, type_str, source, True)
                refmap_updates.update({value._cache_key: hobj})
                param = value
            # elif p in array_table:
            #     type_str = array_table[p]
            #     ref = proj.loader.extern_object.allocate()
            #     hobj = HeapObject(ref, 'reference', source, True, type_str)
            #     refmap_updates.update({ref: hobj})
            else: # object, eg: p = 'java.lang.String'
                desc = p
                ref = proj.loader.extern_object.allocate()
                hobj = HeapObject(ref, 'reference', source, True, desc)
                # TODO enable NULL value after debugging VSA
                obj_symbol = BVV(ref, proj.arch.bits)# .union(0)
                refmap_updates.update({ref: hobj})
                param = obj_symbol
            params.append(param)
    else: # no param info
        num_args = 4
        logger.error(f"No param info for {hex(func_addr)} !!! guessing {num_args} arguments")
        for ind in range(num_args):
            source = ('arg', func_addr, ind + 2)
            value = BVS(f'unknown:{hex(func_addr)}arg{ind+2}', proj.arch.bits)
            hobj = HeapObject(value, "unknown", source, True)
            refmap_updates.update({value._cache_key: hobj})
            param = value
            params.append(param)

    return params, refmap_updates




def register_jni_relevant_data_type():
    register_types(parse_type('struct JNINativeMethod ' +\
                              '{const char* name;' +\
                              'const char* signature;' +\
                              'void* fnPtr;}'))


def plot_vsa_ddg(ddg_data, fname, format="png", project=None, asminst=False, vexinst=True):
    from bingraphvis.angr.annotator import AngrColorDDGStmtEdges
    from bingraphvis.angr.content import AngrAsm, AngrVex
    from bingraphvis.angr.source import AngrCommonSource
    from bingraphvis.base import Vis
    from bingraphvis.output import DotOutput
    vis = Vis()
    vis.set_source(AngrCommonSource())

    vis.add_content(VSADDGLocationHead())
    if project:
        if asminst:
            vis.add_content(AngrAsm(project))
        if vexinst:
            vis.add_content(AngrVex(project))

    vis.add_edge_annotator(AngrColorDDGStmtEdges(project=project))
    vis.set_output(DotOutput(fname, format=format))
    vis.process(ddg_data)


from angr.code_location import CodeLocation
from bingraphvis.base import Content, EdgeAnnotator


class VSADDGLocationHead(Content):
    def __init__(self):
        super(VSADDGLocationHead, self).__init__('head_location', ['name'])

    def gen_render(self, n):
        node = n.obj #type: CodeLocation
        label = None
        if node.sim_procedure:
            label = node.sim_procedure
        else:
            # label = f'{hex(node.ins_addr)} Block[{hex(node.block_addr)} {str(node.stmt_idx)}th]'
            label = f'Location{repr(node)}'

        n.content[self.name] = {
            'data': [{
                'name': {
                    'content': label
                }
            }], 
            'columns': self.get_columns()
        }
