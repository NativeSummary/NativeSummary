import logging
import angr
import claripy
from .common import JNINativeMethod


logger = logging.getLogger(__name__)


def load_string_from_state(state, addr_):
    """
    Load zero terminated UTF-8 string from native memory.

    :param state: state.
    :return:      Loaded string.
    """
    # check if addr is symbolic
    if state.solver.symbolic(addr_):
        logger.error("Loading strings from symbolic addresses is not implemented. "
                "Continue execution with an empty string.")
        return ""
    addr = state.solver.eval(addr_)

    # load chars one by one
    chars = []
    import itertools
    for i in itertools.count():
        str_byte = state.memory.load(addr+i, size=1)
        if state.solver.symbolic(str_byte):
            logger.error("Loading of strings with symbolic chars is not supported. "
                    "Character %d is concretized.", i)
        str_byte = state.solver.eval(str_byte)
        if str_byte == 0:
            break
        chars.append(chr(str_byte))

    return "".join(chars)


def load_from_state(state, addr, data_size,
                                no_of_elements=1, return_as_list=False):
    """
    Load from native memory.

    :param addr:            Native load address.
    :param data_size:       Size of each element.
    :param no_of_elements:  Number of elements to load.
    :param return_as_list:  Whether to wrap a single element in a list.
    :return:                The value or a list of loaded element(s).
    """
    # check if addr is symbolic
    if addr is not None and state.solver.symbolic(addr):
        raise NotImplementedError('Symbolic addresses are not supported.')
    native_memory_endness = state.arch.memory_endness
    # load elements
    values = []
    for i in range(no_of_elements):
        value = state.memory.load(addr + i*data_size,
                                        size=data_size,
                                        endness=native_memory_endness)
        values.append(value)
    # return element(s)
    if no_of_elements == 1 and not return_as_list:
        return values[0]
    else:
        return values

def get_callsite_from_state(proj, state):
    # TODO use offset in so and so_name.
    
    # self.state.regs.lr and self.state.callsite is not accurate in tail call case.
    # link_reg = self.state.solver.eval(self.state.regs.lr)
    # return link_reg
    # return self.state.callstack.current_return_target

    for addr in reversed(state.history.jump_sources):
        # skip plt section
        sec = proj.loader.find_section_containing(addr)
        if sec.name == '.plt':
            continue
        if sec.name != '.text':
            logger.warning(f"get_callsite: find addr in unusual section {sec.name}.")
        return addr


def basic_arg_resolve(state, arg, ref_map, type_hint=None, log_tag='basic_arg_resolve') -> set:
    """
    returns set of HeapObject or int, (and string?)
    """
    ret = set()
    # unwrap SAO
    if type(arg) is angr.state_plugins.SimActionObject:
        arg = arg.to_claripy()

    if type(arg) is claripy.ast.BV:
        # if less than 10 concrete value TODO better solution?
        try:
            concretized = state.solver.eval_atmost(arg, 10)
        except angr.errors.SimValueError as e:
            concretized = []
        for con_val in concretized:
            # heap object
            if val:= ref_map.get(con_val, None): ret.add(val); continue
            # C constant string
            if type_hint == 'string':
                ret.add(load_string_from_state(state, con_val))
            else: # normal number?
                # TODO
                ret.add(con_val)

        # iterate to find BVS symbols
        for leaf in arg.leaf_asts():
            if leaf.op == 'BVS':
                key = leaf._cache_key
                if val:= ref_map.get(key, None): ret.add(val)
    else:
        logger.warning(f'{log_tag}: unknown type {type(arg)} in resolve_arg')
    return ret


def basic_JNINativeMethod_resolve(state, ptr: int, num: int) -> list[tuple[str, str, str]]:
    """
    find as many as possible. be robust(not throwing exceptions) even if num is incorrect(too big)
    ptr: concret address(JNINativeMethod *methods)
    num: concret int
    """
    ret = []
    byte_size = state.arch.bits // 8 # pointer size
    for i in range(num):
        try:
            name, signature, fptr = load_from_state(state, ptr, byte_size, 3)
            fptr = state.solver.eval(fptr)
            name = load_string_from_state(state, name)
            signature = load_string_from_state(state, signature)
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.warning(f"JNINativeMethod array resolve failed for {hex(ptr)} at ind {i}.")
            break
        else: # no exception
            ret.append(JNINativeMethod(name, signature, fptr))
    return ret


def print_dyn_reg_result(reg_result, file_path, loader):
    with open(file_path, 'a') as f:
        f.write(f'======RegisterNatives result======\n')
        for func_key, reg_mths in reg_result.items():
            f.write(f'RegisterNatives at {hex(func_key.native_summary_callsite)}:\n')
            for reg_mth in reg_mths:
                f.write(f'name: {repr(reg_mth.name)}, sig: {repr(reg_mth.sig)}, ptr: {loader.describe_addr(reg_mth.ptr)}\n')
        f.write(f'======RegisterNatives end======\n')