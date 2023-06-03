import logging
from .common import HeapObject, JNINativeMethod

l = logging.getLogger(__name__)

# 对每个API
# key = (callsite, apiname)
# val = tuple[set]
# requires import again when needed
CALL_RECORDS = dict()

# special api name for return value
RETURN_VALUE = 'RETURN_VALUE'


def add_ret_to_records(func_addr, arguments: tuple[set]):
    add_to_records(func_addr, RETURN_VALUE, arguments)


def add_to_records(callsite, apiname, arguments):
    key = (callsite, apiname)
    existing = CALL_RECORDS.get(key, None) #type: tuple[set]
    if existing == None:
        CALL_RECORDS[key] = arguments
        return
    # merge arguments into existing
    for res_new, res_old in zip(arguments, existing):
        if res_old != None or res_new != None:
            res_old.update(res_new)


def clear_call_records():
    global CALL_RECORDS
    CALL_RECORDS = dict()


def print_call_records(records, fname, func_addr, loader, func_name=None):
    if func_name == None:
        api_symbol = loader.find_symbol(func_addr)
        if api_symbol == None:
            l.error(f"print_call_records: no corresponding symbols!")
            func_name = '<unknown>'
        else:
            func_name = api_symbol.name

    f = None
    if fname is None:
        import sys
        f = sys.stdout
    else:
        f = open(fname, 'a')
    f.write(f"When analyzing {func_name}({hex(func_addr)}):\n")
    for (callsite, api_name), args in records.items():
        f.write(f"  {hex(callsite)} call {api_name}:\n")
        for ind, vals in enumerate(args):
            f.write(f"    arg{ind}: ")
            if vals == None:
                f.write('None(unknown or not resolved)\n')
                continue
            is_first_time = True
            for val in vals:
                if not is_first_time: f.write(', ')
                is_first_time = False
                f.write(format_resolved_results(val, loader))
            f.write('\n')
    # if ret_val != None:
    #     f.write(f"  return value:")
    #     is_first_time = True
    #     for val in ret_val:
    #         if not is_first_time: f.write(', ')
    #         is_first_time = False
    #         f.write(format_resolved_results(val, loader))
    #     f.write('\n')
    f.close()

def format_resolved_results(val, loader):
    if type(val) == int:
        if val < 0x1000:
            return str(val)
        else:
            return hex(val)
    elif type(val) == str:
        return repr(val)
    elif type(val) == HeapObject:
        source = val.source
        if source[0] == 'arg':
            if (symb := loader.find_symbol(source[1])):
                func_name = symb.name
            else:
                func_name = hex(source[1])
            return f'HeapObject(func {func_name} arg {source[2]})'
        elif source[0] == 'ret':
            return f'HeapObject({source[2]} ret val from {hex(source[1])} {loader.describe_addr(source[1])})'
    elif type(val) == JNINativeMethod:
        return f'{{{repr(val.name)}, {repr(val.sig)}, {loader.describe_addr(val.ptr)}}}'
    else:
        l.warning('Unable to resolve result')
