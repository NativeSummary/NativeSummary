import logging

from angr import SimProcedure
from angr.procedures.libc.memcpy import memcpy
from cle import SymbolType

from . import JNI_PROCEDURES
from .log import AndroidLogPrint

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class ReturnZero(SimProcedure):
    def run(self):
        self.ret(0)

class UnimplementedHook(SimProcedure):
    def __init__(self, symbol_name, *args, **kwargs):
        super(UnimplementedHook, self).__init__(*args, **kwargs)
        self.symbol_name = symbol_name

    def run(self):
        logger.warning("Symbol '%s' called but corresponding function is NOT implemented." % self.symbol_name)
        self.ret()

# Symbol name, SimProcedure
IMPLEMENTED_IMPORTS = [
    ("pthread_mutex_lock", ReturnZero),
    ("pthread_mutex_unlock", ReturnZero),
    ("__android_log_print", AndroidLogPrint),
    ("__aeabi_memcpy", memcpy)
    ]

import re

# inspired by isCallMth https://github.com/suncongxd/muDep/blob/main/scripts/IDA_script/x64/SourceSinkInvoke_kind.py#L35
call_method_regex = re.compile(r'JNIEnv.*(Call(Static|Nonvirtual)?.*Method)[^AV]')
unhandled_apis = ['NewObject', 'CallNonvirtual', 'CallStatic']

def hookAllImportSymbols(proj):
    # TODO why exactly
    # handle CallXXXMethod in .plt
    # these functions simply jump to a wrapper that calls their varg variant.
    for obj in proj.loader.all_elf_objects:
        for symb_, addr in obj.plt.items():
            if match := call_method_regex.search(symb_):
                f_name = match.group(1)
                logger.warning(f'Recognize "{symb_}" as `{f_name}` only by name!')
                from .java_jni import jni_functions
                proj.hook(addr, JNI_PROCEDURES['java_jni'][jni_functions[f_name]]())
                if jni_functions[f_name] .startswith('Unsupported'):
                    logger.error(f"But {f_name} is not implemented!")
            # # handle NewObject in .plt # ._ZN7_JNIEnv9NewObjectEP7_jclassP10_jmethodIDz
            elif symb_ == '_ZN7_JNIEnv9NewObjectEP7_jclassP10_jmethodIDz':
                logger.warning(f'Recognize "{symb_}" as `NewObject` by name!')
                proj.hook(addr, JNI_PROCEDURES['java_jni']['NewObject']())
            else: # in case
                for api in unhandled_apis:
                    if api in symb_:
                        logger.error(f"Possible unhooked API in plt: {symb_}")

    # Set hook on implemented imports
    for symbName, SimProc in IMPLEMENTED_IMPORTS:
        if proj.loader.find_symbol(symbName):
            proj.hook_symbol(symbName, SimProc(), replace=True)

    # Set warning SimProcedure on unimplemented imports
    for symb in proj.loader.symbols :
        if symb.is_import and symb.type == SymbolType.TYPE_FUNCTION:

            if symb.resolvedby:
                symb_addr = symb.resolvedby.rebased_addr
            else:
                symb_addr = symb.rebased_addr

            if proj.is_hooked(symb_addr):
                simProc = proj.hooked_by(symb_addr)
                if not simProc.is_stub:
                    # This symbol is already implemented by a SimProcedure
                    continue
                else:
                    logger.warning(f"{symb.name} is already hooked by an angr stub.")
                    continue

            proj.hook_symbol(symb_addr,  UnimplementedHook(symb.name), replace=False)
