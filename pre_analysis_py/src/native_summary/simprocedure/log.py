import re
import logging

from .java_jni import JNISimProcedure
from ..api_record import add_to_records

l = logging.getLogger(__name__)


class AndroidLogPrint(JNISimProcedure):
    """
    additional args are put together in the last arg
    """

    # level, tag, fmt_str_ptr
    arguments_ty = ('long', 'reference', 'reference')
    return_ty = 'int'

    def run(self, *args):
        level, tag, fmt_str_ptr = args
        cfmt='''\
(                                  # start of capture group 1
%                                  # literal "%"
(?:                                # first option
(?:[-+0 #]{0,5})                   # optional flags
(?:\d+|\*)?                        # width
(?:\.(?:\d+|\*))?                  # precision
(?:h|l|ll|w|I|I32|I64)?            # size
[cCdiouxXeEfgGaAnpsSZ]             # type
) |                                # OR
%%)                                # literal "%%"
'''
        arg_result = []
        for arg_exp, argty in zip(args, self.arguments_ty):
            result = self.resolve_arg(arg_exp, argty)
            arg_result.append(result)

        # convert tag to string
        arg_result[1] = {self._load_string_from_native_memory(addr) for addr in arg_result[1]}

        fmt_str_result = set()
        varg_result = set()
        # iterate in format string result
        for str_ptr in arg_result[2]:
            if type(str_ptr) != int:
                l.warning(f"AndroidLogPrint: fmt str addr resolved to type {type(str_ptr)}")
                continue
            fmt_str = self._load_string_from_native_memory(str_ptr)
            fmt_str_result.add(fmt_str)
            matches = list(re.finditer(cfmt, fmt_str, flags=re.X))
            for match in matches:
                arg = self.next_arg()
                result = self.resolve_arg(arg, match.string)
                varg_result.update(result)
        arg_result[2] = fmt_str_result
        # if len(varg_result) != 0:
        arg_result.append(varg_result)

        add_to_records(self.get_callsite(), type(self).__name__, tuple(arg_result))
        # num of bytes written TODO refine
        return 10
        # TODO
