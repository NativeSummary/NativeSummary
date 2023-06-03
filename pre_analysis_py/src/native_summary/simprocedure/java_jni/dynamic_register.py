import logging

from . import JNISimProcedure
from ...api_record import add_to_records

l = logging.getLogger(__name__)

# jint (JNICALL *RegisterNatives)
#     (JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
# jint (JNICALL *UnregisterNatives)
#     (JNIEnv *env, jclass clazz);

class RegisterNatives(JNISimProcedure):

    # JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods
    arguments_ty = ('jenv', 'reference', 'reference', 'int')
    return_ty = "int"

    def run(self, *args, **kwargs):
        arg_result = []
        for arg_exp, argty in zip(args, self.arguments_ty):
            if argty == None or argty == 'jenv':
                arg_result.append(None)
                continue
            result = self.resolve_arg(arg_exp, argty)
            arg_result.append(result)
        arg_result = tuple(arg_result)
        add_to_records(self.get_callsite(), type(self).__name__, arg_result)

        l.warning('RegisterNatives is being called.')

        # defer resolution after VFG(VSA)

        return self.JNI_OK


class UnregisterNatives(JNISimProcedure):

    # JNIEnv *env, jclass clazz
    arguments_ty = ('jenv', 'reference')
    return_ty = "int" # constant

    def run(self, *args, **kwargs):
        # return constant 0
        return super().run(*args, return_constant=self.JNI_OK, **kwargs)
