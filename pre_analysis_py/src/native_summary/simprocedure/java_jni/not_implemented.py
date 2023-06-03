import logging

from . import JNISimProcedure, jni_functions, jvm_functions

l = logging.getLogger(__name__)

# pylint: disable=arguments-differ,unused-argument

class UnsupportedJNIFunction(JNISimProcedure):

    # to return a BVS
    return_ty = 'buffer'

    def run(self):
        # get name of the missing function
        native_arch_size = self.state.project.arch.bits
        jni_function_table = self.get_global_map().get('jenv_ptr')
        function_idx = (self.state.addr - jni_function_table) // (native_arch_size//8)
        function_name = list(jni_functions.keys())[function_idx]

        # show warning
        l.warning("SimProcedure for JNI function %s is not implemented. "
                  "Returning unconstrained symbol.", function_name)

        return self.prepare_ret_obj(function_name).value


class UnsupportedJENVFunction(JNISimProcedure):

    # to return a BVS
    return_ty = 'buffer'

    def run(self):
        # get name of the missing function
        native_arch_size = self.state.project.arch.bits
        jvm_function_table = self.get_global_map().get('jvm_ptr')
        function_idx = (self.state.addr - jvm_function_table) // (native_arch_size//8)
        function_name = list(jvm_functions.keys())[function_idx]

        # show warning
        l.warning("SimProcedure for JENV function %s is not implemented. "
                  "Returning unconstrained symbol.", function_name)

        return self.prepare_ret_obj(function_name).value
