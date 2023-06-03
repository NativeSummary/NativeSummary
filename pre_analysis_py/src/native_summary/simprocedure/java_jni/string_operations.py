
import logging

from . import JNISimProcedure

l = logging.getLogger(__name__)

# pylint: disable=arguments-differ,unused-argument

#
# GetStringUTFChars
#

class GetStringUTFChars(JNISimProcedure):

    # ptr_env, str_ref_, ptr_isCopy
    arguments_ty = ('jenv', 'reference', 'reference')
    return_ty = 'buffer'

    def run(self, *args, **kwargs):
        ptr_env, str_ref_, ptr_isCopy = args
        ret = super().run(*args, **kwargs)

        # TODO if isCopy is not null, store JNI_TRUE at that address
        if self.state.solver.eval(ptr_isCopy != 0):
            l.warning('GetStringUTFChars: isCopy is not null!')
            self._store_in_native_memory(data=self.JNI_TRUE,
                                         data_type='boolean',
                                         addr=ptr_isCopy)

        return ret

#
# ReleaseStringUTFChars
#

class ReleaseStringUTFChars(JNISimProcedure):

    # ptr_env, str_ref_, native_buf(ret value of GetStringUTFChars)
    arguments_ty = ('jenv', 'reference', 'reference')
    return_ty = 'void'


#
# NewStringUTF
#

class NewStringUTF(JNISimProcedure):

    # ptr_env, ptr_str_bytes
    arguments_ty = ('jenv', 'string')
    return_ty = 'reference'


#
# GetStringUTFLength
#

class GetStringUTFLength(JNISimProcedure):

    # ptr_env, str_ref_
    arguments_ty = ('jenv', 'reference')
    return_ty = 'int'

