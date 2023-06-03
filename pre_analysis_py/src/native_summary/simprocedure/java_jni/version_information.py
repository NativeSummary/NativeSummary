
from . import JNISimProcedure

# pylint: disable=arguments-differ,unused-argument

class GetVersion(JNISimProcedure):

    arguments_ty = ('jenv')
    return_ty = 'int'

    def run(self, *args, **kwargs):
        # return JNI version 1.8
        ret = 0x00010008
        return super().run(*args, return_constant=ret, **kwargs)
