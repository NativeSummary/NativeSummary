import logging

from . import JNISimProcedure

l = logging.getLogger(__name__)

# pylint: disable=arguments-differ,unused-argument

class GetSuperclass(JNISimProcedure):

    # ptr_env, class_
    arguments_ty = ('jenv', 'reference')
    return_ty = 'reference'
    # TODO possibly null

    def run(self, *args, **kwargs):
        l.warning(f'GetSuperclass: return value is nullable, but currently not implemented.')
        # .union(0) ? TODO
        return super().run(*args, **kwargs)


class FindClass(JNISimProcedure):

    # ptr_env, name_ptr
    arguments_ty = ('jenv', 'string')
    return_ty = 'reference'


