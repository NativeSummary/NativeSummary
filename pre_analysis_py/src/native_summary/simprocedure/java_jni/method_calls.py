
import logging
from typing import Optional

from . import JNISimProcedure

l = logging.getLogger(__name__)

# pylint: disable=arguments-differ,unused-argument

#
# GetMethodID / GetStaticMethodID
#

class GetMethodID(JNISimProcedure):

    # ptr_env, class_, ptr_method_name, ptr_method_sig
    arguments_ty = ('jenv', 'reference', 'string', 'string')
    return_ty = 'reference'

class GetStaticMethodID(GetMethodID):
    pass

#
# Call<Type>Method / CallNonvirtual<Type>Method / CallStatic<Type>Method
#

class CallMethodBase(JNISimProcedure):

    return_ty: Optional[str] = None


#
# Call<Type>Method
#

# TODO
class CallMethod(CallMethodBase):
    # ptr_env, obj_, method_id_
    # resolve one possible argument TODO
    arguments_ty = ('jenv', 'reference', 'reference', '...')
    # def run(self, ptr_env, obj_, method_id_):

    def return_from_invocation(self, ptr_env, obj_, method_id_):
        return self._return_from_invocation()

class CallMethodA(CallMethodBase):
    # do something with reference_ptr?? TODO
    # ptr_env, obj_, method_id_, ptr_args
    arguments_ty = ('jenv', 'reference', 'reference', 'reference_ptr')

    def run(self, *args, **kwargs):
        l.error(f"CallMethodA is not really implemented.")
        return super().run(*args, **kwargs)

    def return_from_invocation(self, ptr_env, obj_, method_id_, ptr_args):
        return self._return_from_invocation()

class CallObjectMethod(CallMethod):
    return_ty = 'reference'
class CallBooleanMethod(CallMethod):
    return_ty = 'boolean'
class CallByteMethod(CallMethod):
    return_ty = 'byte'
class CallCharMethod(CallMethod):
    return_ty = 'char'
class CallShortMethod(CallMethod):
    return_ty = 'short'
class CallIntMethod(CallMethod):
    return_ty = 'int'
class CallLongMethod(CallMethod):
    return_ty = 'long'
class CallVoidMethod(CallMethod):
    return_ty = 'void'
class CallObjectMethodA(CallMethodA):
    return_ty = 'reference'
class CallBooleanMethodA(CallMethodA):
    return_ty = 'boolean'
class CallByteMethodA(CallMethodA):
    return_ty = 'byte'
class CallCharMethodA(CallMethodA):
    return_ty = 'char'
class CallShortMethodA(CallMethodA):
    return_ty = 'short'
class CallIntMethodA(CallMethodA):
    return_ty = 'int'
class CallLongMethodA(CallMethodA):
    return_ty = 'long'
class CallVoidMethodA(CallMethodA):
    return_ty = 'void'

#
# CallNonVirtual<Type>Method
#

class CallNonvirtualMethod(CallMethodBase):

    # ptr_env, obj_, class_, method_id_
    arguments_ty = ('jenv', 'reference', 'reference', 'reference', '...')

    # def run(self, ptr_env, obj_, class_, method_id_):
    #     method_id = self.state.jni_references.lookup(method_id_)
    #     obj = self.state.jni_references.lookup(obj_)
    #     self._invoke(method_id, obj, dynamic_dispatch=False)

    def return_from_invocation(self, ptr_env, obj_, class_, method_id_):
        return self._return_from_invocation()

class CallNonvirtualMethodA(CallMethodBase):

    # do something with reference_ptr?? TODO
    # ptr_env, obj_, class_, method_id_, ptr_args
    arguments_ty = ('jenv', 'reference', 'reference', 'reference', 'reference_ptr')

    # def run(self, ptr_env, obj_, method_id_, ptr_args):
    #     method_id = self.state.jni_references.lookup(method_id_)
    #     obj = self.state.jni_references.lookup(obj_)
    #     self._invoke(method_id, obj, dynamic_dispatch=False, args_in_array=ptr_args)

    def return_from_invocation(self, ptr_env, obj_, method_id_, ptr_args):
        return self._return_from_invocation()

class CallNonvirtualObjectMethod(CallNonvirtualMethod):
    return_ty = 'reference'
class CallNonvirtualBooleanMethod(CallNonvirtualMethod):
    return_ty = 'boolean'
class CallNonvirtualByteMethod(CallNonvirtualMethod):
    return_ty = 'byte'
class CallNonvirtualCharMethod(CallNonvirtualMethod):
    return_ty = 'char'
class CallNonvirtualShortMethod(CallNonvirtualMethod):
    return_ty = 'short'
class CallNonvirtualIntMethod(CallNonvirtualMethod):
    return_ty = 'int'
class CallNonvirtualLongMethod(CallNonvirtualMethod):
    return_ty = 'long'
class CallNonvirtualVoidMethod(CallNonvirtualMethod):
    return_ty = 'void'
class CallNonvirtualObjectMethodA(CallNonvirtualMethodA):
    return_ty = 'reference'
class CallNonvirtualBooleanMethodA(CallNonvirtualMethodA):
    return_ty = 'boolean'
class CallNonvirtualByteMethodA(CallNonvirtualMethodA):
    return_ty = 'byte'
class CallNonvirtualCharMethodA(CallNonvirtualMethodA):
    return_ty = 'char'
class CallNonvirtualShortMethodA(CallNonvirtualMethodA):
    return_ty = 'short'
class CallNonvirtualIntMethodA(CallNonvirtualMethodA):
    return_ty = 'int'
class CallNonvirtualLongMethodA(CallNonvirtualMethodA):
    return_ty = 'long'
class CallNonvirtualVoidMethodA(CallNonvirtualMethodA):
    return_ty = 'void'

#
# CallStatic<Type>Method
#

class CallStaticMethod(CallMethodBase):

    # ptr_env, class_, method_id_
    arguments_ty = ('jenv', 'reference', 'reference', '...')

    # def run(self, ptr_env, class_, method_id_):
    #     method_id = self.state.jni_references.lookup(method_id_)
    #     self._invoke(method_id, dynamic_dispatch=False)

    def return_from_invocation(self, ptr_env, class_, method_id_):
        return self._return_from_invocation()

class CallStaticMethodA(CallMethodBase):

    # ptr_env, obj_, method_id_, ptr_args
    # do something with reference_ptr?? TODO
    arguments_ty = ('jenv', 'reference', 'reference', 'reference_ptr')

    # def run(self, ptr_env, obj_, method_id_, ptr_args):
    #     method_id = self.state.jni_references.lookup(method_id_)
    #     self._invoke(method_id, dynamic_dispatch=False, args_in_array=ptr_args)

    def return_from_invocation(self, ptr_env, class_, method_id_, ptr_args):
        return self._return_from_invocation()

class CallStaticObjectMethod(CallStaticMethod):
    return_ty = 'reference'
class CallStaticBooleanMethod(CallStaticMethod):
    return_ty = 'boolean'
class CallStaticByteMethod(CallStaticMethod):
    return_ty = 'byte'
class CallStaticCharMethod(CallStaticMethod):
    return_ty = 'char'
class CallStaticShortMethod(CallStaticMethod):
    return_ty = 'short'
class CallStaticIntMethod(CallStaticMethod):
    return_ty = 'int'
class CallStaticLongMethod(CallStaticMethod):
    return_ty = 'long'
class CallStaticVoidMethod(CallStaticMethod):
    return_ty = 'void'
class CallStaticObjectMethodA(CallStaticMethodA):
    return_ty = 'reference'
class CallStaticBooleanMethodA(CallStaticMethodA):
    return_ty = 'boolean'
class CallStaticByteMethodA(CallStaticMethodA):
    return_ty = 'byte'
class CallStaticCharMethodA(CallStaticMethodA):
    return_ty = 'char'
class CallStaticShortMethodA(CallStaticMethodA):
    return_ty = 'short'
class CallStaticIntMethodA(CallStaticMethodA):
    return_ty = 'int'
class CallStaticLongMethodA(CallStaticMethodA):
    return_ty = 'long'
class CallStaticVoidMethodA(CallStaticMethodA):
    return_ty = 'void'
