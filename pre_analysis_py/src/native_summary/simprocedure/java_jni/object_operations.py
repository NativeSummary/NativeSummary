import logging

from . import JNISimProcedure
from .method_calls import CallMethodBase

l = logging.getLogger(__name__)

# pylint: disable=arguments-differ,unused-argument

#
# GetObjectClass
#

class GetObjectClass(JNISimProcedure):

    # ptr_env, obj_
    arguments_ty = ('jenv', 'reference')
    return_ty = 'reference'


#
# AllocObject
#

class AllocObject(JNISimProcedure):

    # ptr_env, obj_class_
    arguments_ty = ('jenv', 'reference')
    return_ty = 'reference'


#
# NewObject
#

class NewObject(CallMethodBase):

    # ptr_env, obj_class_, method_id_
    arguments_ty = ('jenv', 'reference', 'reference', '...')
    return_ty = 'reference'


#
# IsInstanceOf
#

class IsInstanceOf(CallMethodBase):

    # ptr_env, obj_, target_class_
    arguments_ty = ('jenv', 'reference', 'reference')
    return_ty = 'boolean'


#
# IsSameObject
#

class IsSameObject(JNISimProcedure):

    # ptr_env, ref1_, ref2_
    arguments_ty = ('jenv', 'reference', 'reference')
    return_ty = 'boolean'


