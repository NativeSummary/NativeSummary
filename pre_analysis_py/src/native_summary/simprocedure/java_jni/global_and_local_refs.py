
import logging

from . import JNISimProcedure

l = logging.getLogger(__name__)

# pylint: disable=arguments-differ,unused-argument

#
# NewGlobalRef / NewWeakGlobalRef
#

class NewGlobalRef(JNISimProcedure):

    # ptr_env, obj_
    arguments_ty = ('jenv', 'reference')
    return_ty = 'reference'


#
# DeleteGlobalRef / DeleteWeakGlobalRef
#

class DeleteGlobalRef(JNISimProcedure):

    # ptr_env, obj_
    arguments_ty = ('jenv', 'reference')
    return_ty = 'void'


#
# NewLocalRef
#

class NewLocalRef(JNISimProcedure):

    # ptr_env, obj_
    arguments_ty = ('jenv', 'reference')
    return_ty = 'reference'


#
# DeleteLocalRef
#

class DeleteLocalRef(JNISimProcedure):

    # ptr_env, obj_
    arguments_ty = ('jenv', 'reference')
    return_ty = 'void'


