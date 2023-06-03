import logging

from . import JNISimProcedure

l = logging.getLogger(__name__)

class ThrowNew(JNISimProcedure):
    # jint ThrowNew(JNIEnv *env, jclass clazz, const char *message);
    arguments_ty = ('jenv', 'reference', 'string')
    return_ty = 'int'

class Throw(JNISimProcedure):
    # jint Throw(JNIEnv *env, jthrowable obj);
    arguments_ty = ('jenv', 'reference')
    return_ty = 'int'

class ExceptionDescribe(JNISimProcedure):
    # void ExceptionDescribe(JNIEnv *env);
    arguments_ty = ('jenv')
    return_ty = 'void'

class ExceptionClear(JNISimProcedure):
    # void ExceptionClear(JNIEnv *env);
    arguments_ty = ('jenv')
    return_ty = 'void'

class ExceptionCheck(JNISimProcedure):
    # jboolean ExceptionCheck(JNIEnv *env);
    arguments_ty = ('jenv')
    return_ty = 'boolean'

class ExceptionOccurred(JNISimProcedure):
    # jthrowable (JNICALL *ExceptionOccurred) (JNIEnv *env);
    arguments_ty = ('jenv')
    return_ty = 'reference'

class FatalError(JNISimProcedure):
    # void FatalError(JNIEnv *env, const char *msg);
    arguments_ty = ('jenv', 'string')
    return_ty = 'void'

