import logging

from . import JNISimProcedure

l = logging.getLogger(__name__)

class NewDirectByteBuffer(JNISimProcedure):
    # jobject NewDirectByteBuffer(JNIEnv* env, void* address, jlong capacity);
    arguments_ty = ('jenv', 'pointer', 'long')
    return_ty = 'reference'

class GetDirectBufferAddress(JNISimProcedure):
    # void* GetDirectBufferAddress(JNIEnv* env, jobject buf);
    arguments_ty = ('jenv', 'reference')
    return_ty = 'buffer'

class GetDirectBufferCapacity(JNISimProcedure):
    # jlong GetDirectBufferCapacity(JNIEnv* env, jobject buf);
    arguments_ty = ('jenv', 'reference')
    return_ty = 'long'
