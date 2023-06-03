package org.example.nativesummary.env.funcs;

import com.bai.env.*;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.Heap;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import org.example.nativesummary.util.*;
import org.example.nativesummary.util.*;

import java.util.List;
import java.util.Set;

public class JNIFunctionBase extends ExternalFunctionBase {
    // 在每次PcodeVisitor那边调用ExternalFunction的Model之前会设置一下这个，从而在不必大量修改接口的同时传入callsite。
    public static Address currentCallSite;

    private static final Set<String> staticSymbols = Set.of( // "GetObjectClass", "GetMethodID", "CallObjectMethodV", "GetStringUTFChars",
            "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod", "FromReflectedField", "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom", "ToReflectedField", "Throw", "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "FatalError", "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef", "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject", "NewObjectV", "NewObjectA", "GetObjectClass", "IsInstanceOf", "GetMethodID", "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA", "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA", "CallByteMethod", "CallByteMethodV", "CallByteMethodA", "CallCharMethod", "CallCharMethodV", "CallCharMethodA", "CallShortMethod", "CallShortMethodV", "CallShortMethodA", "CallIntMethod", "CallIntMethodV", "CallIntMethodA", "CallLongMethod", "CallLongMethodV", "CallLongMethodA", "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA", "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA", "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA", "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV", "CallNonvirtualObjectMethodA", "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA", "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV", "CallNonvirtualByteMethodA", "CallNonvirtualCharMethod", "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA", "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV", "CallNonvirtualShortMethodA", "CallNonvirtualIntMethod", "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA", "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV", "CallNonvirtualLongMethodA", "CallNonvirtualFloatMethod", "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA", "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV", "CallNonvirtualDoubleMethodA", "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA", "GetFieldID", "GetObjectField", "GetBooleanField", "GetByteField", "GetCharField", "GetShortField", "GetIntField", "GetLongField", "GetFloatField", "GetDoubleField", "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField", "SetShortField", "SetIntField", "SetLongField", "SetFloatField", "SetDoubleField", "GetStaticMethodID", "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA", "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA", "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA", "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA", "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA", "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA", "CallStaticLongMethod", "CallStaticLongMethodV", "CallStaticLongMethodA", "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA", "CallStaticDoubleMethod", "CallStaticDoubleMethodV", "CallStaticDoubleMethodA", "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA", "GetStaticFieldID", "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField", "GetStaticCharField", "GetStaticShortField", "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField", "GetStaticDoubleField", "SetStaticObjectField", "SetStaticBooleanField", "SetStaticByteField", "SetStaticCharField", "SetStaticShortField", "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField", "SetStaticDoubleField", "NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength", "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement", "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray", "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray", "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements", "GetFloatArrayElements", "GetDoubleArrayElements", "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements", "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements", "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements", "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion", "GetIntArrayRegion", "GetLongArrayRegion", "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion", "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion", "SetIntArrayRegion", "SetLongArrayRegion", "SetFloatArrayRegion", "SetDoubleArrayRegion", "RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion", "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical", "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType",
            "DestroyJavaVM", "AttachCurrentThread", "DetachCurrentThread", "GetEnv", "AttachCurrentThreadAsDaemon",
            "__android_log_print"
            );

    public JNIFunctionBase() {
        super(staticSymbols);
    }

    public JNIFunctionBase(Set<String> staticSymbols) {
        super(staticSymbols);
    }

    // record this call for summary ir
    public static JNIValue recordCall(Context context, Function callFunc) {
        JNIValue jcs = new JNIValue(context, callFunc.getName(), currentCallSite.getOffset());
        // 先注册，待之后回来解析参数
        MyGlobalState.jnim.registerCall(jcs, context);
        return jcs;
    }

    public static JNIValue recordAllocCall(Context context, Function callFunc, Heap heap) {
        JNIValue jcs = recordCall(context, callFunc);
        MyGlobalState.jnim.heapMap.put(heap, jcs);
        return jcs;
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        // check GetEnv GetJavaVM
        int index = -1;
        String funcname = callFunc.getName();
        if (funcname.equals("GetEnv")) {
            // jint (JNICALL *GetEnv)(JavaVM *vm, void **penv, jint version);
            index = 1;
        }
        if (funcname.equals("GetJavaVM")) {
            // jint (JNICALL *GetJavaVM) (JNIEnv *env, JavaVM **vm);
            index = 1;
        }
        // need to set pointer for GetEnv GetJavaVM
        if (index != -1) {
            List<ALoc> alocs = getParamALocs(callFunc, index, inOutEnv);
            boolean isExact = Utils.isResolutionExact(alocs, inOutEnv);
            if (!isExact) {
                Logging.warn("GetEnv: Cannot accurately know JNIEnv*");
            }
            for (ALoc loc: alocs) {
                KSet ks = inOutEnv.get(loc);
                if (ks.isTop()) {  break; }
                for (AbsVal val: ks) {
                    if (val.getValue() == 0) { continue; }
                    ALoc ptr = Utils.toALoc(val, MyGlobalState.defaultPointerSize);
                    KSet env = new KSet(MyGlobalState.defaultPointerSize*8);
                    if (funcname.equals("GetEnv")) { // GetEnv
                        env = env.insert(new AbsVal(EnvSetup.getJNIEnv()));
                    } else if (funcname.equals("GetJavaVM")) { // GetJavaVM
                        env = env.insert(new AbsVal(EnvSetup.getJavaVM()));
                    }
                    assert env.getInnerSet().size() == 1;
                    inOutEnv.set(ptr, env, true);
                }
            }
            // handle return value (JNI_OK = 0)
            ALoc retALoc = getReturnALoc(callFunc, false);
            KSet ret = new KSet(retALoc.getLen()*8).insert(new AbsVal(0));
            if (ret != null) {
                inOutEnv.set(retALoc, ret, true);
            }
            // not recording.
            return;
        }

        // other API: only emulate return value
        if (!currentCallSite.isMemoryAddress()) {
            Logging.error("JNI callsite address is not memory address!");
        }
        JNIValue jcs = recordCall(context, callFunc);
        // Setting return value
        if (callFunc.getReturnType().getName().equals("void")) { // return void
            return;
        }
        ALoc retALoc = getReturnALoc(callFunc, false);
        if(callFunc.getReturnType().getName().equals("undefined")) {
            Logging.warn("Function ret type undefined: "+callFunc.getSignature().getPrototypeString());
        }
        KSet ret = null;
        // check RegisterNatives
        // return value copy from 4th arg
        // RegisterNatives现在只需要考虑返回值。
        if (callFunc.getName().equals("RegisterNatives")) {
            ret = getParamKSet(callFunc, 3, inOutEnv);
        } else { // all other case
            ret = JNIManager.getRetFromType(callFunc.getReturnType(), currentCallSite, jcs, retALoc.getLen() * 8, callFunc, context, inOutEnv);
        }
        if (ret != null) {
            inOutEnv.set(retALoc, ret, true);
        }
    }

    @Override
    public void defineDefaultSignature(Function calleeFunc) {
        // already set by previous processing TODO
        return;
    }

}
