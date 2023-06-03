package org.example.nativesummary.util;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.KSet;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import org.example.nativesummary.ir.Instruction;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;

public class Utils {

    public static DataTypeManager getSoDataTypeManage(DataTypeManagerService service) {
        // Look for an already open "jni_all" archive.
        DataTypeManager[] managers = service.getDataTypeManagers();
        for (DataTypeManager m : managers) {
            if (m.getName().endsWith(".so")) {
                return m;
            }
        }
        return null;
    }
    public static byte[] getStringFromMemory(Address addr) throws MemoryAccessException {
        MemoryBlock mb = GlobalState.currentProgram.getMemory().getBlock(addr);
        if (mb == null) {
            Logging.error("JNI cannot decode string at 0x"+addr.toString());
            return null;
        }
        if (mb.isWrite()) {
            Logging.error("JNI constant str not from readonly section!");
        }
        StringBuilder sb = new StringBuilder();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while(mb.getByte(addr) != 0) {
            out.write(mb.getByte(addr));
            addr = addr.add(1);
        }
        return out.toByteArray();
    }

    public static void applyFunctionSig(Program currentProgram, Function function, FunctionDefinition signature) throws InvalidInputException {
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                function.getEntryPoint(),
                signature,
                SourceType.USER_DEFINED
        );
        cmd.applyTo(currentProgram, TaskMonitor.DUMMY);
    }

    public static final Set<String> JNISymbols = Set.of(
            "GetVersion", "DefineClass", "FindClass", "FromReflectedMethod", "FromReflectedField", "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom", "ToReflectedField", "Throw", "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "FatalError", "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef", "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject", "NewObjectV", "NewObjectA", "GetObjectClass", "IsInstanceOf", "GetMethodID", "CallObjectMethod", "CallObjectMethodV", "CallObjectMethodA", "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA", "CallByteMethod", "CallByteMethodV", "CallByteMethodA", "CallCharMethod", "CallCharMethodV", "CallCharMethodA", "CallShortMethod", "CallShortMethodV", "CallShortMethodA", "CallIntMethod", "CallIntMethodV", "CallIntMethodA", "CallLongMethod", "CallLongMethodV", "CallLongMethodA", "CallFloatMethod", "CallFloatMethodV", "CallFloatMethodA", "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA", "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA", "CallNonvirtualObjectMethod", "CallNonvirtualObjectMethodV", "CallNonvirtualObjectMethodA", "CallNonvirtualBooleanMethod", "CallNonvirtualBooleanMethodV", "CallNonvirtualBooleanMethodA", "CallNonvirtualByteMethod", "CallNonvirtualByteMethodV", "CallNonvirtualByteMethodA", "CallNonvirtualCharMethod", "CallNonvirtualCharMethodV", "CallNonvirtualCharMethodA", "CallNonvirtualShortMethod", "CallNonvirtualShortMethodV", "CallNonvirtualShortMethodA", "CallNonvirtualIntMethod", "CallNonvirtualIntMethodV", "CallNonvirtualIntMethodA", "CallNonvirtualLongMethod", "CallNonvirtualLongMethodV", "CallNonvirtualLongMethodA", "CallNonvirtualFloatMethod", "CallNonvirtualFloatMethodV", "CallNonvirtualFloatMethodA", "CallNonvirtualDoubleMethod", "CallNonvirtualDoubleMethodV", "CallNonvirtualDoubleMethodA", "CallNonvirtualVoidMethod", "CallNonvirtualVoidMethodV", "CallNonvirtualVoidMethodA", "GetFieldID", "GetObjectField", "GetBooleanField", "GetByteField", "GetCharField", "GetShortField", "GetIntField", "GetLongField", "GetFloatField", "GetDoubleField", "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField", "SetShortField", "SetIntField", "SetLongField", "SetFloatField", "SetDoubleField", "GetStaticMethodID", "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA", "CallStaticBooleanMethod", "CallStaticBooleanMethodV", "CallStaticBooleanMethodA", "CallStaticByteMethod", "CallStaticByteMethodV", "CallStaticByteMethodA", "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA", "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA", "CallStaticIntMethod", "CallStaticIntMethodV", "CallStaticIntMethodA", "CallStaticLongMethod", "CallStaticLongMethodV", "CallStaticLongMethodA", "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA", "CallStaticDoubleMethod", "CallStaticDoubleMethodV", "CallStaticDoubleMethodA", "CallStaticVoidMethod", "CallStaticVoidMethodV", "CallStaticVoidMethodA", "GetStaticFieldID", "GetStaticObjectField", "GetStaticBooleanField", "GetStaticByteField", "GetStaticCharField", "GetStaticShortField", "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField", "GetStaticDoubleField", "SetStaticObjectField", "SetStaticBooleanField", "SetStaticByteField", "SetStaticCharField", "SetStaticShortField", "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField", "SetStaticDoubleField", "NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength", "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement", "NewBooleanArray", "NewByteArray", "NewCharArray", "NewShortArray", "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray", "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements", "GetFloatArrayElements", "GetDoubleArrayElements", "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements", "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements", "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements", "GetBooleanArrayRegion", "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion", "GetIntArrayRegion", "GetLongArrayRegion", "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion", "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion", "SetIntArrayRegion", "SetLongArrayRegion", "SetFloatArrayRegion", "SetDoubleArrayRegion", "RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion", "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical", "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType"
            );

    public static boolean isParameterJNIEnvPtr(Parameter p) {
        return p.getDataType().getName().equals("JNIEnv *");
    }

    public static boolean isParameterJavaVMPtr(Parameter p) {
        return p.getDataType().getName().equals("JavaVM *");
    }


    public static Function getExternalFunc(String name) {
        // Function externalTarget = getCurrentProgram().getListing().getFunctions(Library.UNKNOWN, fname).get(0);
        Namespace ext = GlobalState.currentProgram.getExternalManager().getExternalLibrary(Library.UNKNOWN);
        List<ExternalLocation> l = GlobalState.currentProgram.getExternalManager().getExternalLocations(Library.UNKNOWN, name);
        if (l.size() == 0) {
            Logging.error("getExternalJNIFunc: Cannot find "+name+".");
            return null;
        }
        return l.get(0).getFunction();
    }


    public static boolean isAllZero(long[] callString) {
        for (long l: callString) {
            if (l != 0) {
                return false;
            }
        }
        return true;
    }

    public static String funcNameAndAddr(Function func) {
        return String.format(
                "%s @ %s",
                getFuncName(func),
                func.getEntryPoint().toString());
    }

    public static String getFuncName(Function func) {
        if (func.getName() != null)
            return func.getName();
        return "(undefined)";
    }

    public static String describeAddr(long addr) {
        if (addr == 0) {
            return "[0]";
        }
        Function func = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(addr));
        return String.format("%s[%s]", func == null? "null":func.getName(), Long.toHexString(addr));
    }

    public static String generateCallComments(long[] callstring, long callsite) {
        StringJoiner sj;
        if (callstring == null) {
            return String.format("context: null, callsite: %s", describeAddr(callsite));
        } else if (callstring.length > 1) {
            sj = new StringJoiner(", ", "{", "}");
        } else {
            sj = new StringJoiner(", ");
        }
        for (long addr: callstring) {
            sj.add(describeAddr(addr));
        }
        return String.format("context: %s, callsite: %s", sj.toString(), describeAddr(callsite));
    }

    public static void appendToComments(Instruction inst, String comment) {
        if (inst.comments == null) {
            inst.comments = comment;
        } else {
            inst.comments += comment;
        }
    }

    public static void prependToComments(Instruction inst, String comment) {
        if (inst.comments == null) {
            inst.comments = comment;
        } else {
            inst.comments = comment + inst.comments;
        }
    }

    public static AbsVal getExactSpVal(AbsEnv env) {
        KSet sp = env.get(ALoc.getSPALoc());
        if (sp.isTop() || sp.getInnerSet().size() > 1) {
            return null;
        }
        AbsVal val = sp.iterator().next();
        if (val.getRegion().isLocal()) {
            return val;
        }
        return null;
    }

    public static Function getExternalFunctionAt(Address targetAddress, Address current) {
        // does not apply to plt section
        if (current != null && GlobalState.flatAPI.getMemoryBlock(current).getName().contains(".plt")) {
            return null;
        }
        if (targetAddress == null) { return null; }
        Function callee = GlobalState.flatAPI.getFunctionAt(targetAddress);
        if (callee == null) {
            return null;
        }

        if (callee.isThunk()) {
            callee = callee.getThunkedFunction(true);
        }

        if (callee.isExternal() || FunctionModelManager.isFunctionAddressMapped(targetAddress)) {
            return callee;
        }
        return null;
    }

    public static boolean isResolutionExact(List<ALoc> alocs, AbsEnv env) {
        boolean isExact = true;
        if (alocs.size() > 1) {
            isExact = false;
        } else {
            KSet ks = env.get(alocs.get(0));
            if (ks.isTop() || ks.getInnerSet().size() > 1) {
                isExact = false;
            }
        }
        return isExact;
    }

    public static ALoc toALoc(AbsVal val, int size) {
        return ALoc.getALoc(val.getRegion(), val.getValue(), size);
    }
}
