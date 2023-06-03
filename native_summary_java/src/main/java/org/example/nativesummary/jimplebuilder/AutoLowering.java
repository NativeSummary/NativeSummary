package org.example.nativesummary.jimplebuilder;

import org.example.nativesummary.ir.Module;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * ~~和TypeAnalysis耦合，负责处理其中的extCallMap成员~~
 * 为每个外部函数调用生成对应的static native函数，然后生成static call
 */
public class AutoLowering {
    public static String[] handledApi = 
    {"ExceptionCheck", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear", "GetArrayLength", "PushLocalFrame", "PopLocalFrame", "DefineClass",
    "GetBooleanArrayRegion","GetByteArrayRegion","GetCharArrayRegion","GetShortArrayRegion","GetIntArrayRegion","GetLongArrayRegion","GetFloatArrayRegion","GetDoubleArrayRegion",
    "SetBooleanArrayRegion","SetByteArrayRegion","SetCharArrayRegion","SetShortArrayRegion","SetIntArrayRegion","SetLongArrayRegion","SetFloatArrayRegion","SetDoubleArrayRegion",
    "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements", "GetFloatArrayElements", "GetDoubleArrayElements",
};
    public static final Set<String> handledApiSet = new HashSet<>(Arrays.asList(handledApi));

    public static void process(Module summary, boolean isAnalyzePreLoad) {
        
    }
}
