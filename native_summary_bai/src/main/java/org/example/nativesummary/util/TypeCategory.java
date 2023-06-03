package org.example.nativesummary.util;

import com.bai.util.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;

public enum TypeCategory {
    UNKNOWN,
    JNIENV,
    NUMBER, // 该类型使用Taint追踪传播
    BUFFER, // 需要返回HeapRegion的类型，使用HeapRegion追踪传播
    JNI_VALUE, // JNI的不透明值
    JAVA_VM;

    public static TypeCategory byName(DataType dt) {
        DataType originalDt = dt;
        TypeCategory ret;
        ret = handleJavaNameIterTypedef(dt);
        if (ret != null && ret != UNKNOWN) {
            return ret;
        }
        // Non java type
        // skip TypeDef TODO enum?
        if (dt instanceof TypeDef) {
            dt = ((TypeDef) dt).getBaseDataType();
        }
        ret = handleCType(dt.getName());
        if (ret != null) {
            return ret;
        }
        if (originalDt.getName().equals("undefined")) {
            return UNKNOWN;
        }
        Logging.error("[TypeCategory] Unknown return type: " + originalDt.getName());
        return UNKNOWN;
    }

    private static TypeCategory handleCType(String cTypeName) {
        switch (cTypeName.replaceAll("\\s+", "")) {
            case "char":
            case "short":
            case "int":
            case "long":
            case "uint":
            case "ulong":
                return NUMBER;
            case "char*":
                return BUFFER;
            case "FILE*":
            case "void*":
                return JNI_VALUE;
            default:
                return null;
        }
    }
    private static TypeCategory handleJavaNameIterTypedef(DataType dt) {
        // 简单检测jshort*类型
        if (dt instanceof Pointer && handleJavaName(((Pointer) dt).getDataType().getName())==NUMBER) {
            return BUFFER;
        }
        // 递归检测类似typedef jshortArray jobject这种类型
        do {
            TypeCategory tc = handleJavaName(dt.getName());
            if (tc != UNKNOWN) {
                return tc;
            }
            if (dt instanceof TypeDef) {
                dt = ((TypeDef) dt).getDataType();
            }
        } while(dt instanceof TypeDef);
        return handleJavaName(dt.getName());
    }

    private static TypeCategory handleJavaName(String dtName) {
        switch (dtName.replaceAll("\\s+", "").toLowerCase()) {
            case "jmethodid":
            case "jfieldid":
            case "jclass":
            case "jvalue":
            case "jstring":
            case "jarray":
            case "jthrowable":
            case "jobject":
                return JNI_VALUE;
            case "jboolean":
            case "jchar":
            case "jbyte":
            case "jshort":
            case "jint":
            case "jsize":
            case "jlong":
            case "jfloat":
            case "jdouble":
                return NUMBER;
            case "jnienv*":
                return JNIENV;
            case "javavm*":
                return JAVA_VM;
            default:
                return UNKNOWN;
        }
    }
}
