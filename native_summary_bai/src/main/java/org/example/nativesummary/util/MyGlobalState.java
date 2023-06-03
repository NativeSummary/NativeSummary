package org.example.nativesummary.util;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import org.example.nativesummary.checkers.SummaryExporter;
import org.example.nativesummary.env.TaintMap;
import org.example.nativesummary.mapping.JSONAnalyzer;
import org.javimmutable.collections.JImmutableMap;
import org.javimmutable.collections.tree.JImmutableTreeMap;

/**
 * 由于一次分析需要运行多次BinAbsInspector，因此它的GlobalState也不再Global。
 * - 发现JNI_OnLoad方法存在的时候，设置onLoad
 * - 在开始分析JNI_onLoad前，设置onLoadContext
 * - 分析结束后，onJNIOnLoadFinish被调用，此时设置onLoadContext和onloadJNIm
 * - 分析其他的时候
 */
public class MyGlobalState {

    public static JNIManager onloadJNIm;
    public static JNIManager jnim;
    public static SummaryExporter se;
    public static int defaultPointerSize; // 按字节的, 4或者8
    /** current jni function. easily get function params' types */
    public static Function currentJNI;
    public static JSONAnalyzer ja;
    // global decompiler result cache
    public static DecompilerCache decom;
    public static PcodePrettyPrinter pp;
    public static Function onLoad;
    public static Context onLoadContext;

//    entrypoint env for global data section. To preserve modification done by JNI_OnLoad
    public static AbsEnv onLoadEnv;

    public static WarningDeduplicator warner;


    public static void reset(GhidraScript main) {
        defaultPointerSize = main.getCurrentProgram().getDefaultPointerSize();
        onloadJNIm = null;
        jnim = new JNIManager();
        se = new SummaryExporter();
        try {
            decom = new DecompilerCache(main.getState());
        } catch (RuntimeException e) {
            main.println(e.getMessage());
            e.printStackTrace();
        }
        pp = new PcodePrettyPrinter(main.getCurrentProgram());
        ja = null;
        onLoad = null;
        onLoadContext = null;
        onLoadEnv = null;
        warner = new WarningDeduplicator();
    }

    public static void onStartOne(Function f, org.example.nativesummary.ir.Function irFunc) {
        jnim = new JNIManager(onloadJNIm);
        TaintMap.reset();
        currentJNI = f;
        se.onStartFunc(irFunc);
        warner.onStartOne();
    }

    public static void onFinishOne() {
        se.check();
        se.onFinishFunc(currentJNI.equals(onLoad));
    }

    // get exit env for JNI_OnLoad, and set onLoadEnv.
    public static void onJNIOnLoadFinish() {
        JImmutableTreeMap<ALoc, KSet> exit = onLoadContext.getExitValue();
        AbsEnv out = new AbsEnv();
        for (JImmutableMap.Entry<ALoc, KSet> entry: exit) {
            ALoc aLoc = entry.getKey();
            // 仅加入全局变量
            if (aLoc.getRegion().isGlobal()) {
                out.set(aLoc, entry.getValue(), true);
            }
            // 其他的不加入
        }
        onLoadEnv = out;
        onloadJNIm = jnim;
    }
}
