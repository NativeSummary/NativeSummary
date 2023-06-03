package org.example.nativesummary.jimplebuilder;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.example.nativesummary.ir.Function;
import org.example.nativesummary.ir.Instruction;
import org.example.nativesummary.ir.Module;
import org.example.nativesummary.ir.inst.Call;
import org.example.nativesummary.ir.inst.Phi;
import org.example.nativesummary.ir.utils.Use;
import org.example.nativesummary.ir.utils.Value;
import org.example.nativesummary.ir.value.Null;
import org.example.nativesummary.ir.value.Number;
import org.example.nativesummary.ir.value.Str;
import soot.Scene;
import soot.SootClass;

/**
 * 从函数名map到某个类？
 * __android_log_print 需要根据参数生成
 */
public class ExternalFuncLoweringEarly {
    public boolean isAnalyzePreLoad;
    Set<String> toLoad = new HashSet<>();
    // double as handledApiSet
    public static final Map<String, List<String>> loadMap = initLoadMap();
    //  android_LogPriority in C to Log.x name
    public static final String[] logPrioToMth = {"d", "d", "d", "d", "i", "w", "e", "e", "d"};

    public static void process(Module summary, boolean isAnalyzePreLoad) {
        ExternalFuncLoweringEarly instance = new ExternalFuncLoweringEarly(isAnalyzePreLoad);
        for (Function func: summary.funcs) {
            instance.visitFunction(func);
        }
        if (isAnalyzePreLoad) {
            for (String clz: instance.toLoad) {
                Scene.v().loadClass(clz, SootClass.SIGNATURES);
            }
        }
    }

    private static Map<String, List<String>> initLoadMap() {
        Map<String, List<String>> map = new HashMap<>();
        map.put("__android_log_print", List.of("android.util.Log"));
        // List<String> ctx = List.of("java.io.FileInputStream");
        // map.put("open", ctx);
        // map.put("fopen", ctx);
        // map.put("read", ctx);
        // map.put("fread", ctx);
        // List<String> files = List.of("java.io.FileOutputStream");
        // map.put("write", files);
        // map.put("fwrite", files);
        // map.put("fputs", files);
        // map.put("access", files);
        // map.put("stat", files);
        return map;
    }

    public ExternalFuncLoweringEarly(boolean isAnalyzePreLoad){
        this.isAnalyzePreLoad = isAnalyzePreLoad;
    }

    public void visitFunction(Function func) {
        int size = func.insts().size();
        for (int index=0;index < size; index++) {
            List<Instruction> toInsertAfter = new ArrayList<>();

            Instruction inst = func.insts().get(index);
            if (! (inst instanceof Call)) {
                continue;
            }
            Call call = (Call) inst;
            String api = call.target;
            if (api == null) {
                continue;
            }
            // 仅分析需要加载哪些类到soot中，不构建语句
            if (isAnalyzePreLoad) {
                if (loadMap.containsKey(api)) {
                    toLoad.addAll(loadMap.get(api));
                }
                continue;
            }
            //int __android_log_print(int prio, const char *tag, const char *fmt, ...);
            if (api.equals("__android_log_print")) {
                // handle prio
                String logm = "d";
                if (call.operands.size() > 0) {
                    Value prio = call.operands.get(0).value;
                    if (prio instanceof Number) {
                        long num = ((Number) prio).val.longValue();
                        if (num > 0 && num < logPrioToMth.length) {
                            logm = logPrioToMth[Math.toIntExact(num)];
                        }
                    }
                }
                
                // 处理剩余参数
                Set<Value> args = new HashSet<>();
                // 从format开始遍历
                for (int i=2;i<call.operands.size();i++) {
                    args.add(call.operands.get(i).value);
                }
                // 参数数量大于1则使用Phi合并
                Value msg;
                if (args.size() == 0) {
                    msg = Null.instance;
                } else if (args.size() > 1) {
                    Phi msgPhi = new Phi();
                    toInsertAfter.add(msgPhi);
                    for (Value v: args) {
                        msgPhi.operands.add(new Use(msgPhi, v));
                    }
                    msg = msgPhi;
                } else {
                    msg = args.iterator().next();
                }

                // 构造调用: FindClass GetMethodID CallStaticIntMethod
                // javap -cp "C:\Users\xxx\AppData\Local\Android\Sdk\platforms\android-29\android.jar" -s -p android.util.Log
                Call callMth = buildStaticCall("android.util.Log", logm, "(Ljava/lang/String;Ljava/lang/String;)I", toInsertAfter);
                Value tag;
                if (call.operands.size() == 0) {
                    tag = Str.of("d");
                } else {
                    tag = call.operands.get(1).value;
                }
                callMth.operands.add(new Use(callMth, tag));
                callMth.operands.add(new Use(callMth, msg));

                // remove original call
                call.replaceAllUseWith(callMth);
                call.removeAllOperands();
                func.insts().remove(index);
                index -= 1;
                size -= 1;
            }// else
            // if (api.equals("open") || api.equals("fopen")) {
            //     // TODO mark input or output
            //     Call newStream = buildNewObject("java.io.FileInputStream", "(Ljava/lang/String;)V", toInsertAfter);
            //     Value fpath = call.operands.get(0).value;
            //     newStream.operands.add(new Use(newStream, fpath));

            //     // remove original call
            //     call.replaceAllUseWith(newStream);
            //     call.removeAllOperands();
            //     func.insts().remove(index);
            //     index -= 1;
            //     size -= 1;
            // }
            // if (api.equals("read") || api.equals("fread")) {
            //     Value stream = call.operands.get(0).value;
            //     Call call_ = buildCall("java.io.FileInputStream", "read", "()I", stream, toInsertAfter);
            //     // Value content = call.operands.get(1).value;
            //     // call_.operands.add(new Use(call_, fpath));
            //     // call_.operands.add(new Use(call_, content));

            //     // remove original call
            //     call.replaceAllUseWith(call_);
            //     call.removeAllOperands();
            //     func.insts().remove(index);
            //     index -= 1;
            //     size -= 1;
            // }
            // if (api.equals("write") || api.equals("fwrite")) {
            //     Value stream = call.operands.get(0).value;
            //     Call call_ = buildCall("java.io.FileOutputStream", "write", "([B)V", stream, toInsertAfter);

            //     // Call call_ = buildStaticCall("java.nio.file.Files", "write", "(Ljava/nio/file/Path;[B[Ljava/nio/file/OpenOption;)Ljava/nio/file/Path;", toInsertAfter);
            //     // Value fpath = call.operands.get(0).value;
            //     Value content = call.operands.get(1).value;
            //     // call_.operands.add(new Use(call_, fpath));
            //     call_.operands.add(new Use(call_, content));
            //     // // TODO zero sized array?
            //     // call_.operands.add(new Use(call_, Null.instance));

            //     // remove original call
            //     call.replaceAllUseWith(call_);
            //     call.removeAllOperands();
            //     func.insts().remove(index);
            //     index -= 1;
            //     size -= 1;
            // }
            // int access(const char *pathname, int mode);
            // int stat(const char *restrict pathname, struct stat *restrict statbuf);
            // https://developer.android.com/reference/java/nio/file/Files#exists(java.nio.file.Path,%20java.nio.file.LinkOption...)
            // if (api.equals("access") || api.equals("stat")) {
            //     Call call_ = buildStaticCall("java.nio.file.Files", "exist", "(Ljava/nio/file/Path;[Ljava/nio/file/LinkOption;)Z", toInsertAfter);
            //     Value fpath = call.operands.get(0).value;
            //     call_.operands.add(new Use(call_, fpath));
            //     // TODO zero sized array?
            //     call_.operands.add(new Use(call_, Null.instance));

            //     // remove original call
            //     call.replaceAllUseWith(call_);
            //     call.removeAllOperands();
            //     func.insts().remove(index);
            //     index -= 1;
            //     size -= 1;
            // }

            func.addAll(index+1, toInsertAfter);
            index += toInsertAfter.size();
            size += toInsertAfter.size();
        }
    }

    Call buildNewObject(String clz, String sig, List<Instruction> toInsertAfter) {
        Call findClass = buildFindClass(clz, toInsertAfter);
        Call getMID = buildGetMid(findClass, "<init>", sig, toInsertAfter);
        Call callMth = buildNewObject(findClass, getMID, toInsertAfter);
        return callMth;
    }

    Call buildStaticCall(String clz, String name, String sig, List<Instruction> toInsertAfter) {
        Call findClass = buildFindClass(clz, toInsertAfter);
        Call getMID = buildGetMid(findClass, name, sig, toInsertAfter);
        Call callMth = buildStaticCall(findClass, getMID, toInsertAfter);
        return callMth;
    }

    Call buildCall(String clz, String name, String sig, Value obj, List<Instruction> toInsertAfter) {
        Call findClass = buildFindClass(clz, toInsertAfter);
        Call getMID = buildGetMid(findClass, name, sig, toInsertAfter);
        Call callMth = buildCall(obj, getMID, toInsertAfter);
        return callMth;
    }

    // need to add args after this call
    Call buildStaticCall(Call clz, Call mid, List<Instruction> toInsertAfter) {
        Call callMth = new Call();
        toInsertAfter.add(callMth);
        callMth.target = "CallStaticIntMethod"; // currently ok because BodyBuilder does not use ret type here
        callMth.operands.add(new Use(callMth, Null.instance));
        callMth.operands.add(new Use(callMth, clz));
        callMth.operands.add(new Use(callMth, mid));
        return callMth;
    }

    Call buildCall(Value obj, Call mid, List<Instruction> toInsertAfter) {
        Call callMth = new Call();
        toInsertAfter.add(callMth);
        callMth.target = "CallIntMethod";
        callMth.operands.add(new Use(callMth, Null.instance));
        callMth.operands.add(new Use(callMth, obj));
        callMth.operands.add(new Use(callMth, mid));
        return callMth;
    }

    Call buildNewObject(Call clz, Call mid, List<Instruction> toInsertAfter) {
        Call callMth = new Call();
        toInsertAfter.add(callMth);
        callMth.target = "NewObject";
        callMth.operands.add(new Use(callMth, Null.instance));
        callMth.operands.add(new Use(callMth, clz));
        callMth.operands.add(new Use(callMth, mid));
        return callMth;
    }

    Call buildGetMid(Call clz, String name, String sig, List<Instruction> toInsertAfter) {
        Call getMID = new Call();
        toInsertAfter.add(getMID);
        getMID.target = "GetMethodID";
        getMID.operands.add(new Use(getMID, Null.instance));
        getMID.operands.add(new Use(getMID, clz));
        getMID.operands.add(new Use(getMID, Str.of(name)));
        getMID.operands.add(new Use(getMID, Str.of(sig)));
        return getMID;
    }

    Call buildFindClass(String string, List<Instruction> toInsertAfter) {
        Call findClass = new Call();
        toInsertAfter.add(findClass);
        findClass.target = "FindClass";
        findClass.operands.add(new Use(findClass, Null.instance));
        findClass.operands.add(new Use(findClass, Str.of(string)));
        return findClass;
    }

    public void visitCall(Call inst) {
        
    }

}
