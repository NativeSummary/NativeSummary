package org.example.nativesummary.mapping;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import org.example.nativesummary.ir.utils.Type;
import org.example.nativesummary.ir.value.Param;
import org.example.nativesummary.util.MyGlobalState;
import org.example.nativesummary.util.Utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

// example json file:
/*{
  "Java_org_arguslab_native_1heap_1modify_MainActivity_heapModify": {
    "className": "Lorg/arguslab/native_heap_modify/MainActivity;",
    "name": "heapModify",
    "descriptor": "(Landroid/content/Context; Lorg/arguslab/native_heap_modify/Data;)V",
    "argumentTypes": [
      "JNIEnv *",
      "jclass",
      "jobject",
      "jobject"
    ],
    "returnType": "void"
  }
}*/

public class JSONAnalyzer {

    FlatProgramAPI flatapi;
    GhidraScript script;
    DataTypeManager manager;

    public JSONAnalyzer(FlatProgramAPI flatapi, GhidraScript script, DataTypeManager manager) {
        this.flatapi = flatapi;
        this.script = script;
        this.manager = manager;
    }

    public ArrayList<Map.Entry<Function, org.example.nativesummary.ir.Function>> run(JsonObject jsonObject) throws InvalidInputException, DuplicateNameException {
        ArrayList<Map.Entry<Function, org.example.nativesummary.ir.Function>> ret = new ArrayList<>();

        // handle JNI_OnLoad, ensure it's the first elem.
        List<Function> onLoadList = flatapi.getGlobalFunctions("JNI_OnLoad");
        if (onLoadList.size() > 1) {
            script.println("[ERROR] cannot find unique JNI_OnLoad");
        }
        if (onLoadList.size() != 0) {
            Function onLoad = onLoadList.get(0);
            MyGlobalState.onLoad = onLoad;
            ret.add(handleJNIOnLoad(onLoad));
        }

        for (Map.Entry<String, JsonElement> e : jsonObject.entrySet()) {
            List<Function> flist = flatapi.getGlobalFunctions(e.getKey());
            if (flist.size() != 1) {
                script.println("[ERROR] cannot find unique function "+e.getKey());
                if (flist.size() == 0) {
                    script.println("[ERROR] skip function "+e.getKey());
                    continue;
                }
            }
            Function f = flist.get(0);

            JsonObject obj = e.getValue().getAsJsonObject();
            String className = obj.getAsJsonPrimitive("className").getAsString();
            String name = obj.getAsJsonPrimitive("name").getAsString();
            String descriptor = obj.getAsJsonPrimitive("descriptor").getAsString();
            String returnType = obj.getAsJsonPrimitive("returnType").getAsString();
            JsonArray params = obj.getAsJsonArray("argumentTypes");
            org.example.nativesummary.ir.Function irFunc = new org.example.nativesummary.ir.Function();
            irFunc.clazz = className;
            irFunc.name = name;
            irFunc.signature = descriptor;
            // add params
            int i=0;
            for (JsonElement para: params) {
                String paramType = para.getAsString();
                String pname = getNameByType(paramType, i);
                if (pname == null) { pname = "a"+String.valueOf(i); }
                irFunc.params.add(new Param(pname, new Type(null).setTypeDef(paramType)));
                i+=1;
            }
            // add ret type
            irFunc.returnType = new Type(null).setTypeDef(returnType);
            ret.add(Map.entry(f, irFunc));
            // Set argument types and return types
            if (f.getParameterCount() == 0 || (!Utils.isParameterJNIEnvPtr(f.getParameter(0)))) {
                setFunctionType(f, obj.getAsJsonArray("argumentTypes"), obj.getAsJsonPrimitive("returnType").getAsString());
            } else {
                script.println("Warning: "+f.getName()+" param type already set?");
            }
        }
        return ret;
    }

    public Map.Entry<Function, org.example.nativesummary.ir.Function> handleJNIOnLoad(Function f) throws InvalidInputException, DuplicateNameException {
        org.example.nativesummary.ir.Function irFunc = new org.example.nativesummary.ir.Function();
        irFunc.clazz = "@";
        irFunc.name = "JNI_OnLoad";
        irFunc.params.add(new Param("vm", new Type(null).setTypeDef("JavaVM *")));
        irFunc.params.add(new Param("reserved", new Type(null).setTypeDef("void *")));
        irFunc.returnType = new Type(Type.BaseType.INT).setTypeDef("jint");
        setJNIOnLoadType(f);
        return Map.entry(f, irFunc);
    }

    public void setJNIOnLoadType(Function f) throws InvalidInputException, DuplicateNameException {
        Parameter[] params = new Parameter[2];
        params[0] = new ParameterImpl("vm", this.manager.getDataType("/jni_all.h/" + "JavaVM *"), script.getCurrentProgram(),
                SourceType.USER_DEFINED);
        params[1] = new ParameterImpl("reserved", this.manager.getDataType("/void *"), script.getCurrentProgram(),
                SourceType.USER_DEFINED);
        Parameter returnType = new ReturnParameterImpl(this.manager.getDataType("/jni_all.h/" + "jint"),
                script.getCurrentProgram());
        f.updateFunction(null, returnType, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
                SourceType.USER_DEFINED, params);
    }

    public void setFunctionType(Function f, JsonArray argumentTypes, String returnTypeStr) throws InvalidInputException, DuplicateNameException {
        List<String> conv = new ArrayList<>();
        for (JsonElement e: argumentTypes) {
            conv.add(e.getAsString());
        }
        setFunctionType(f, conv, returnTypeStr);
    }

    public void setFunctionType(Function f, List<String> argumentTypes, String returnTypeStr) throws InvalidInputException, DuplicateNameException {
        Parameter[] params = new Parameter[argumentTypes.size()];
        int i = 0;
        for(String t : argumentTypes) {
            String name = getNameByType(t, i);
            if (name == null) { name = "a"+String.valueOf(i); }
            params[i] = new ParameterImpl(name, this.manager.getDataType("/jni_all.h/" + t), script.getCurrentProgram(),
                    SourceType.USER_DEFINED);
            i+=1;
        }
        Parameter returnType;
        if (returnTypeStr.equals("void")) {
            returnType = new ReturnParameterImpl(VoidDataType.dataType, script.getCurrentProgram());
        } else {
            returnType = new ReturnParameterImpl(this.manager.getDataType("/jni_all.h/" + returnTypeStr),
                    script.getCurrentProgram());
        }
        f.updateFunction(null, returnType, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS, true,
                SourceType.USER_DEFINED, params);
    }

    public static String getNameByType(String t, int i) {
        if (i == 0 && t.equals("JNIEnv *")) {
            return "env";
        } else if (i == 1 && t.equals("jobject")) {
            return "thiz";
        } else if (i == 1 && t.equals("jclass")) {
            return "clazz";
        }
        return null;
    }
}
