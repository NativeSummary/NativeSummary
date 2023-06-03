package org.example.nativesummary.ir;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Module implements Serializable {
    public String apk_name;
    public String so_name;
    public int defaultPointSize;
    public List<Function> funcs = new ArrayList<>();

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (apk_name != null) {
            sb.append("source_filename = \"").append(apk_name).append("\"\n");
        }
        if (so_name != null) {
            sb.append("native_object_filename = \"").append(so_name).append("\"\n");
        }
        if (defaultPointSize != 0) {
            sb.append("pointer_size = \"").append(defaultPointSize).append("\"\n");
        }
        sb.append("\n");
        for (Function f: funcs) {
            sb.append(f.toString());
            sb.append("\n\n");
        }
        return sb.toString();
    }

    /**
     * Function如果重了，直接把指令合到一起。
     * 目前Function和Module之间还不耦合，所以直接添加即可。
     * @param ms
     * @return
     */
    public static Module merge(List<Module> ms) {
        if (ms.size() == 0) return null;
        Module ret = ms.get(0);
        Map<String, Function> dup = new HashMap<>();
        for (Module m: ms) {
            //  { continue; }
            for(Function f: m.funcs) {
                Function prev = dup.putIfAbsent(f.clazz+"\t"+f.name+"\t"+f.signature, f);
                if (prev != null) {
                    if (!prev.name.equals("JNI_OnLoad")) {
                        System.out.println(String.format("Warning: duplicate function: %s %s %s", f.clazz, f.name, f.signature));
                    }
                    // remove ownership
                    for (Instruction inst: f.insts()) {
                        if (inst.parent == f) {
                            inst.parent = null;
                        }
                    }
                    // // fix param
                    // assert prev.params.size() == f.params.size();
                    for (int i=0;i<f.params.size();i++) {
                        f.params.get(i).replaceAllUseWith(prev.params.get(i));
                    }

                    prev.addAll(f.insts());
                } else {
                    if (m != ret) {
                        ret.funcs.add(f);
                    }
                }
            }
        }
        return ret;
    }
}
