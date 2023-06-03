package org.example.nativesummary.jimplebuilder;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.example.nativesummary.SecondRepacker.SigCollector;
import org.example.nativesummary.ir.Function;
import org.example.nativesummary.ir.Module;
import soot.AbstractJasminClass;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.dexpler.Util;

public class MethodBuilder {
    private final static Logger logger = LoggerFactory.getLogger(MethodBuilder.class);
    protected Module summary;
    public AuxMethodManager mmgr;
    public boolean debugJimple;
    public String jimpleDebugOutput = "";
    // public List<String> patchedMethods = new ArrayList<>();
    public SigCollector repackedNative = new SigCollector();

    public MethodBuilder(Module summary, AuxMethodManager mmgr) {
        this.summary = summary;
        this.mmgr = mmgr;
        // BodyBuilder.loadRequiredClasses(); // too late
    }

    public MethodBuilder(Module summary, AuxMethodManager mmgr, boolean debugJimple) {
        this(summary, mmgr);
        // BodyBuilder.loadRequiredClasses(); // too late
        this.debugJimple = debugJimple;
    }

    public void buildBody(SootMethod mth, Function summary) {
        logger.info("Build body for: " + mth.getDeclaringClass().getName() + " " + mth.getName());
        BodyBuilder b = new BodyBuilder(mth, summary, mmgr);
        if (debugJimple) {
            b.debugJimple = true;
        }
        b.build();
        if (debugJimple) {
            jimpleDebugOutput += "\n";
            jimpleDebugOutput += b.jimpleDebugOutput;
        }
    }

    public static SootMethod findMethodBySig(String sig) {
        String[] parts = sig.split("\t");
        String clazz = Util.dottedClassName(parts[0]);
        SootClass clz = Scene.v().getSootClass(clazz);
        // SootMethod mth = clz.getMethod(subsignature);
        SootMethod mth;
        try {
            mth = clz.getMethodByNameUnsafe(parts[1]);
        } catch (soot.AmbiguousMethodException e) {
            mth = null;
        }
        if (mth == null) {
            parts[2] = parts[2].replaceAll("\\s+","");
            for (SootMethod m: clz.getMethods()) {
                if (!m.getName().equals(parts[1])) {continue;}
                String msig = AbstractJasminClass.jasminDescriptorOf(m.makeRef());
                if (msig.equals(parts[2])) {
                    return m;
                }
            }
            throw new RuntimeException("Cannot find method, using wrong sematic summary json file?");
        }
        return mth;
    }

    private static SootMethod findMethod(Function func) {
        SootClass currentClass;
        // dynamic register
        if (func.clazz == null) {
            assert func.registeredBy != null;
            currentClass = TypeAnalysis.dynRegMap.get(func.registeredBy);
            if (currentClass == null) {
                logger.error("Cannot Find Target Class for dynamic registered function: "+func.name);
                return null;
            }
        } else {
            String clazz = soot.dexpler.Util.dottedClassName(func.clazz);
            currentClass = Scene.v().getSootClass(clazz);
        }

        SootMethod current;
        try {
            current = currentClass.getMethodByNameUnsafe(func.name);
        } catch (soot.AmbiguousMethodException e) {
            current = null;
        }
        if (current == null) {
            String sig = func.signature.replaceAll("\\s+","");
            for (SootMethod m: currentClass.getMethods()) {
                if (!m.getName().equals(func.name)) {continue;}
                String msig = AbstractJasminClass.jasminDescriptorOf(m.makeRef());
                if (msig.equals(sig)) {
                    current = m;
                    break;
                }
            }
            if (current == null) {
                logger.error("Can find class, but cannot find method for: {}.{}", currentClass, func.name);
            }
        } else {
            // check if method match
            if (current.getParameterCount() + 2 != func.params.size()) {
                logger.error("IR signature {} mismatch with SootMethod!!! {}.", current, func.signature, current.getSignature());
                current = null;
            }
        }
        if (current == null && func.registeredBy == null) {
            throw new RuntimeException("Cannot find method, using wrong sematic summary json file?");
        }
        return current;
    }

    /**
     * 
     * @return built methods (entry in summary).
     */
    public List<Function> patchSoot() {
        List<Function> ret = new ArrayList<>();

        // 遍历每个summary

        // JsonObject mth_log = ss.get("mth_logs").getAsJsonObject();
        // for(Map.Entry<String, JsonElement> e: mth_log.entrySet()) {
        //     SootMethod n_mth = MethodBuilder.findMethodBySig(e.getKey());
        //     buildBody(n_mth, e.getValue().getAsJsonObject());
        //     ret.add(e.getKey());
        // }

        for (Function m: summary.funcs) {
            SootMethod sootMth;
            if (org.example.nativesummary.Util.isJNIOnLoad(m)) {
                sootMth = mmgr.jniOnLoad();
            } else {
                sootMth = MethodBuilder.findMethod(m);
            }
            if (sootMth == null) {
                logger.error("cannot find sootmethod: "+m.clazz+"."+m.name);
                continue;
            }

            repackedNative.addMethod(sootMth);
            buildBody(sootMth, m);
            ret.add(m);
        }

        List<SootMethod> left = new ArrayList<>();
        for (SootClass clz : Scene.v().getClasses()) {
            if (!clz.isApplicationClass()) {
                continue;
            }
            if (clz.getName().contains(AuxMethodManager.mainClassName)) {
                continue;
            }
            for (SootMethod method: clz.getMethods()) {
                if (!method.isNative()) {
                    continue;
                }
                left.add(method);
            }
        }
        logger.debug("Unhandled native methods: " + left.toString());
        // APKRepacker.outputAPK(true);
        return ret;
    }
}
