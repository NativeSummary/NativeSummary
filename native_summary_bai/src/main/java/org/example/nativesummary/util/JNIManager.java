package org.example.nativesummary.util;

import com.bai.env.*;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.Heap;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import org.example.nativesummary.env.TaintMap;

import java.util.*;

public class JNIManager {

    public void reset() {
        counter = 0;
        idMap.clear();
        callSiteMap.clear();
        callSites.clear();
        heapMap.clear();
    }

    public JNIManager() {
    }

    // copy constructor
    public JNIManager(JNIManager instance) {
        this();
        if (instance != null) {
            counter = instance.counter;
            idMap.putAll(instance.idMap);
            callSiteMap.putAll(instance.callSiteMap);
//            callSites.putAll(instance.callSites);
            heapMap.putAll(instance.heapMap);
        }
    }

    // ------JNIEnv block addr calc---------

    public static long[] JNIEnvAddr = {0xE000_0000L, 0x7fff_0000_0000L};

    // ---------------

    long counter = 0;

    static final long stride = 0x10;

    // ensure highest 4 bit is 0x8, Or real value before return.
    static long mask = 0; // 0x80 00 00 00 [...]
    public static long getMask() {
        if (mask != 0) return mask;
        mask = 0x8L << (GlobalState.currentProgram.getDefaultPointerSize() * 8 - 4);
        return mask;
    }

    public static boolean highestBitsMatch(long value) {
        long mask = 0xFL << (GlobalState.currentProgram.getDefaultPointerSize() * 8 - 4);
        return getMask() == (value & mask);
    }

    private long alloc() {
        long ret = counter;
        counter += stride;
        return ret | getMask();
    }

    // -------------------

    // TODO replace with bidirectional map ??
    final Map<Long, JNIValue> idMap = new HashMap<>();

    // deduplicate cache map
    final Map<JNIValue, Long> callSiteMap = new HashMap<>();

    // keep sequence for export without control flow
    public final LinkedHashMap<JNIValue, Context> callSites = new LinkedHashMap<>();

    // Heap region map
    public final Map<Heap, JNIValue> heapMap = new HashMap<>();

    public void registerCall(JNIValue cs, Context ctx) {
        callSites.put(cs, ctx);
    }

    public long getId(JNIValue cs) {
        if (callSiteMap.containsKey(cs)) {
            return callSiteMap.get(cs);
        }
        long newval = alloc();
        callSiteMap.put(cs, newval);
        idMap.put(newval, cs);
        return newval;
    }
    public JNIValue getValue(long id) {
        return idMap.get(id);
    }

    /**
     * 该函数在每次分析前被 `com.bai.solver.InterSolver#run()` 调用一次
     *
     * @param cur         当前的入口函数
     * @param e           准备使用的初始化环境
     * @param mainContext
     */
    public void setupArg(Function cur, AbsEnv e, Context mainContext) {
        // 遍历每个参数
//        for (Parameter p: cur.getParameters()) {
        for (int i=0;i<cur.getParameters().length;i++) {
            Parameter p = cur.getParameters()[i];
            if (p.getName().contains("reserve")) { // skip JNI_OnLoad 2nd arg
                continue;
            }
            List<ALoc> al = ExternalFunctionBase.getParamALocs(cur, i, e);
            if (al.size() > 1) {
                // TODO warn about it
                Logging.warn("setupArg: multiple ALocs found for param !!!");
            }
            if (al.size() == 0) {
                Logging.error("Cannot find ALocs for param!!! " +
                        String.format("(Func %s, Param %s %s)", cur.toString(), p.getDataType().getName(), p.getName()));
            }
            for (ALoc al_: al) {
                JNIValue jniVal = new JNIValue(i);
                KSet val =  getRetFromType(p.getDataType(), null, jniVal, al_.getLen()*8, null, mainContext, e);
                if (val != null) {
                    e.set(al_, val, false);
                }
            }
        }
    }

    // 传函数和context进来是为了创建Heap region。
    public static KSet getRetFromType(DataType ty, Address callSite, JNIValue jcs, int bits, Function cur, Context context, AbsEnv env) {
        long newTaint;
        KSet retKSet;
        switch (TypeCategory.byName(ty)) {
            case JNIENV:
                assert bits == (MyGlobalState.defaultPointerSize*8);
                retKSet = new KSet(bits);
                retKSet = retKSet.insert(new AbsVal(EnvSetup.getJNIEnv()));
                return retKSet;
            case JAVA_VM:
                assert bits == (MyGlobalState.defaultPointerSize*8);
                retKSet = new KSet(bits);
                retKSet = retKSet.insert(new AbsVal(EnvSetup.getJavaVM()));
                return retKSet;
            case JNI_VALUE:
                long retval = MyGlobalState.jnim.getId(jcs);
                retKSet = new KSet(bits);
                retKSet = retKSet.insert(new AbsVal(retval));
                return retKSet;
            case NUMBER:
                newTaint = TaintMap.getTaints(jcs);
                if (TaintMap.isNewTaint(newTaint)) {
                    Logging.info("Allocating taint for "+(cur==null?"Param":cur.getName())+" "+ty.toString() + " " + context.toString());
                }
                return KSet.getTop(newTaint);
            case BUFFER:
                // New Heap
                KSet resKSet = new KSet(bits);
                Heap allocChunk = Heap.getHeap(callSite, context, Heap.DEFAULT_SIZE, true);
                resKSet = resKSet.insert(AbsVal.getPtr(allocChunk));
                Logging.info("Returning heap region for "+(cur==null?"Param":cur.getName())+" "+ty.toString() + " " + context.toString());
                MyGlobalState.jnim.heapMap.put(allocChunk, jcs);

                // set a tainted top at the beginning
                newTaint = TaintMap.getTaints(jcs);
//                Logging.info("Allocating taint for "+(cur==null?"Param":cur.getName())+" "+ty.toString() + " " + context.toString());
                KSet taintedTop = KSet.getTop(newTaint);
                env.set(ALoc.getALoc(allocChunk, allocChunk.getBase(),  1), taintedTop, false);

                return resKSet;
            default:
            case UNKNOWN:
                if (!ty.getName().equals("undefined")) {
                    Logging.error("Unknown JNI return type: "+ty.getName());
                }
                return null;
        }
    }

}
