package org.example.nativesummary.checkers;

import com.bai.checkers.CheckerBase;
import com.bai.env.*;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import org.example.nativesummary.ir.Module;
import org.example.nativesummary.ir.NumValueNamer;
import org.example.nativesummary.env.TaintMap;
import org.example.nativesummary.ir.inst.Call;
import org.example.nativesummary.ir.inst.Phi;
import org.example.nativesummary.ir.inst.Ret;
import org.example.nativesummary.ir.utils.Type;
import org.example.nativesummary.ir.utils.Use;
import org.example.nativesummary.ir.utils.Value;
import org.example.nativesummary.ir.value.*;
import org.example.nativesummary.ir.value.Number;
import org.example.nativesummary.mapping.JSONAnalyzer;
import org.example.nativesummary.util.*;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Triple;
import org.example.nativesummary.ir.value.*;
import org.example.nativesummary.util.*;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class SummaryExporter extends CheckerBase {
    Module mod = new Module();
    org.example.nativesummary.ir.Function current = new org.example.nativesummary.ir.Function();

    Map<JNIValue, Value> onLoadJvMap;
    Map<JNIValue, Value> jvMap;
    public static final int ADDITIONAL_ARG_COUNT = 5;

    public Set<Triple<String, String, Function>> dynRegSet = new HashSet<>();
    public List<String> dynRegName = new ArrayList<>();
    public List<String> dynRegSig = new ArrayList<>();
    public List<Function> dynRegFunc = new ArrayList<>();
    public List<Call> dynRegCall = new ArrayList<>();

    public SummaryExporter() {
        super(null, null);
    }

    // TODO APK name
    public void export(OutputStream w, FileWriter irFw, String apkname) {
        mod.apk_name = apkname;
        try {
            ObjectOutputStream out = new ObjectOutputStream(w);
            out.writeObject(mod);
            out.close();
            irFw.write(mod.toString());
        } catch (IOException i) {
            i.printStackTrace();
        }
    }

    public void onFinishFunc(boolean isOnLoad) {
//        String key = entry.getName();
        new NumValueNamer().visitFunc(current);
        mod.funcs.add(current);
        // String a = current.toString(); // TO DEBUG
        current = null;
        if (isOnLoad) {
            onLoadJvMap = jvMap;
        }
        jvMap = null;
//        current = new org.example.nativesummary.ir.Function();
//        for ()
    }

    public List<org.example.nativesummary.ir.Instruction> decodeRetVal(Ret r, Function jnifunc, AbsEnv env) {
        List<org.example.nativesummary.ir.Instruction> ret = new ArrayList<>();
        ALoc aloc = ExternalFunctionBase.getReturnALoc(jnifunc, false);
        KSet kSet = env.get(aloc);
        if (kSet == null) {
            Logging.warn("Cannot find return value for "+jnifunc.getName());
            return ret;
        }
        // TODO c str as return val?
        List<Value> v = decodeKSet(jnifunc.getReturnType(), kSet, env,
                String.format("Func %s return value", jnifunc.getName()));
        r.operands.add(new Use(r, phiMerge(v, ret)));
        ret.add(r);
        return ret;
    }

    // 负责处理一个JV，返回生成的指令，因为有Phi所以可能对应多条指令。
    public List<org.example.nativesummary.ir.Instruction> decodeParams(Function f, Call call, Function jniapi, AbsEnv env) {
        List<org.example.nativesummary.ir.Instruction> ret = new ArrayList<>();
        Parameter[] params = jniapi.getParameters();
        int paramSize = jniapi.getParameters().length;
        for (int index=0;index<paramSize;index++) {
            Parameter p = jniapi.getParameter(index);
            String dtName = p.getDataType().getName();
            if (dtName.equals("JNIEnv *") || dtName.equals("JavaVM *")) {
                call.operands.add(new Use(call, Null.instance));
                continue;
            }

//            ALoc regaloc = ALoc.getALoc(Reg.getInstance(), p.getRegister().getOffset(), p.getRegister().getNumBytes());
            List<ALoc> alocs = getParamALocs(jniapi, index, env);

            if (index == (paramSize-1) && isVaListAPI(call.target)) {
                // handle va_list.
                Logging.warn(String.format("Resolving %s additional arguments for %s at %s", ADDITIONAL_ARG_COUNT, jniapi.getName(), Utils.describeAddr(call.callsite)));
                Utils.prependToComments(call, "va_list ");

                // warn if cannot resolve accurately
                boolean isExact = Utils.isResolutionExact(alocs, env);
                if (!isExact) {
                    Logging.warn(String.format("Cannot resolve va_list exactly for %s at (%s)", jniapi.getName(), Utils.describeAddr(call.callsite)));
                }
                for (ALoc aloc: alocs) {
                    // TODO a list of list for each param?
                    KSet ks = env.get(aloc);
                    if (ks.isTop()) {  break; }
                    for (AbsVal val: ks) {
                        if (val.getRegion().isLocal()) {
                            resolveVaList(call, val, env, ret);
                        }
                    }
                }
                call.target = toNonVaListJNI(call.target);
                continue;
            }

            // decode to v, and merge them.
            List<Value> v = new ArrayList<>();
            for (ALoc aloc: alocs) {
                KSet ks = env.get(aloc);

                // register natives.
                if (p.getDataType().getName().equals("JNINativeMethod *")) {
                    for (AbsVal val: ks) {
                        if (val.getRegion().isGlobal()) {
                            long ptr;
                            ptr = val.getValue();
                            Logging.info("JNINativeMethod detected at 0x"+Long.toHexString(ptr));
                            v.add(Str.of(Long.toHexString(ptr)));
                        } else {
                            Logging.warn("JNINativeMethod* not in data section?");
                            v.add(Str.of(val.toString()));
                        }
                        resolveNativeMethodsAt(val, env, call);
                    }
                    Logging.info("RegisterNatives: ===== summary ===== .");
                    for (int i=0;i<dynRegName.size();i++) {
                        Logging.info(String.format("[%s] [%s] at [%s]", dynRegName.get(i), dynRegSig.get(i), dynRegFunc.get(i)));
                    }
                } else {
                    v.addAll(decodeKSet(p.getDataType(), ks, env,
                            String.format("Func %s Param %s %s",jniapi.getName(), p.getDataType().toString(), p.getName())));
                }
            }
            call.operands.add(new Use(call, phiMerge(v, ret)));
        }
        // handle varargs
        if (jniapi.hasVarArgs()) {
            // get additional vararg count by decompiler result.
            // 目前还不能很好利用反编译结果，因为内部有很多的unique空间或者奇怪的复用寄存器。
            // 因此仅仅获取参数个数。
            int totalArgCount = 8;
            HighFunction highFunc = null;
            if (f != null) {
                highFunc = MyGlobalState.decom.decompileFunction(f);
            }
            if (highFunc == null) {
                Logging.error("Decompilation for vararg failed.");
            } else {
                Iterator<PcodeOpAST> ops = highFunc.getPcodeOps(GlobalState.flatAPI.toAddr(call.callsite));
                for (Iterator<PcodeOpAST> it = ops; it.hasNext(); ) {
                    PcodeOpAST op = it.next();
                    int opcode = op.getOpcode();
                    // 跳过非call的指令
                    if (opcode <  PcodeOp.CALL || opcode > PcodeOp.CALLOTHER) {
                        continue;
                    }
//                    Logging.info(String.format("vararg call: \n  %s\ndecomp pcode: %s", call.toString(),
//                            MyGlobalState.pp.printOneWithAddr(op)));
                    Varnode[] ins = op.getInputs();
                    // 跳过那个call pcode指令的目标地址参数
                    totalArgCount = ins.length - 1;
                    Logging.info(String.format("Vararg call arg count at 0x%s: total %s, additional %s.",
                            Long.toHexString(call.callsite),
                            totalArgCount,
                            totalArgCount - paramSize));
                }
            }
            // 部分函数特殊处理
            if (jniapi.getName().equals("__android_log_print")) {
                totalArgCount = Math.max(4, totalArgCount);
            }
            // 通过CallingConvention获取参数的地址。
            int startInd = paramSize;
            PrototypeModel cc = jniapi.getCallingConvention();
            if (cc == null) {
                cc = GlobalState.currentProgram.getCompilerSpec().getDefaultCallingConvention();
            }
            for(int i=startInd;i<totalArgCount;i++) {
                VariableStorage vs = cc.getArgLocation(i, params, null, GlobalState.currentProgram);
                assert vs.getVarnodeCount() == 1;
                Varnode node = vs.getLastVarnode();
                KSet ks = null;
                if (node != null) {
                    ALoc loc = null;
                    if (node.getAddress().isStackAddress()) {
                        AbsVal sp = Utils.getExactSpVal(env);
                        if (sp != null) {
                            loc = ALoc.getALoc(sp.getRegion(), sp.getValue()+node.getOffset(), MyGlobalState.defaultPointerSize);
                        } else {
                            Logging.warn(String.format("vararg no exact sp for %s at (%s)", jniapi.getName(), Utils.describeAddr(call.callsite)));
                        }
                    } else {
                        if (node.getSize() < MyGlobalState.defaultPointerSize) {
                            node = new Varnode(node.getAddress(), MyGlobalState.defaultPointerSize);
                        }
                        loc = ALoc.getALoc(node);

                    }

                    if (loc != null) {
                        ks = env.get(loc);
                    }
                }
                List<Value> v = decodeKSet(null, ks, env,
                        String.format("Func %s additional Param at: %s",jniapi.getName(), MyGlobalState.pp.printVarnode(node)));
                call.operands.add(new Use(call, phiMerge(v, ret)));
            }
        }
        ret.add(call);
        return ret;
    }

    private void resolveNativeMethodsAt(AbsVal ptr, AbsEnv env, Call dynreg) {
        boolean failed = false;
        long index = 0;
        int ptrSize = MyGlobalState.defaultPointerSize;
        int structSize = ptrSize*3;
        while(!failed) {
            long base = ptr.getValue() + index * structSize;
            ALoc pname = ALoc.getALoc(ptr.getRegion(), base, ptrSize);
            ALoc psig = ALoc.getALoc(ptr.getRegion(), base + ptrSize, ptrSize);
            ALoc fptr = ALoc.getALoc(ptr.getRegion(), base + ptrSize + ptrSize, ptrSize);
            KSet kname = env.get(pname);
            KSet ksig = env.get(psig);
            KSet kfunc = env.get(fptr);
            if (kname.isTop() || ksig.isTop() || kfunc.isTop() || kfunc.getInnerSet().size() != 1) {
                failed = true;
                break;
            }
            if (kname.getInnerSet().size() != 1 || ksig.getInnerSet().size() != 1) {
                Logging.warn("RegisterNatives: string pointer inprecise.");
                failed = true;
                break;
            }
            // TODO
            AbsVal name = kname.iterator().next();
            AbsVal sig = ksig.iterator().next();
            String sname = decodeStr(env, name);
            String ssig = decodeStr(env, sig);
            if (sname == null || ssig == null || sname.length() == 0 || ssig.length() == 0) {
                failed = true;
                break;
            }
            AbsVal func = env.get(fptr).iterator().next();
            if (!func.getRegion().isGlobal()) {
                Logging.error(String.format("RegisterNatives: func val not in Global. (%s %s)", sname, ssig));
                continue;
            }
            long target = func.getValue();
            // arm thumb mode.
            boolean isThumb = false;
            boolean isArm = GlobalState.arch.isArmSeries();
            if (isArm) {
                if (target % 2 == 1) { target = target - 1; isThumb = true; }
            }
            Address addr = GlobalState.flatAPI.toAddr(target);
            Function toRegister = GlobalState.flatAPI.getFunctionAt(addr);
            if (toRegister == null) {
                Logging.warn(String.format("RegisterNatives:No Func at 0x%s for (%s %s)", Long.toHexString(func.getValue()), sname, ssig));
                toRegister = GlobalState.flatAPI.createFunction(addr, null);
                if (toRegister == null) {
                    Logging.warn("RegisterNatives:func creation failed.");
                    failed = true;
                    index += 1;
                    continue;
                } else {
                    if (isArm && isThumb) {
                        // assume TMode = 1
                        // set register
                        ProgramContext pctx = GlobalState.currentProgram.getProgramContext();
                        Register tMode = pctx.getRegister("TMode");
                        RegisterValue regval = pctx.getRegisterValue(tMode, addr);
                        boolean isThumb_ = regval.getUnsignedValue().testBit(0);
                        if (!isThumb_) {
                            Logging.info("RegisterNatives:Set Thumb (TMode=1) for 0x"+Long.toHexString(target));
                            try {
                                pctx.setValue(tMode, addr, addr, BigInteger.ONE);
                            } catch (ContextChangeException e) {
                                // an illegal change to program context has been attempted
                                Logging.error("RegisterNatives: set TMode failed: \n" + Context.getStackTrace(e));
//                                throw new RuntimeException(e);
                            }
                        }
                    }
                }
            }
            Triple<String, String, Function> ele = new ImmutableTriple<>(sname, ssig, toRegister);
            if (!dynRegSet.contains(ele)) {
                dynRegSet.add(ele);
                dynRegName.add(sname);
                dynRegSig.add(ssig);
                dynRegFunc.add(toRegister);
                dynRegCall.add(dynreg);
            }
            index += 1;
        }
        // summarize and log
        Logging.info(String.format("RegisterNatives: successfully registered %s func.", index)); // TODO fix by sub
    }

    private String toNonVaListJNI(String target) {
        if (target.endsWith("MethodV")){
            return target.substring(0, target.length()-1);
        } else if (target.equals("NewObjectV")) {
            return target.substring(0, target.length()-1);
        }
        return target;
    }

    private void resolveVaList(Call call, AbsVal val, AbsEnv env, List<org.example.nativesummary.ir.Instruction> ret) {
        int paramSize = MyGlobalState.defaultPointerSize; // TODO
        long startOffset = val.getValue();
        for (int i=0;i<ADDITIONAL_ARG_COUNT;i++) {
            long offset = startOffset + (long) paramSize * i;
            ALoc loc = ALoc.getALoc(val.getRegion(), offset, paramSize);
            KSet ks = env.get(loc);
            List<Value> v = decodeKSet(null, ks, env,
                    String.format("Func %s va_list Param %s",call.target, String.valueOf(i)));
            call.operands.add(new Use(call, phiMerge(v, ret)));
        }
    }

    private boolean isVaListAPI(String target) {
        if (target == null) {
            return false;
        }
        return target.endsWith("MethodV") || target.equals("NewObjectV");
    }

    // merge value in vs, and add new Phi inst to insts.
    public Value phiMerge(List<Value> vs, List<org.example.nativesummary.ir.Instruction> insts) {
        if (vs.size() == 0) {
            return new Top();
        }
        if (vs.size() == 1) {
            return vs.get(0);
        }
        Phi p = new Phi();
        for (Value v: vs) {
            p.operands.add(new Use(p, v));
        }
        insts.add(p);
        return p;
    }

    /**
     * TODO 考虑非global的值（指针）的解析
     * @param dt datatype, 但是当解析vararg额外的参数的时候会是null
     * @param ks
     * @param env 为了解码str
     * @param ident
     * @return
     */
    public List<Value> decodeKSet(DataType dt, KSet ks, AbsEnv env, String ident) {
        // 处理taint
        List<Value> ret = new ArrayList<>();
        if (ks == null) {
            return ret;
        }
        long taints = ks.getTaints();
        List<JNIValue> taintSourceList = TaintMap.getTaintSourceList(taints);
        for (JNIValue jv : taintSourceList) {
            ret.add(decodeJV(jv));
        }
        if (ks.isTop()) {
            return ret;
        }
        for (AbsVal targetVal : ks) {
            // 处理Heap region
            RegionBase region = targetVal.getRegion();
            if (region.isHeap() && MyGlobalState.jnim.heapMap.containsKey(region)) {
                ret.add(decodeJV(MyGlobalState.jnim.heapMap.get(region)));
                // check Ffirst taint in heap
                KSet top = env.get(ALoc.getALoc(region, region.getBase(), 1));
                taints = top.getTaints();
                taintSourceList = TaintMap.getTaintSourceList(taints);
                for (JNIValue jv : taintSourceList) {
                    ret.add(decodeJV(jv));
                }
                continue;
            }

            if (!region.isGlobal() || targetVal.isBigVal()) {
                Logging.warn("Cannot decode Absval: "+targetVal.toString()); // + " at: " +  TODO
                ret.add(new Top());
                continue;
            }
            // 判断是否是不透明的JNI值
            long id = targetVal.getValue();
            if (id == EnvSetup.getJNIEnv()) {
                ret.add(current.params.get(0));
                continue;
            }
            // TODO handle region
            // highest byte
            if (JNIManager.highestBitsMatch(id)) { // special value
                JNIValue v = MyGlobalState.jnim.getValue(id);
                if (v == null) {
                    Logging.warn("Cannot find JNIValue?: "+Long.toHexString(id));
                } else {
                    ret.add(decodeJV(v));
                    continue;
                }
            }
            // according to type
            long addr = id;
            String dtName;
            TypeCategory dtTc;
            if (dt != null) {
                dtName = dt.getName();
                dtTc = TypeCategory.byName(dt);
            } else if (isPossibleStr(targetVal)) { // in rodata region
                dtName = "const char*";
                dtTc = null;
            } else {
                // TODO
                dtName= "int";
                dtTc = TypeCategory.NUMBER;
            }
            switch (dtName.replaceAll("\\s+","")) {
                case "constchar*":
                case "char*":
                    if (addr == 0) { // handle null
                        ret.add(new Null());
                        continue;
                    }
                    String s = decodeStr(env, targetVal);
                    ret.add(Str.of(s));
                    continue;
                case "jboolean*":
                    if (addr != 0) {
                        Logging.error(ident + " is `jboolean*` but not null.");
                    }
                    ret.add(Number.ofLong(addr));
                    continue;
                default:
                    break;
            }
            // handel number and warnings
            switch (dtTc) {
                case JNIENV:
                    throw new RuntimeException();
                case JNI_VALUE:
                    Logging.error("JNI Value type("+dt.toString()+") decode failed for "+ident);
                    break;
                case BUFFER:
                    Logging.warn(String.format("Cannot decode buffer(%s): 0x%s", dt != null ? dt.toString(): dtName, Long.toHexString(addr)));
                    break;
                case NUMBER:
                    ret.add(Number.ofLong(addr));
                    break;
                default:
                case UNKNOWN:
                    if (!dtName.equals("undefined")) {
                        Logging.error("Unknown datatype "+dtName);
                    }
                    break;
            }
        }
        return ret;
    }

    boolean isPossibleStr(AbsVal val) {
        if (!val.getRegion().isGlobal()) {
            return false;
        }
        long addr_ = val.getValue();
        Address addr = GlobalState.flatAPI.toAddr(addr_);
        MemoryBlock mb = GlobalState.currentProgram.getMemory().getBlock(addr);
        if (mb == null) {
            return false;
        }
        return !mb.isWrite();
    }

    // TODO make it more robust
    private String decodeStr(AbsEnv env, AbsVal val) {
        if (!val.getRegion().isGlobal()) {
            Logging.warn("Cannot decode non global str ptr.");
            return null;
        }
        long addr = val.getValue();
        if (addr < 0x100) {
            return null;
        }
        byte[] bs = null;
        try {
            bs = Utils.getStringFromMemory(GlobalState.flatAPI.toAddr(addr));
        } catch (MemoryAccessException e) {
            Logging.error("JNI char* decode failed! 0x"+Long.toHexString(addr));
            return null;
        }
        if (bs == null) {
            return null;
        }
        String s;
        try {
            Charset csets = StandardCharsets.UTF_8;
            CharsetDecoder cd = csets.newDecoder();
            CharBuffer r = cd.decode(ByteBuffer.wrap(bs));
            s = r.toString();
        } catch (CharacterCodingException e) {
            s = Arrays.toString(bs);
        }
        return s;
    }

    private Value decodeJV(JNIValue v) {
        if (v.isParamValue()) {
            return current.params.get(v.getParamInd());
        } else if (jvMap.containsKey(v)) {
            return jvMap.get(v);
        // 可能读取了JNI_OnLoad保存的值。
        } else if (onLoadJvMap != null && onLoadJvMap.containsKey(v)) {
            return onLoadJvMap.get(v);
        } else {
            Logging.warn("Reference to a future return value!!");
            Call c = new Call();
            jvMap.put(v, c);
            return c;
        }
    }

    public static String encodeCallsite(long[] cs, long callsite) {
        StringBuilder b = new StringBuilder();
        for(long c: cs) {
            b.append("0x").append(Long.toHexString(c));
            b.append('\t');
        }
        b.append(Long.toHexString(callsite));
        return b.toString();
    }

    public static String encodeProperty(JNIValue v, Function f) {
        return encodeCallsite(v.callstring, v.callsite) + "\t" + v.apiName;
    }

    public static String encodeRetVal() {
        return "RETURN_VALUE";
    }

    @Override
    public boolean check() {
        // TODO handle tail jump.
        for(Map.Entry<JNIValue, Context> ent: MyGlobalState.jnim.callSites.entrySet()) {
            JNIValue v = ent.getKey();
            Context context = ent.getValue();
            long callsite = v.callsite;
            Function f = GlobalState.flatAPI.getFunctionContaining(GlobalState.flatAPI.toAddr(callsite));
            Function jniapi = Utils.getExternalFunc(v.apiName);
            AbsEnv absEnv = context.getAbsEnvIn().get(GlobalState.flatAPI.toAddr(callsite));
            if (absEnv == null) {
                Logging.error("Cannot find absEnv for 0x"+Long.toHexString(callsite));
                continue;
            }
            // decode params
            assert jniapi != null;
//                encodeProperty(v, f)
            Call c = JV2Call(v);
            jvMap.put(v, c);
            current.addAll(decodeParams(f, c, jniapi, absEnv));
        }
        // decode ret val
        Function cur = MyGlobalState.currentJNI;
        if (!(cur.getReturnType() instanceof VoidDataType)) {
            boolean found = false;
            for (Context context : Context.getContext(cur)) {
                if (!Utils.isAllZero(context.getCallString())) {
                    continue;
                }
                found = true;
                // TODO get exit AbsEnv
                Ret r = new Ret();
                current.addAll(decodeRetVal(r, cur, new AbsEnv(context.getExitValue())));
            }
            if (!found) {
                Logging.error("Cannot find context for main func? "+cur.getName());
            }
        }

        return false;
    }

    public Call JV2Call(JNIValue jv) {
        assert ! jv.isParamValue();
        // in case forward reference
        Call v;

        if (jvMap.containsKey(jv)) { // && (!onLoadJvMap.containsValue(jvMap.get(jv)))
            v = (Call) jvMap.get(jv);
        } else {
            v = new Call();
            v.callsite = jv.callsite;
            v.target = jv.apiName;
            v.callstring = jv.callstring;
        }
        if (v.comments == null) {
            v.comments = Utils.generateCallComments(v.callstring, v.callsite);
        }
        return v;
    }

    public void onStartFunc(org.example.nativesummary.ir.Function irFunc) {
        current = irFunc;
        jvMap = new HashMap<>();
    }

    public List<Map.Entry<Function, org.example.nativesummary.ir.Function>> handleDynamicRegister() throws InvalidInputException, DuplicateNameException {
        if (dynRegName.size() == 0) {
            return List.of();
        }
        List<Map.Entry<Function, org.example.nativesummary.ir.Function>> ret = new ArrayList<>();

        // set signature for each
        for (int i=0;i<dynRegFunc.size();i++) {
            JNIDescriptorParser parser = new JNIDescriptorParser(dynRegSig.get(i));
            List<String> tys = parser.parse();
            if (tys == null) {
                Logging.error("DynReg: Parse descriptor failed: "+parser.error);
                continue;
            }
            String retTy = parser.parseRet();
            if (retTy == null) {
                Logging.error("DynReg: Parse descriptor failed: "+parser.error);
                continue;
            }
            tys.add(0, "JNIEnv *");
            // jclazz or thiz
            tys.add(1, "jobject");
            Function f = dynRegFunc.get(i);
            // Set argument types and return types in ghidra
            if (f.getParameterCount() == 0 || (!Utils.isParameterJNIEnvPtr(f.getParameter(0)))) {
                MyGlobalState.ja.setFunctionType(dynRegFunc.get(i), tys, retTy);
            } else {
                Logging.info("DynReg: " + f.getName()+" param type already set?");
            }

            org.example.nativesummary.ir.Function irFunc = new org.example.nativesummary.ir.Function();
            irFunc.registeredBy = dynRegCall.get(i);
            irFunc.name = dynRegName.get(i);
            irFunc.signature = dynRegSig.get(i);

            for (int j=0;j<tys.size();j++) {
                String ty = tys.get(j);
                String pname = JSONAnalyzer.getNameByType(ty, j);
                if (pname == null) { pname = "a"+String.valueOf(j); }
                irFunc.params.add(new Param(pname, new Type(null).setTypeDef(ty)));
            }
            // add ret type
            irFunc.returnType = new Type(null).setTypeDef(retTy);
            ret.add(Map.entry(dynRegFunc.get(i), irFunc));
        }
        dynRegCall.clear();
        dynRegName.clear();
        dynRegSig.clear();
        dynRegFunc.clear();
        dynRegSet.clear();
        return ret;
    }
}
