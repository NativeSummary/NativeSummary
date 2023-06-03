package org.example.nativesummary.jimplebuilder;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.example.nativesummary.APKRepacker;
import org.example.nativesummary.Util;
import org.example.nativesummary.ir.Function;
import org.example.nativesummary.ir.Instruction;
import org.example.nativesummary.ir.inst.Call;
import org.example.nativesummary.ir.inst.Phi;
import org.example.nativesummary.ir.inst.Ret;
import org.example.nativesummary.ir.utils.Constant;
import org.example.nativesummary.ir.utils.Use;
import org.example.nativesummary.ir.value.Null;
import org.example.nativesummary.ir.value.Number;
import org.example.nativesummary.ir.value.Param;
import org.example.nativesummary.ir.value.Str;
import org.example.nativesummary.ir.value.Top;
import soot.ArrayType;
import soot.Body;
import soot.BooleanType;
import soot.ByteType;
import soot.CharType;
import soot.DoubleType;
import soot.FloatType;
import soot.IntType;
import soot.Local;
import soot.LongType;
import soot.NullType;
import soot.PackManager;
import soot.PhaseOptions;
import soot.PrimType;
import soot.RefLikeType;
import soot.RefType;
import soot.Scene;
import soot.ShortType;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Type;
import soot.Value;
import soot.VoidType;
import soot.jimple.ClassConstant;
import soot.jimple.DoubleConstant;
import soot.jimple.Expr;
import soot.jimple.FloatConstant;
import soot.jimple.IfStmt;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.Jimple;
import soot.jimple.LongConstant;
import soot.jimple.NeExpr;
import soot.jimple.NullConstant;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;

/*
typedef enum android_LogPriority {
    ANDROID_LOG_UNKNOWN = 0,
    ANDROID_LOG_DEFAULT,    // only for SetMinPriority() 
    ANDROID_LOG_VERBOSE,
    ANDROID_LOG_DEBUG,
    ANDROID_LOG_INFO,
    ANDROID_LOG_WARN,
    ANDROID_LOG_ERROR,
    ANDROID_LOG_FATAL,
    ANDROID_LOG_SILENT,     // only for SetMinPriority(); must be last 
} android_LogPriority;
*/

public class BodyBuilder {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    AuxMethodManager mmgr;
    SootMethod mth;
    Function func;
    TypeAnalysis ta;
    Body newBody;
    List<Value> mth_args = new ArrayList<>();
    Local returnVal;
    Map<String, Local> ret_map = new HashMap<>();
    Map<org.example.nativesummary.ir.Instruction, Value> valueMap = new HashMap<>();
    boolean isRetVoid;
    boolean isStatic;
    private int local_counter = 0;

    public static boolean noNullInPhi = false;

    public static String[] unhandledApi = 
    {"ReleaseStringUTFChars", "RegisterNatives", "DeleteLocalRef", 
      "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements", "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements", "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements",
    };
    public static final Set<String> unhandledApiSet = new HashSet<>(Arrays.asList(unhandledApi));

    private Local predicate_counter = null;
    private int predicate_count = 1;
    private Local getCounter() {
        if (predicate_counter == null) {
            predicate_counter = Jimple.v().newLocal("$opred", soot.IntType.v());
            newBody.getLocals().add(predicate_counter);
            // Initial Value? TODO
            StaticInvokeExpr e = Jimple.v().newStaticInvokeExpr(mmgr.opaqueInt().makeRef());
            newBody.getUnits().add(Jimple.v().newAssignStmt(predicate_counter, e));
        }
        return predicate_counter;
    }
    private IntConstant getCount() {
        return IntConstant.v(predicate_count ++);
    }

    public boolean debugJimple;
    public String jimpleDebugOutput;

    // 构建完成后调用，打印用于debug的jimple函数语句
    public String makeJimpleDebugOutput() {
        StringWriter out = new StringWriter();
        PrintWriter writer = new PrintWriter(out);
        soot.Printer.v().setOption(soot.Printer.USE_ABBREVIATIONS);
        soot.Printer.v().printTo(newBody, writer);
        writer.flush();
        jimpleDebugOutput = out.toString();
        return jimpleDebugOutput;
    }

    // public static final String[] REQUIRED_CLASS = {"android.util.Log"};

    // public static void loadRequiredClasses() {
    //     for(int i=0; i<REQUIRED_CLASS.length; i++) {
    //         Scene.v().loadClass(REQUIRED_CLASS[i], SootClass.SIGNATURES);
    //     }
    // }

    BodyBuilder(SootMethod mth, Function summary, AuxMethodManager mmgr) {
        this.mmgr = mmgr;
        this.mth = mth;
        this.func = summary;
        this.isRetVoid = (mth.getReturnType() instanceof VoidType);
        this.isStatic = mth.isStatic();
        this.ta = TypeAnalysis.instances.get(func);
        assert ta != null;
    }

    // based on muDep droidsafe_modified\src\main\java\stub\generation\service\FlagAnalysis.java
    protected void buildArgs() {
        if (Util.isJNIOnLoad(func)) {
            Local p = Jimple.v().newLocal("$javaVM", mth.getParameterType(0));
            mth_args.add(p);
            newBody.getLocals().add(p);
            newBody.getUnits().add(Jimple.v().newIdentityStmt(p, Jimple.v().newParameterRef(mth.getParameterType(0), 0)));
            return;
        } else {
            mth_args.add(NullConstant.v()); // for jnienv
        }
        if (!isStatic) {
            Local ths = Jimple.v().newLocal("$this", mth.getDeclaringClass().getType());
            newBody.getLocals().add(ths);
            newBody.getUnits().add(Jimple.v().newIdentityStmt(ths, Jimple.v().newThisRef(mth.getDeclaringClass().getType())));
            mth_args.add(ths);
        } else {
            // 占位，保持index一致
            mth_args.add(NullConstant.v());
        }
        //参数 local声明
        for (int i = 0; i < mth.getParameterCount(); i++) {
            Local p = Jimple.v().newLocal("$p" + i, mth.getParameterType(i));
            mth_args.add(p);
            newBody.getLocals().add(p);
            newBody.getUnits().add(Jimple.v().newIdentityStmt(p, Jimple.v().newParameterRef(mth.getParameterType(i), i)));
        }
    }

    protected void visitInstruction(Instruction i_) {
        if (i_ instanceof Call) {
            Call i = (Call)i_;
            visitCall(i);
        }
        // Phi delayed to 
        if (i_ instanceof Phi) {
            Phi i = (Phi) i_;
            Local local = null;
            Type lty = null;
            if (local == null) {
                lty = ta.getValueType(i);
                if (lty == null) {
                    logger.error("VisitPhi: cannot find type: "+i);
                    // lty = NullType.v();
                    valueMap.put(i, NullConstant.v());
                    return;
                }
                local = Jimple.v().newLocal("$"+i.name+"_phi", lty);
                newBody.getLocals().add(local);
                newBody.getUnits().add(Jimple.v().newAssignStmt(local, getDefaultValue(lty)));
            }
            List<Value> vals = filterPhiOperands(i, noNullInPhi);
            if (vals.size() == 1) {
                valueMap.put(i, vals.get(0));
                return;
            }
            // make if brach for each possible value.
            // if (i != n) goto next_if; assign arg = pv; goto last; next_if
            Stmt lastNop = Jimple.v().newNopStmt();
            IfStmt prevIfStmt = null;
            for (Value sootVal: vals) {
                NeExpr cond = Jimple.v().newNeExpr(getCounter(), getCount());
				IfStmt ifStmt = Jimple.v().newIfStmt(cond, (Stmt)null);
				newBody.getUnits().add(ifStmt);
                // fixup prev target
                if (prevIfStmt != null) {
                    prevIfStmt.setTarget(ifStmt);
                }
                prevIfStmt = ifStmt;
                
                if (!sootVal.getType().equals(local.getType())) {
                    Value casted = handleCast(sootVal, local.getType());
                    sootVal = casted;
                }
                newBody.getUnits().add(Jimple.v().newAssignStmt(local, sootVal));
                // create goto last;
                newBody.getUnits().add(Jimple.v().newGotoStmt(lastNop));
            }
            // fix last if
            prevIfStmt.setTarget(lastNop);
            newBody.getUnits().add(lastNop);
            valueMap.put(i, local);
        }
        if (i_ instanceof Ret) {
            Ret i = (Ret) i_;
            if (!(mth.getReturnType() instanceof VoidType)) {
                Value val = valueMap.get(i.operands.get(0).value);
                if (val == null) {
                    val = visitValue(i.operands.get(0).value, mth.getReturnType());
                }
                if (val == null) {
                    val = NullConstant.v();
                }

                if (!val.getType().equals(mth.getReturnType())) {
                    Value casted = handleCast(val, mth.getReturnType());
                    val = casted;
                }
                newBody.getUnits().add(Jimple.v().newReturnStmt(val));
            }
        }
    }

    private Value handleCast(Value sootVal, Type ty) {
        if (sootVal instanceof NullConstant) {
            return sootVal;
        }
        if (ty instanceof RefLikeType && sootVal.getType() instanceof PrimType) {
            Local boxed = doBoxing(sootVal, (PrimType)sootVal.getType());
            if (boxed != null) {
                Type boxedTy_ = boxed.getType();
                assert boxedTy_ instanceof RefType;
                if (boxedTy_ instanceof RefType) {
                    RefType boxedTy = (RefType)boxedTy_;
                    SootMethod tostr = boxedTy.getSootClass().getMethodUnsafe("toString", Collections.<Type>emptyList(), RefType.v("java.lang.String"));
                    if (tostr != null) {
                        Local ret = buildCallAssign(tostr, boxed, "$casted");
                        return ret;
                    }
                } else {logger.error("not RefType after boxing!!");}
                return boxed;
            }
            
        }
        // return Jimple.v().newCastExpr(sootVal, ty);
        return sootVal;
    }

    private Local doBoxing(Value sootVal2, PrimType ty) {
        RefType boxedTy = ty.boxedType();
        SootMethod conv = boxedTy.getSootClass().getMethodUnsafe("valueOf", List.<Type>of(ty), boxedTy);
        if (conv == null) {
            logger.error("Boxing failed for "+ty.toString());
            return null;
        }
        return buildCallAssign(conv, null, "boxed", sootVal2);
    }

    private List<Value> filterPhiOperands(Phi i, boolean noNullInPhi) {
        Set<Value> ret = new HashSet<>();
        for (Use use: i.operands) {
            org.example.nativesummary.ir.utils.Value val = use.value;
            if (noNullInPhi) {
                if (val instanceof Null || val instanceof Top) {
                    continue;
                }
            }
            Value sootVal = visitValue(val);
            if (sootVal == null) {
                continue;
            }
            if (!ret.contains(sootVal)) {
                ret.add(sootVal);
            }
        }
        return new ArrayList<>(ret);
    }

    private Value getDefaultValue(Type t) {
        if (t instanceof FloatType) {
            return FloatConstant.v(0.0f);
        } else if (t instanceof DoubleType) {
            return DoubleConstant.v(0.0);
        } else if (t instanceof IntType || t instanceof LongType || t instanceof CharType || t instanceof BooleanType || t instanceof ByteType
            || t instanceof ShortType) {
            return IntConstant.v(0);
        } else if (t instanceof RefLikeType) {
            return NullConstant.v();
        }
        throw new UnsupportedOperationException();
    }

    Value visitValue(org.example.nativesummary.ir.utils.Value val) {
        return visitValue(val, null);
    }

    Value visitValue(org.example.nativesummary.ir.utils.Value val, Type hint) {
        if (val instanceof Instruction) {
            Value sval = valueMap.get(val);
            if (sval != null) {
                return sval;
            } else {
                return NullConstant.v();
            }
        }
        if (val instanceof Top) {
            // TODO
            return NullConstant.v();
        }
        if (val instanceof Param) {
            Param p = (Param) val;
            int index = func.params.indexOf(p);
            // jniOnLoad has only one argument
            if (index == -1 && Util.isJNIOnLoad(func)) {
                index = 0;
            }
            return mth_args.get(index);
        } 
        if (val instanceof Constant) {
            return visitConstant((Constant)val, hint);
        }
        throw new UnsupportedOperationException();
    }

    protected Value visitConstant(Constant val_, Type hint) {
        if (val_ instanceof Null) {
            return NullConstant.v();
        }
        if (val_ instanceof Number) {
            Number val = (Number) val_;
            if ((val.val).longValue() == 0L && !(hint instanceof PrimType)) {
                return NullConstant.v();
            }
            if (val.val instanceof Integer) {
                return IntConstant.v((Integer)val.val);
            }
            if (val.val instanceof Long) {
                return LongConstant.v((Long)val.val);
            }
            if (val.val instanceof Float) {
                return FloatConstant.v((Float)val.val);
            }
            if (val.val instanceof Double) {
                return DoubleConstant.v((Double)val.val);
            }
        }
        if (val_ instanceof Str) {
            Str val = (Str) val_;
            return StringConstant.v(val.val == null ? "" : val.val);
        }
        throw new UnsupportedOperationException();
    }

    protected void visitCall(Call inst) {
        SootMethod sm = null;
        String api = inst.target;
        if (api == null) {
            return;
        }
        // if (!Util.isJNIAPI(api)) {
        //     logger.error("Unhandled API "+api);
        //     return;
        // }
        // assert Util.isJNIAPI(api);
        boolean isStatic = api.contains("Static");
        Value ret;
        // 这里忽视了API名字中的类型，直接利用了pass找到的SootField
        if (api.startsWith("Get") && api.endsWith("Field")) {
            // if (api.startsWith("GetStatic")) { isStatic = true; }
            SootField fld = ta.getFieldMap(inst.operands.get(2).value);
            if (fld == null) {
                logger.error(api+" cannot find field!!");
                return;
            }
            if (isStatic) {
                // JNIEnv *env, jclass clazz, jfieldID fieldID
                ret = Jimple.v().newStaticFieldRef(fld.makeRef());
            } else {
                // JNIEnv *env, jobject obj, jfieldID fieldID
                Value base = visitValue(inst.operands.get(1).value, fld.getType());
                base = ensureNonNull(base, fld.getDeclaringClass().getType());
                ret = Jimple.v().newInstanceFieldRef(base, fld.makeRef());
            }
            // 冗余没关系，由后面优化去处理
            ret = makeLocal(ret, inst.name);
            valueMap.put(inst, ret);
            ta.typeValue(inst, fld.getType());
            return;
        }
        // 直接不管类型
        if (api.startsWith("Set") && api.endsWith("Field")) {
            //          JNIEnv *env, jobject obj, jfieldID fieldID, jobject val
            // static - JNIEnv *env, jclass clazz, jfieldID fieldID, jobject value
            SootField fld = ta.getFieldMap(inst.operands.get(2).value);
            if (fld == null) {
                logger.error(api+" cannot find field!!");
                return;
            }
            Value val = visitValue(inst.operands.get(3).value, fld.getType());
            if (!val.getType().equals(fld.getType())) {
                Value casted = handleCast(val, fld.getType());
                val = casted;
            }
            if (isStatic) {
                newBody.getUnits().add(Jimple.v().newAssignStmt(Jimple.v().newStaticFieldRef(fld.makeRef()), val));
            } else {
                Value base = visitValue(inst.operands.get(1).value, fld.getDeclaringClass().getType());
                base = ensureNonNull(base, fld.getDeclaringClass().getType());
                newBody.getUnits().add(Jimple.v().newAssignStmt(Jimple.v().newInstanceFieldRef(base, fld.makeRef()), val));
            }
            valueMap.put(inst, null);
            ta.typeValue(inst, null);
            return;
        }
        // if (api.startsWith("Call") && api.endsWith("Method")) {
        if (api.matches("Call.*Method.?")) {
            // JNIEnv *env, jobject obj, jmethodID methodID, ...
            // JNIEnv *env, jclass clazz, jmethodID methodID, ... (static)
            char last = api.charAt(api.length()-1);
            // TODO 感觉这里应该二进制分析那边把相关的都转成不带A和V的方便传递污点。
            boolean isVar = false; // CallxxxMethodV
            boolean isArr = false; // CallxxxMethodA
            if (last == 'A') {
                isArr = true;
            } else if (last == 'V') {
                isVar = true;
            } else {
                assert last == 'd';
            }
            if (isArr || isVar) {
                logger.error("Special call {} is currently unsupported!", api);
            }

            SootMethod target = ta.getMethodMap(inst.operands.get(2).value);
            if (target == null) {
                logger.error(api+" cannot find method!!");
                return;
            }
            int argCount = target.getParameterCount();
            if (argCount > inst.operands.size() - 3){
                logger.error(api+" (0x"+Long.toHexString(inst.callsite)+")"+": resolved arg count not enough");
                argCount = inst.operands.size() - 3;
            }
            List<Value> args = new ArrayList<>();
            for (int i=0;i<argCount;i++) {
                Type at = target.getParameterType(i);
                Value l = visitValue(inst.operands.get(i+3).value, at);
                // TODO 转成Local？
                if (!l.getType().equals(at)) {
                    Value casted = handleCast(l, at);
                    l = casted;
                }
                args.add(l);
            }
            SootClass target_clz = target.getDeclaringClass();
            RefType target_type = RefType.v(target_clz);
            if (isStatic) {
                assert target.isStatic();
                ret = buildCallAssign(target, null, "$"+inst.name, args.toArray(new Value[0]));
            } else {
                Value base = visitValue(inst.operands.get(1).value, target_type);
                if (!(base instanceof Local)) {
                    Local l = Jimple.v().newLocal("$"+inst.name+"_base", target_type);
                    newBody.getLocals().add(l);
                    // TODO make cast?
                    newBody.getUnits().add(Jimple.v().newAssignStmt(l, base));
                    base = l;
                } else {
                    if (!base.getType().equals(target_type)) {
                        Local l = Jimple.v().newLocal("$"+inst.name+"_base", target_type);
                        newBody.getLocals().add(l);
                        Value casted = Jimple.v().newCastExpr(base, target_type);
                        newBody.getUnits().add(Jimple.v().newAssignStmt(l, casted));
                        base = l;
                    }
                }
                ret = buildCallAssign(target, (Local)base, "$"+inst.name, args.toArray(new Value[0]));
            }
            valueMap.put(inst, ret);
            ta.typeValue(inst, ret != null? ret.getType(): null);
            return;
        }

        // JNIEnv *env, jclass clazz, jmethodID methodID
        if (api.equals("NewObject")) {
            SootMethod target = ta.getMethodMap(inst.operands.get(2).value);
            if (target == null) {
                logger.error(api+" cannot find method!!");
                return;
            }
            int arg_size = target.getParameterCount();
            if (arg_size != inst.operands.size() - 3){
                logger.error(api+" (0x"+Long.toHexString(inst.callsite)+")"+": resolved arg count mismatch");
            }
            List<Value> args = new ArrayList<>();
            for (int i=0;i<arg_size;i++) {
                Type at = target.getParameterType(i);
                Value l;
                if (inst.operands.size() > i+3) {
                    l = visitValue(inst.operands.get(i+3).value, at);
                    if (!l.getType().equals(at)) {
                        Value casted = handleCast(l, at);
                        l = casted;
                    }
                } else { // fill in default value
                    l = getDefaultValue(at);
                }
                args.add(l);
            }
            // 创建返回值
            SootClass target_clz = target.getDeclaringClass();
            RefType target_type = target_clz.getType();
            ret = Jimple.v().newLocal("$"+inst.name, target_type);
            newBody.getLocals().add((Local)ret);

            // $r15 = new java.lang.StringBuilder;
            newBody.getUnits().add(Jimple.v().newAssignStmt(ret, Jimple.v().newNewExpr(target_type)));
            // specialinvoke $r15.<java.lang.StringBuilder: void <init>()>();
            buildSpecialCall(target, (Local)ret, args.toArray(new Value[0]));
            valueMap.put(inst, ret);
            ta.typeValue(inst, ret.getType());
            return;
        }
        if (api.equals("GetStringUTFChars")) {
            Value val = visitValue(inst.operands.get(1).value, RefType.v("java.lang.String"));
            if (val instanceof NullConstant) {
                logger.error("GetStringUTFChars argument is unknown");
            }
            valueMap.put(inst, val);
            ta.typeValue(inst, val.getType());
            return;
        }
        if (api.equals("NewStringUTF")) {
            Value val = visitValue(inst.operands.get(1).value, RefType.v("java.lang.String"));
            if (val instanceof NullConstant) {
                logger.warn("NewStringUTF argument is unknown");
            }
            valueMap.put(inst, val);
            ta.typeValue(inst, val.getType());
            return;
        }
        if (api.startsWith("Get") && api.endsWith("ArrayElement")) {
            // Call GetObjectArrayElement null, %a2, long 1
            Value base = visitValue(inst.operands.get(1).value);
            Value ind = visitValue(inst.operands.get(2).value, IntType.v());
            if (ind instanceof NullConstant) {
                // make opaque int
            }
            if (ind instanceof LongConstant) {
                ind = IntConstant.v(Math.toIntExact(((LongConstant)ind).value));
            }
            Value result;
            // base is unknown, degrade to assign
            if (base instanceof NullConstant) {
                result = base;
                valueMap.put(inst, result);
            } else {
                // ind is unknown, use 0.
                if (ind instanceof NullConstant) {
                    ind = IntConstant.v(0);
                }
                result = Jimple.v().newArrayRef(base, ind);
                result = makeLocal(result, inst.name);
            }
            valueMap.put(inst, result);
            ta.typeValue(inst, result.getType());
            return;
        }
        if (api.equals("GetDirectBufferAddress") ||
                (api.startsWith("Get") && api.endsWith("ArrayElements")) ){
            Value val = visitValue(inst.operands.get(1).value);
            valueMap.put(inst, val);
            ta.typeValue(inst, val.getType());
            return;
        }
        if (api.equals("IsSameObject")) {
            Value val1 = visitValue(inst.operands.get(1).value);
            Value val2 = visitValue(inst.operands.get(2).value);
            if (val1 != null && val2 != null && !(val1 instanceof NullConstant) && !(val2 instanceof NullConstant)) {
                Value val = Jimple.v().newEqExpr(val1, val2);
                valueMap.put(inst, val);
                ta.typeValue(inst, val.getType()); // BooleanType.v()
            }
            return;
        }
        if (api.equals("IsInstanceOf")) {
            Value val = visitValue(inst.operands.get(1).value);
            SootClass target = ta.getClassMap(inst.operands.get(2).value);
            if (val != null && target != null) { // val can be nullconstant
                val = Jimple.v().newInstanceOfExpr(val, target.getType());
                valueMap.put(inst, val);
                ta.typeValue(inst, val.getType()); // 就是 BooleanType.v()
            } else {
                logger.warn("failed to resolve IsInstanceOf.");
            }
            return;
        }
        if (api.equals("Throw")) {
            Value val = visitValue(inst.operands.get(1).value);
            if (val != null) {
                newBody.getUnits().add(Jimple.v().newThrowStmt(val));
            }
            return;
        }
        if (api.equals("ThrowNew")) {
            SootClass target = ta.getClassMap(inst.operands.get(1).value);
            SootMethod cons = null;
            if (target != null) {
                cons = target.getMethodUnsafe(SootMethod.constructorName, List.of(RefType.v("java.lang.String")), VoidType.v());

                Value str = visitValue(inst.operands.get(2).value);
                if (cons != null && str != null) {
                    RefType target_type = target.getType();
                    ret = Jimple.v().newLocal("$"+inst.name, target_type);
                    newBody.getLocals().add((Local)ret);
                    newBody.getUnits().add(Jimple.v().newAssignStmt(ret, Jimple.v().newNewExpr(target_type)));
                    buildSpecialCall(cons, (Local)ret, str); // omit?
                    newBody.getUnits().add(Jimple.v().newThrowStmt(ret));
                }
            }
            return;
        }
        if (TypeAnalysis.handledApiSet.contains(api)) {
            return;
        }
        if (unhandledApiSet.contains(api)) {
            return;
        }

        // 自动从里面创建。
        if (AutoLowering.handledApiSet.contains(api) || (!Util.isJNIAPI(api))) {
            // 收集参数和返回值类型，去创建一个Native函数
            List<Value> args = new ArrayList<>();
            List<Type> argTypes = new ArrayList<>();
            for (Use u: inst.operands) {
                Value v = visitValue(u.value);
                args.add(v);
                Type t = v.getType();
                if (v instanceof NullConstant) {
                    t = RefType.v("java.lang.Object");
                }
                argTypes.add(t);
            }
            Type retTy = ta.getValueType(inst);
            if (retTy == null) {
                retTy = IntType.v();
            }
            // 创建调用
            SootMethod target = mmgr.getNativeMth(api, argTypes, retTy);
            ret = buildCallAssign(target, null, "$"+inst.name, args.toArray(new Value[0]));
            valueMap.put(inst, ret);
            ta.typeValue(inst, ret.getType());
            return;
        }
        logger.error("unimplemented api: "+api);
    }

    Value ensureNonNull(Value base, RefType type) {
        if (base instanceof NullConstant) {
            Local l = Jimple.v().newLocal("$tmp", type);
            newBody.getLocals().add(l);
            newBody.getUnits().add(Jimple.v().newAssignStmt(l, base));
            base = l;
        }
        return base;
    }
    Value makeLocal(Value ret, String name) {
        if (ret.getType() instanceof NullType) {
            return null;
        }
        Local l = Jimple.v().newLocal("$"+name, ret.getType());
        newBody.getLocals().add(l);
        newBody.getUnits().add(Jimple.v().newAssignStmt(l, ret));
        return l;
    }

    public static Value nullableValue(Value v) {
        if (v == null) {
            return NullConstant.v();
        }
        return v;
    }

    public static List<String> searchForSig(String clz_name, String mth_name) {
        SootClass c = Scene.v().getSootClassUnsafe(clz_name);
        List<String> sigs = new ArrayList<>();
        for (SootMethod m: c.getMethods()) {
            if (m.getName().equals(mth_name)) {
                sigs.add(m.toString());
            }
        }
        return sigs;
    }

    // used by GetMethodID
    /**
     * construct a class array in body for calling reflection methods, eg: `getDeclaredMethod`.
     * @param sig
     * @return
     */
    public Local classArrFromSig(String sig) {
        // $r6 = newarray (java.lang.Class)[1];
        // $r6[0] = class "Ljava/lang/String;";
        // first get array size
        List<Type> ts = argTypesFromSig(sig);
        int arraySize = ts.size();
        // make local variable
        Type cls_arr_t = ArrayType.v(Scene.v().getType("java.lang.Class"), 1);
        Local arr = Jimple.v().newLocal("$a"+local_counter++, cls_arr_t);
        newBody.getLocals().add(arr);
        Expr e = Jimple.v().newNewArrayExpr(cls_arr_t, IntConstant.v(arraySize));
        Stmt assign = Jimple.v().newAssignStmt(arr, e);
        newBody.getUnits().add(assign);
        // assign each elem
        for (int i=0;i<ts.size();i++) {
            Type t = ts.get(i);
            Value clz = ClassConstant.fromType(t);
            Value lef = Jimple.v().newArrayRef(arr, IntConstant.v(i));
            Stmt assign2 = Jimple.v().newAssignStmt(lef, clz);
            newBody.getUnits().add(assign2);
        }
        return arr;
    }

    // used by GetMethodID
    public static List<Type> argTypesFromSig(String sig) {
        // from soot src\main\java\soot\toDex\DexPrinter.java buildEnclosingMethodTag
        String[] split1 = sig.split("\\)");
        String parametersS = split1[0].replaceAll("\\(", "");
        // String returnTypeS = split1[1];
    
        List<Type> typeList = new ArrayList<Type>();
        if (!parametersS.isEmpty()) {
          for (String p : soot.dexpler.Util.splitParameters(parametersS)) {
            if (!p.isEmpty()) {
                Type t = soot.dexpler.Util.getType(p);
                typeList.add(t);
            }
          }
        }
        return typeList;
    }

    protected Local buildCallAssign(String methodSignature, Local base, String retName, Value... args) {
        SootMethod m = Scene.v().getMethod(methodSignature);
        return buildCallAssign(m, base, retName, args);
    }

    protected Local buildCallAssign(SootMethod m, Local base, String retName, Value... args) {
        
        InvokeExpr ie;
        if(m.isConstructor()) {
            ie = Jimple.v().newSpecialInvokeExpr(base, m.makeRef(), args);
        } else if(m.isStatic()) {
            ie = Jimple.v().newStaticInvokeExpr(m.makeRef(), args);
        } else if(m.getDeclaringClass().isInterface()) {
            ie = Jimple.v().newInterfaceInvokeExpr(base, m.makeRef(), args);
        } else {
            ie = Jimple.v().newVirtualInvokeExpr(base, m.makeRef(), args);
        }
        Type retType = m.getReturnType();
        if (!(retType instanceof VoidType)) {
            Local ret = Jimple.v().newLocal(retName, retType);
            newBody.getLocals().add(ret);
            newBody.getUnits().add(Jimple.v().newAssignStmt(ret, ie));
            return ret;
        } else {
            newBody.getUnits().add(Jimple.v().newInvokeStmt(ie));
        }
        return null;
    }

    public void buildSpecialCall(SootMethod m, Local base, Value... args) {
        assert m.isConstructor();
        InvokeExpr ie = Jimple.v().newSpecialInvokeExpr(base, m.makeRef(), args);
        newBody.getUnits().add(Jimple.v().newInvokeStmt(ie));
    }

    public void build() {
        if (((mth.getModifiers() & soot.Modifier.NATIVE) == 0) && (mth.hasActiveBody())) {
            logger.error("method already built?");
            return;
        }
        newBody = Jimple.v().newBody();
        //turn off native modifier
        mth.setModifiers(mth.getModifiers() ^ soot.Modifier.NATIVE);
        newBody.setMethod(mth);
        mth.setActiveBody(newBody);
        
        // 获取参数到局部变量，局部变量放进参数list里备用。
        buildArgs();
        if (!isRetVoid) {
            returnVal = Jimple.v().newLocal("$ret", mth.getReturnType());
            newBody.getLocals().add(returnVal);
        }

        // if(met.isConstructor()) {
        //     ie = Jimple.v().newSpecialInvokeExpr(local, met.makeRef(), parameters);
        // }else if(met.isStatic()) {
        //     ie = Jimple.v().newStaticInvokeExpr(met.makeRef(), parameters);
        // }else {
        //     ie = Jimple.v().newVirtualInvokeExpr(local, met.makeRef(), parameters);
        // }

        // 遍历每一个log。根据API是什么决定要不要生成语句
        // 要生成的依次用if处理参数可能取多值的情况
        // 最后生成调用。保存返回值备用
        // 发现是返回值的API的生成返回语句。（如果不是最后一句就用if保护一下。）
        // for(Map.Entry<String, JsonElement> e: summary.entrySet()) {
        //     Local r = buildCall(e.getKey(), e.getValue());
        //     ret_map.put(e.getKey(), r);
        //     // newBody.validate();
        // }

        for (Instruction i: func.insts()) {
            visitInstruction(i);
        }

        // return
        if (isRetVoid) {
            newBody.getUnits().add(Jimple.v().newReturnVoidStmt());
        } else {
            newBody.getUnits().add(Jimple.v().newReturnStmt(returnVal));
        }

        // NopEliminator.v().transform(newBody);
        newBody.validate();
        // !!! do optimize
        if (!APKRepacker.cmd.hasOption("no-opt")) {
            PhaseOptions.v().setPhaseOption("jop", "enabled");
            PackManager.v().getPack("jop").apply(newBody);
        }
        if (debugJimple) {
            makeJimpleDebugOutput();
        }
        return;
    }
}
