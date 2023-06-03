package org.example.nativesummary.jimplebuilder;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.example.nativesummary.Util;
import org.example.nativesummary.ir.Function;
import org.example.nativesummary.ir.Instruction;
import org.example.nativesummary.ir.Module;
import org.example.nativesummary.ir.inst.Call;
import org.example.nativesummary.ir.inst.Phi;
import org.example.nativesummary.ir.inst.Ret;
import org.example.nativesummary.ir.utils.Constant;
import org.example.nativesummary.ir.utils.Use;
import org.example.nativesummary.ir.utils.Value;
import org.example.nativesummary.ir.value.Null;
import org.example.nativesummary.ir.value.Number;
import org.example.nativesummary.ir.value.Param;
import org.example.nativesummary.ir.value.Str;
import org.example.nativesummary.ir.value.Top;
import soot.AbstractJasminClass;
import soot.ArrayType;
import soot.DoubleType;
import soot.FloatType;
import soot.IntType;
import soot.LongType;
import soot.PrimType;
import soot.RefLikeType;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Type;

/**
 * find concrete id, annotate each method with SootMethod/SootField/SootClass
 * find concrete class for registerNatives
 * use worklist to propergate type info
 * type untyped external function
 */
public class TypeAnalysis {
    final static Logger logger = LoggerFactory.getLogger(TypeAnalysis.class);
    public static Map<Function, TypeAnalysis> instances;
    // 本分析需要处理的API
    // 特殊处理，不生成对应的java
    public static String[] handledApi = 
    {"GetMethodID", "GetStaticMethodID", "GetFieldID", "GetStaticFieldID",
        "FindClass", "GetObjectClass", "GetSuperclass", "NewGlobalRef"}; // TODO "DefineClass" "GetBooleanArrayElements"
    public static final Set<String> handledApiSet = new HashSet<>(Arrays.asList(handledApi));

    public static void process(Module summary, AuxMethodManager mmgr) {
        instances = new HashMap<>();
        for (Function func: summary.funcs) {
            TypeAnalysis instance = new TypeAnalysis(func);
            // skip JNI_OnLoad
            if (Util.isJNIOnLoad(func)) {
                instance.current = mmgr.jniOnLoad();
            } else {
                instance.findSootMethod();
            }
            instance.doAnalysis();
            instances.put(func, instance);
        }
    }

    Function func;
    // analysis results
    SootClass currentClass;
    SootMethod current;
    Map<Value, Type> sootTyMap = new HashMap<>();
    Map<Value, SootClass> classMap = new HashMap<>();
    Map<Value, SootMethod> methodMap = new HashMap<>();
    Map<Value, SootField> fieldMap = new HashMap<>();
    // Map<Value, SootMethod> extCallMap = new HashMap<>();
    public static Map<Call, SootClass> dynRegMap = new HashMap<>();

    public TypeAnalysis(Function f) {
        this.func = f;
    }

    // find corresponding SootMethod for current Func
    public void findSootMethod() {
        if (func.clazz == null) {
            assert func.registeredBy != null;
            currentClass = TypeAnalysis.dynRegMap.get(func.registeredBy);
            if (currentClass == null) {
                logger.error("Cannot Find Target Class for dynamic registered function: "+func.name);
                return;
            }
        } else {
            String clazz = soot.dexpler.Util.dottedClassName(func.clazz);
            currentClass = Scene.v().getSootClass(clazz);
        }

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
    }

    // GetMethodID/GetStaticMethodID/GetFieldID/GetStaticFieldID depends on FindClass/GetObjectClass/GetSuperclass/GetObjectClass
    // handle class id -> handle method id
    public void doAnalysis() {
        if (current == null) {
            logger.error("Skipped building body for: "+func.clazz+"."+func.name);
            return;
        }
        // thiz
        sootTyMap.put(func.params.get(1), current.getDeclaringClass().getType());
        // jnienv, thiz
        if (!Util.isJNIOnLoad(func)) {
            if (func.params.size() != current.getParameterCount() + 2) {
                logger.error("IR signature {} mismatch with SootMethod!!! {}.", current, func.signature, current.getSignature());
            }
        }
        // mark parameter type
        // int size = func.params.size()-2;
        int size = current.getParameterCount();
        String comment = "";
        for (int i=0; i<size; i++) {
            int index = Util.isJNIOnLoad(func) ? i : i+2;
            Param param = func.params.get(index);
            Type sootTy = current.getParameterType(i);
            // typeValue(param, sootTy);
            sootTyMap.put(param, sootTy);
            comment = comment + String.format("(%s: %s) ", param.name, sootTy.toString());
        }
        if (comment.length() != 0){
            func.comment = comment;
        }
        // process all class id before method id.
        handleClassId();
        handleNewGlobalRef();
        handleMthFldId();
        // process all method call statement
        // call's parameter type flow to argument type.
        handleInst();
    }

    // 同时前向传播和反向传播必然确定的类型信息。使用一个Worklist算法。
    void handleInst() {
        // TODO better ordered set
        LinkedHashSet<Instruction> worklist = new LinkedHashSet<>();
        worklist.addAll(func.insts());
        while (!worklist.isEmpty()) {
            Instruction inst = worklist.iterator().next();
            worklist.remove(inst);
            // Call指令不会引用未来的值
            if (inst instanceof Call) {
                Call call = (Call)inst;
                if (call.target == null) {
                    continue;
                }
                // jobject clazz/obj, jmethodID methodID, ...
                // Nonvirtual: jobject obj, jclass clazz, jmethodID methodID, ... 
                if (call.target.matches("Call.*Method.?")) {
                    if (!Util.jniApiNameSet.contains(call.target)) {
                        logger.error("Cannot recognize JNI call: "+call.target);
                        continue;
                    }
                    int midInd = 2;
                    if (call.target.contains("Nonvirtual")) {
                        midInd = 3;
                    }
                    SootMethod m = getMethodMap(call.operands.get(midInd).value);
                    if (m == null) {
                        logger.error("TypeAnalysis: Cannot resolve target for "+call.toString());
                        continue;
                    }
                    // if no type for each argument, type it.
                    int callArgSize = call.operands.size() - (midInd + 1);
                    int mthArgSize = m.getParameterCount();
                    if (callArgSize < mthArgSize) {
                        logger.error("call operand count {} smaller than actual count {}: {}", callArgSize, mthArgSize, call);
                    }
                    int size = Math.min(callArgSize, mthArgSize);
                    // 参数传播（可能反向）
                    for (int i=0;i<size;i++) {
                        Use u = call.operands.get(midInd+1+i);
                        Value arg = u.value;
                        if (typeValue(arg, m.getParameterType(i))) {
                            addUsersToWorklist(arg, worklist);
                            addToWorklist(arg, worklist);
                        }
                    }
                    // 返回值传播
                    if (typeValue(call, m.getReturnType())) {
                        // 加入所有User
                        addUsersToWorklist(call, worklist);
                    }
                }
            }
            // Phi的类型双向传播。把所有类型都合并起来，然后传播合并后的类型。
            if (inst instanceof Phi) {
                Phi phi = (Phi) inst;
                // 获取所有类型，并合并
                Type orig = sootTyMap.get(phi);
                Set<Type> types = new HashSet<>();
                if (orig != null) {
                    types.add(orig);
                }
                for (Use u: phi.operands) {
                    Type st = getValueType(u.value);
                    if (st != null) {
                        types.add(st);
                    }
                }
                Type result = mergeTypes(types);
                
                // type返回值。
                if (typeValue(phi, result)) {
                    addUsersToWorklist(phi, worklist);
                } 
                // type参数
                for (Use u: phi.operands) {
                    if (typeValue(u.value, result)) {
                        addUsersToWorklist(u.value, worklist);
                        addToWorklist(u.value, worklist);
                    }
                }
            }
            if (inst instanceof Ret) {
                Ret r = (Ret) inst;
                Value val = r.operands.get(0).value;
                if (typeValue(val, current.getReturnType())) {
                    addUsersToWorklist(val, worklist);
                    addToWorklist(val, worklist);
                }
            }
        }
    }

    Type mergeTypes(Set<Type> types) {
        int size = types.size();
        if (size == 0) {
            return null;
        } else if (size == 1) {
            return types.iterator().next();
        } else {
            Type ret = types.iterator().next();
            for (Type ty: types) {
                ret = mergeType(ret, ty);
            }
            return ret;
        }
    }

    Type mergeType(Type ty1, Type ty2) {
        if (ty1 == null) {
            return ty2;
        }
        if (ty2 == null) {
            return ty1;
        }
        if (ty1.equals(ty2)) {
            return ty1;
        }
        Type ret = ty1;
        // TODO add importance mark?
        // 如果同时有PrimType和RefType，优先RefType，因为PrimType可以Box
        if (ty1 instanceof PrimType && ty2 instanceof RefLikeType) {
            ret = ty2;
        } else if (ty2 instanceof PrimType && ty1 instanceof RefLikeType) {
            ret = ty1;
        } else if (ty1 instanceof LongType) { // Workaround: 二进制那边都直接用的long，所以出现了int的话应该用int。
            ret = ty2;
        } else if(ty2 instanceof LongType) {
            ret = ty1;
        } else {
            logger.error("Failed to merge two type: {} vs. {}", ty1, ty2);
        }
        return ret;
    }

    // merge type and put into typemap
    // return true if updated
    boolean typeValue(Value val, Type ty) {
        if (ty == null) {
            return false;
        }
        Type current = getValueType(val);

        if (current == null) {
            Type orig = sootTyMap.putIfAbsent(val, ty);
            assert orig == null;
            return true;
        } else if (current.equals(ty)) {
            return false;
        } else { // two different type
            // merge two type
            // if (ty instanceof RefType && current instanceof RefType) {
            //     RefType refc = (RefType) current;
            //     refc.getSootClass().i
            // }
            // TODO
            
            Type tym = mergeType(current, ty);
            if (tym.equals(current)) {
                return false;
            } else {
                sootTyMap.put(val, tym);
                return true;
            }
        }
    }

    void addToWorklist(Value v, LinkedHashSet<Instruction> worklist) {
        if (v instanceof Instruction && ((Instruction)v).parent == func) {
            worklist.add(((Instruction)v));
        }
    }

    // 将使用了value的，本函数的Instruction加入到worklist
    void addUsersToWorklist(Value v, LinkedHashSet<Instruction> worklist) {
        for (Use u: v.getUses()) {
            Value user = u.user;
            addToWorklist(user, worklist);
        }
    }

    public Type getValueType(Value val) {
        if (sootTyMap.containsKey(val)) {
            return sootTyMap.get(val);
        }
        Type ret = null;
        if (val instanceof Constant) {
            ret = getConstantType((Constant)val);
        }
        else if (val instanceof Instruction) {
            ret = null;
        }
        else if (val instanceof Top) {
            return null;
        }
        else if (val instanceof Param) {
            // Param must have type in sootTyMap
            Param p = (Param) val;
            Type ty = sootTyMap.get(p);
            // assert ty != null;
            return ty;
        } else {
            // be exhausted
            throw new UnsupportedOperationException();
        }
        sootTyMap.put(val, ret);
        return ret;
    }

    public static Type getConstantType(Constant val_) {
        if (val_ instanceof Null) {
            return null;
        }
        if (val_ instanceof Number) {
            Number val = (Number) val_;
            if (val.val instanceof Integer) {
                return IntType.v();
            }
            if (val.val instanceof Long) {
                return LongType.v();
            }
            if (val.val instanceof Float) {
                return FloatType.v();
            }
            if (val.val instanceof Double) {
                return DoubleType.v();
            }
        }
        if (val_ instanceof Str) {
            Str val = (Str) val_;
            return RefType.v("java.lang.String");
        }
        throw new UnsupportedOperationException();
    }

    void handleNewGlobalRef() {
        iterCall(call -> {
            if (call.target.matches("NewGlobalRef")) {
                Value cid = call.operands.get(1).value;
                if (classMap.containsKey(cid)) {
                    logger.debug("passing classid for"+call.toString());
                    classMap.put(call, getClassMap(cid));
                }
                if (sootTyMap.containsKey(cid)) {
                    logger.debug("passing sootType for"+call.toString());
                    sootTyMap.put(call, getValueType(cid));
                }
            }
        });
    }

    void handleMthFldId() {
        for (Instruction inst: func.insts()) {
            if (inst instanceof Phi) {
                // TODO handle Phi for fields
                for (Use use: inst.operands) {
                    Value val = use.value;
                    if (fieldMap.containsKey(val)) {
                        // throw new UnsupportedOperationException("TODO handle Phi for jfield.");
                        logger.error("TODO handle Phi for jfield");
                        fieldMap.put(inst, fieldMap.get(val));
                    }
                }
            }
            if (!(inst instanceof Call)) {
                continue;
            }
            Call call = (Call)inst;
            if (call.target == null) {
                continue;
            }
            // signature暂时没有用到
            // jclass clazz, const char *name, const char *sig
            if (call.target.equals("GetFieldID") || call.target.equals("GetStaticFieldID")) {
                Value clz = call.operands.get(1).value;
                SootClass cclz = getClassMap(clz);
                if (cclz == null) {
                    logger.error("GetFieldID unable resolve to soot class: {}", clz);
                    continue;
                }
                Value nameVal = call.operands.get(2).value;
                Value sigVal = call.operands.get(3).value;
                Str name = ensureStr(nameVal);
                if (name == null) {
                    logger.error("GetFieldID cannot resolve name: {}", nameVal);
                    continue;
                }
                SootField f;
                try{
                    f = cclz.getFieldByName(name.val);
                } catch (RuntimeException e) {
                    logger.error(e.getMessage());
                    continue;
                }
                fieldMap.put(call, f);
                call.preComments = f.toString();
            }
            // JNIEnv *env, jclass clazz, const char *name, const char *sig
            if (call.target.equals("GetMethodID") || call.target.equals("GetStaticMethodID")) {
                Value clz = call.operands.get(1).value;
                SootClass cclz = getClassMap(clz);
                if (cclz == null) {
                    logger.error("GetMethodID unable resolve to soot class: {}", clz);
                    continue;
                }
                Value nameVal = call.operands.get(2).value;
                Value sigVal = call.operands.get(3).value;
                Str name = ensureStr(nameVal);
                Str sig = ensureStr(sigVal);
                if (name == null) {
                    logger.error("GetMethodID cannot resolve name: {}", nameVal);
                    continue;
                }
                if (sig == null) {
                    logger.error("GetMethodID cannot resolve signature: {}", sigVal);
                    continue;
                }
                List<Type> ts = BodyBuilder.argTypesFromSig(sig.val);
                SootMethod m;
                try{
                    m = cclz.getMethod(name.val, ts);
                } catch (RuntimeException e) {
                    logger.error(e.getMessage());
                    continue;
                }
                methodMap.put(call, m);
                call.preComments = m.toString();
            }
            if (call.target.equals("RegisterNatives")) {
                Value clz = call.operands.get(1).value;
                SootClass cclz = getClassMap(clz);
                if (cclz == null) {
                    logger.error("RegisterNatives unable resolve to soot class: {}", clz);
                    continue;
                }
                dynRegMap.put(call, cclz);
            }
        }
    }

    void handleClassId() {
        iterCall(call -> {
            if (call.target.equals("FindClass")) {
                Value strv = call.operands.get(1).value;
                Str str = ensureStr(strv);
                if (str == null || str.val == null) {
                    logger.error("FindClass resolution failed: {}", call);
                    return;
                }
                String clz_name = str.val.replace('/', '.');
                SootClass clz = Scene.v().getSootClassUnsafe(clz_name, false);
                if (clz == null || (clz.isPhantomClass() && clz.getMethodCount() == 0)) {
                    logger.error("cannot load class for: {}", call);
                    logger.error("Please add "+clz_name+" to preloaded classes.");
                    // Scene.v().loadClass(clz_name, SootClass.SIGNATURES);
                    // throw new RuntimeException("Cannot load class.");
                    return;
                }
                classMap.put(call, clz);
                call.preComments = clz.toString();
            }
            if (call.target.equals("GetObjectClass")) {
                // JNIEnv *env, jobject obj
                Value strv = call.operands.get(1).value;
                if (sootTyMap.containsKey(strv)) {
                    Type ty = sootTyMap.get(strv);
                    // ty to sootClass
                    if(ty instanceof RefType) {
                        RefType ref = (RefType)ty;
                        SootClass clz = ref.getSootClass();
                        classMap.put(call, clz);
                        call.preComments = clz.toString();
                    } else if (ty instanceof ArrayType) {
                        // SootClass clz = ((ArrayType)ty).getArrayElementType()
                        logger.error("Cannot resolve SootClass: cannot call GetObjectClass on array type {}: {}", ty, call);
                    } else {
                        assert ty instanceof PrimType;
                        SootClass clz = ((PrimType)ty).boxedType().getSootClass();
                        classMap.put(call, clz);
                        call.preComments = clz.toString();
                    }
                    
                } else {
                    logger.error("Cannot resolve: " + call);
                }
            }
            if (call.target.equals("GetSuperclass")) {
                Value strv = call.operands.get(1).value;
                if (sootTyMap.containsKey(strv)) {
                    Type ty = sootTyMap.get(strv);
                    assert ty instanceof RefType;
                    RefType ref = (RefType)ty;
                    SootClass clz = ref.getSootClass();
                    assert clz.hasSuperclass();
                    clz = clz.getSuperclassUnsafe();
                    classMap.put(call, clz);
                    call.preComments = clz.toString();
                } else {
                    logger.error("Cannot resolve: " + call);
                }
            }
            if (call.target.matches("NewGlobalRef")) {
                Value cid = call.operands.get(1).value;
                if (classMap.containsKey(cid)) {
                    logger.debug("passing classid for"+call.toString());
                    classMap.put(call, getClassMap(cid));
                }
                if (sootTyMap.containsKey(cid)) {
                    logger.debug("passing sootType for"+call.toString());
                    sootTyMap.put(call, getValueType(cid));
                }
            }
        });
    }

    Str ensureStr(Value strv) {
        if (!(strv instanceof Str)) {
            if (strv instanceof Top || strv instanceof Null) {
                logger.warn("str value not accurate: {}", strv);
            } else if (strv instanceof Phi) {
                // 找到第一个strValue充数。TODO 支持Phi的解析
                Phi phi = (Phi) strv;
                Str ret = null;
                for (Use u: phi.operands) {
                    ret = ensureStr(u.value);
                    if (ret != null) {
                        break;
                    }
                }
                return ret;
            } else {
                logger.error("string constant expected: {}", strv);
            }
            return null;
        }
        Str str = (Str) strv;
        return str;
    }

    public static SootField getFieldMap(Value operand, Map<Value, SootField> defMap) {
        if(operand instanceof Instruction) {
            Instruction inst = (Instruction) operand;
            return instances.get(inst.parent).fieldMap.get(inst);
        } else {
            return defMap.get(operand);
        }
    }

    SootField getFieldMap(Value operand) {
        if(operand instanceof Instruction) {
            Instruction inst = (Instruction) operand;
            return instances.get(inst.parent).fieldMap.get(inst);
        } else {
            return fieldMap.get(operand);
        }
    }

    public static SootMethod getMethodMap(Value operand, Map<Value, SootMethod> defMap) {
        if(operand instanceof Instruction) {
            Instruction inst = (Instruction) operand;
            return instances.get(inst.parent).methodMap.get(inst);
        } else {
            return defMap.get(operand);
        }
    }

    SootMethod getMethodMap(Value operand) {
        if(operand instanceof Instruction) {
            Instruction inst = (Instruction) operand;
            if (inst.parent != func) {
                return instances.get(inst.parent).methodMap.get(inst);
            } else {
                return methodMap.get(operand);
            }
            
        } else {
            return methodMap.get(operand);
        }
    }

    public static SootClass getClassMap(Value operand, Map<Value, SootClass> defMap) {
        if(operand instanceof Instruction) {
            Instruction inst = (Instruction) operand;
            return instances.get(inst.parent).classMap.get(inst);
        } else {
            return defMap.get(operand);
        }
    }

    SootClass getClassMap(Value operand) {
        if(operand instanceof Instruction) {
            Instruction inst = (Instruction) operand;
            if (inst.parent != func) {
                return instances.get(inst.parent).classMap.get(inst);
            } else {
                return classMap.get(operand);
            }
        } else {
            return classMap.get(operand);
        }
    }

    public void iterCall(CallHandler handler) {
        for (Instruction inst: func.insts()) {
            if (inst instanceof Phi) {
                // TODO handle Phi for classes
                for (Use use: inst.operands) {
                    Value val = use.value;
                    if (classMap.containsKey(val)) {
                        logger.error("TODO handle Phi for jclass.");
                    }
                }
            }
            if (!(inst instanceof Call)) {
                continue;
            }
            Call call = (Call)inst;
            if (call.target == null) {
                continue;
            }
            handler.handle(call);
        }
    }

    private interface CallHandler {
        void handle(Call call);
    }
}
