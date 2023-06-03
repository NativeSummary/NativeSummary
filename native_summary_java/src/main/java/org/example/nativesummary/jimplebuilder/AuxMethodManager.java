package org.example.nativesummary.jimplebuilder;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import soot.IntType;
import soot.LongType;
import soot.Modifier;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootField;
import soot.SootMethod;
import soot.Type;

public class AuxMethodManager {
    public static final String mainClassName = "org.example.NativeSummaryAux";
    public static final String nativeClassName = "org.example.NativeSummaryFuncs";
    public static final String opaqueIntName = "opaqueInt";
    public static final String contextName = "context";
    public static final String jniOnLoadName = "JNI_OnLoad";

    public SootClass mainClass;
    public SootClass nativeFuncClass;

	public SootClass getMain() {
        if (hasMainClass()) { return mainClass; }
		SootClass mainClass = Scene.v().getSootClassUnsafe(mainClassName);
		if (mainClass == null || mainClass.isPhantomClass()) {
			mainClass = Scene.v().makeSootClass(mainClassName, Modifier.PUBLIC);
			mainClass.setResolvingLevel(SootClass.BODIES);
            mainClass.setSuperclass(Scene.v().getSootClass("java.lang.Object"));
			Scene.v().addClass(mainClass);
            // First add class to scene, then make it an application class
            // as addClass contains a call to "setLibraryClass"
            mainClass.setApplicationClass();
		}
        this.mainClass = mainClass;
		return mainClass;
	}

    public SootClass getNativeFuncClass() {
        if (nativeFuncClass != null) { return nativeFuncClass; }
		SootClass nativeFuncClass = Scene.v().getSootClassUnsafe(nativeClassName);
		if (nativeFuncClass == null || nativeFuncClass.isPhantomClass()) {
			nativeFuncClass = Scene.v().makeSootClass(nativeClassName, Modifier.PUBLIC);
			nativeFuncClass.setResolvingLevel(SootClass.BODIES);
            nativeFuncClass.setSuperclass(Scene.v().getSootClass("java.lang.Object"));
			Scene.v().addClass(nativeFuncClass);
            // First add class to scene, then make it an application class
            // as addClass contains a call to "setLibraryClass"
            nativeFuncClass.setApplicationClass();
		}
        this.nativeFuncClass = nativeFuncClass;
		return nativeFuncClass;
	}

    public AuxMethodManager() {
        // this.mainClass = getMain();
    }

    // lazy creation, indicate that class is required.
    public boolean hasMainClass() {
        return mainClass != null;
    }
    public boolean hasNativeFuncClass() {
        return nativeFuncClass != null;
    }

    // lazy create
    public SootMethod opaqueInt() {
        SootMethod m = getMain().getMethodByNameUnsafe(opaqueIntName);
        if (m == null) {
            return createOpaqueInt();
        }
        return m;
    }

    protected SootMethod createOpaqueInt() {
        return createMainMth(opaqueIntName, Modifier.PUBLIC | Modifier.STATIC | Modifier.NATIVE, Collections.emptyList(), IntType.v());
    }

    public SootMethod jniOnLoad() {
        SootMethod m = getMain().getMethodByNameUnsafe(jniOnLoadName);
        if (m == null) {
            return createjniOnLoad();
        }
        return m;
    }

    public SootMethod getNativeMth(String name, List<Type> parameterTypes, Type returnType) {
        SootClass n = getNativeFuncClass();
        SootMethod ret = n.getMethodUnsafe(name, parameterTypes, returnType);
        if (ret == null) {
            return createNativeMth(name, parameterTypes, returnType);
        }
        return ret;
    }

    public SootMethod createNativeMth(String name, int modifiers, List<Type> parameterTypes, Type returnType) {
        return createMth(getNativeFuncClass(), name, modifiers, parameterTypes, returnType);
    }

    public SootMethod createNativeMth(String name, List<Type> parameterTypes, Type returnType) {
        return createMth(getNativeFuncClass(), name, Modifier.PUBLIC | Modifier.STATIC | Modifier.NATIVE, parameterTypes, returnType);
    }

    SootMethod createjniOnLoad() {
        return createMainMth(jniOnLoadName, Modifier.PUBLIC | Modifier.STATIC | Modifier.NATIVE, List.of(RefType.v("java.lang.Object")), LongType.v());
    }

    SootMethod createMainMth(String name, int modifiers, List<Type> parameterTypes, Type returnType) {
        return createMth(getMain(), name, modifiers, parameterTypes, returnType);
    }

    SootMethod createMth(SootClass sc, String name, int modifiers, List<Type> parameterTypes, Type returnType) {
        SootMethod m = Scene.v().makeSootMethod(name, parameterTypes, returnType);
        m.setModifiers(modifiers);
        sc.addMethod(m);
        return m;
    }

    SootField createMainFld(String name, Type ty, int modifiers) {
        SootField f = Scene.v().makeSootField(name, ty);
        f.setModifiers(modifiers);
        getMain().addField(f);
        return f;
    }

    public static String[] nonSinks = 
    {"malloc", "free", "clock", "strchr", 
    "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements", "GetIntArrayElements", "GetLongArrayElements", "GetFloatArrayElements", "GetDoubleArrayElements",
    };
    public static final Set<String> nonSinksSet = new HashSet<>(Arrays.asList(nonSinks));
    public String getFlowDroidSinks() {
        if (nativeFuncClass == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (SootMethod m: nativeFuncClass.getMethods()) {
            if (nonSinksSet.contains(m.getName())) {
                continue;
            }
            sb.append(m.getSignature());
            sb.append(" -> _SINK_\n");
        }
        return sb.toString();
    }
    
}
