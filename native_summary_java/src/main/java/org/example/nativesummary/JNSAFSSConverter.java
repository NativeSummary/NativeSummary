package org.example.nativesummary;

import java.io.FileWriter;
import java.util.StringJoiner;

import soot.ArrayType;
import soot.BooleanType;
import soot.ByteType;
import soot.CharType;
import soot.DoubleType;
import soot.FloatType;
import soot.IntType;
import soot.LongType;
import soot.RefType;
import soot.ShortType;
import soot.Type;
import soot.jimple.infoflow.android.data.AndroidMethod;
import soot.jimple.infoflow.android.data.parsers.PermissionMethodParser;
import soot.jimple.infoflow.data.SootMethodAndClass;
import soot.jimple.infoflow.sourcesSinks.definitions.ISourceSinkDefinition;
import soot.jimple.infoflow.sourcesSinks.definitions.MethodSourceSinkDefinition;
import soot.jimple.infoflow.sourcesSinks.definitions.SourceSinkType;
import soot.toDex.SootToDexUtils;

public class JNSAFSSConverter {
    public static void main(String[] args) throws Exception {
        String path = "F:\\ss_taintbench.txt";//args[0];
        String out_path = "F:\\jnsaf_taintbench.txt";//args[0];
        FileWriter fw = new FileWriter(out_path);
        PermissionMethodParser parser = PermissionMethodParser.fromFile(path);
        StringJoiner result = new StringJoiner("\n");
        int count = 0;
        for(ISourceSinkDefinition def: parser.getAllMethods()) {
            if (!(def instanceof MethodSourceSinkDefinition)) {
                System.err.println("non method ss!");
                System.exit(-1);
            }
            MethodSourceSinkDefinition def1 = (MethodSourceSinkDefinition) def;
            SootMethodAndClass mth = def1.getMethod();
            if (!(mth instanceof AndroidMethod)) {
                System.err.println("not AndroidMethod!");
                System.exit(-1);
            }
            AndroidMethod mth1 = (AndroidMethod) mth;
            StringBuilder sb = handleAM(mth1);
            if (mth1.getSourceSinkType() != SourceSinkType.Undefined)
                sb.append(" ->");
            if (mth1.getSourceSinkType() == SourceSinkType.Source)
                sb.append(" _SOURCE_");
            else if (mth1.getSourceSinkType() == SourceSinkType.Sink)
                sb.append(" _SINK_ ");
            else if (mth1.getSourceSinkType() == SourceSinkType.Neither)
                sb.append(" _NONE_");
            else if (mth1.getSourceSinkType() == SourceSinkType.Both) {
                // sb.append(" _BOTH_");
                StringBuilder sb2 = new StringBuilder();
                sb2.append(sb.toString()).append(" _SOURCE_\n");
                sb2.append(sb.toString()).append(" _SINK_");
                sb = sb2;
            }
            System.out.println(sb.toString());
            result.add(sb.toString());
            count += 1;
        }
        fw.write(result.toString());
        fw.close();
    }

    private static StringBuilder handleAM(AndroidMethod mth1) {
        StringBuilder sb = new StringBuilder();
        sb.append(SootToDexUtils.getDexClassName(mth1.getClassName()));
        sb.append('.');
        sb.append(mth1.getMethodName());
        sb.append(":(");
        for (String param: mth1.getParameters()) {
            sb.append(handleType(param));  // todo
        }
        sb.append(')');
        sb.append(handleType(mth1.getReturnType())); // todo
        return sb;
    }

    private static String handleType(String param) {
        if (param.equals("void")) {
            return "V";
        }
        Type t = getTypeFromString(param);
        return SootToDexUtils.getDexTypeDescriptor(t);
    }

    public static Type getTypeFromString(String type) {
		if (type == null || type.isEmpty())
			return null;

		// Reduce arrays
		int numDimensions = 0;
		while (type.endsWith("[]")) {
			numDimensions++;
			type = type.substring(0, type.length() - 2);
		}

		// Generate the target type
		final Type t;
		if (type.equals("int"))
			t = IntType.v();
		else if (type.equals("long"))
			t = LongType.v();
		else if (type.equals("float"))
			t = FloatType.v();
		else if (type.equals("double"))
			t = DoubleType.v();
		else if (type.equals("boolean"))
			t = BooleanType.v();
		else if (type.equals("char"))
			t = CharType.v();
		else if (type.equals("short"))
			t = ShortType.v();
		else if (type.equals("byte"))
			t = ByteType.v();
		else {
            t = RefType.v(type);
		}

		if (numDimensions == 0)
			return t;
		return ArrayType.v(t, numDimensions);
	}

}
