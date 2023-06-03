package org.example.nativesummary.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.3.3
public class JNIDescriptorParser {
    public String error;
    String desc;
    int index;
    public JNIDescriptorParser(String desc) {
        this.desc = desc;
    }

    public String advance() {
        if (index >= desc.length()) return null;
        String token = lexicalTokenAt(index, desc);
        if (token != null) {
            index += token.length();
        }
        return token;
    }

    public List<String> parse() {
        ArrayList<String> tys = new ArrayList<>();
        index = 0;
        String token;
        // parse (
        token = advance();
        if (token == null || !token.equals("(")) {
            error = String.format("expect '(', receive %s", token);
            return null;
        }
        while(true) {
            token = advance();
            if (token == null) {
                error = "expect ')' but not found.";
                return null;
            }
            if (token.equals(")")) { break; }
            String ty = fullTypeOf(token);
            if (ty == null) {
                error = "unable to decode "+token;
                return null;
            }
            if (ty.equals("void")) {
                error = "void type in parameter";
                return null;
            }
            tys.add(ty);
        }
        return tys;
    }

    public String parseRet() {
        String token = advance();
        String ty = fullTypeOf(token);
        if (token == null || ty == null) {
            error = "Expect return type, but get "+token;
            return null;
        }
        return ty;
    }

    public static String lexicalTokenAt(int index, String desc) {
        if (desc == null) {return null;}
        char c = desc.charAt(index);
        switch (c) {
            case '(':
            case ')':
            case 'B':
            case 'C':
            case 'D':
            case 'F':
            case 'I':
            case 'J':
            case 'S':
            case 'Z':
            case 'V':
                return String.valueOf(c);
            case 'L':
                int index1;
                index1 = desc.indexOf(';', index);
                return desc.substring(index, index1+1);
            case '[':
                return "["+lexicalTokenAt(index+1, desc);
            default:
                return null;
        }
    }

    public static Map<Character, String> baseTypes = buildBaseTypes();
    public static String fullTypeOf(String ty) {
        return fullTypeOf(ty, false);
    }
    public static String fullTypeOf(String ty, boolean noAddArray) {
        if (ty == null) {return null;}
        char c = ty.charAt(0);
        switch (c) {
            case 'B':
            case 'C':
            case 'D':
            case 'F':
            case 'I':
            case 'J':
            case 'S':
            case 'Z':
            case 'V':
                assert ty.length() == 1;
                return baseTypes.get(c);
            case '[':
                if (noAddArray) {
                    return fullTypeOf(ty.substring(1), noAddArray);
                } else {
                    String val = fullTypeOf(ty.substring(1), true);
                    if (val.equals("jstring")) { val = "jobject"; } // no jstringArray
                    return val + "Array";
                }
            case 'L':
                if (ty.equals("Ljava/lang/String;")) { return "jstring"; }
                return "jobject";
            default:
                return null;
        }
    }

    public static Map<Character, String> buildBaseTypes() {
        Map<Character, String> ret = new HashMap<>();
        ret.put('B', "jbyte");
        ret.put('C', "jchar");
        ret.put('D', "jdouble");
        ret.put('F', "jfloat");
        ret.put('I', "jint");
        ret.put('J', "jlong");
        ret.put('S', "jshort");
        ret.put('Z', "jboolean");
        ret.put('V', "void");
        return ret;
    }
}
