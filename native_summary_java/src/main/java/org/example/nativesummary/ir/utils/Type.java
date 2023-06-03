package org.example.nativesummary.ir.utils;

import java.io.Serializable;

public class Type implements Serializable {
    public static final Type CSTR = new Type(BaseType.CHAR).setPtr();
    public static final Type LONG = new Type(BaseType.LONG);

    public enum BaseType {
        VOID,
        INT,
        SHORT,
        LONG,
        BYTE,
        CHAR,
        FLOAT,
        DOUBLE,
        BOOL,
        NULL,
        ARRAY,
        OBJECT,
    };
    public BaseType ty;
    int pointerLevel = 0;
//    List<Integer> dims = new ArrayList<>();
    String typedef;

    public Type(BaseType t) {
        ty = t;
    }

    public Type setPtr() {
        pointerLevel += 1;
        return this;
    }

    public Type setTypeDef(String s) {
        typedef = s;
        return this;
    }

    @Override
    public String toString() {
        if (typedef != null) {
            return typedef;
        } else {
            return ty.toString().toLowerCase() + new String(new char[pointerLevel]).replace('\0', '*');
        }
    }
}
