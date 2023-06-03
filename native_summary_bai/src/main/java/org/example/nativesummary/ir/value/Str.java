package org.example.nativesummary.ir.value;

import org.example.nativesummary.ir.utils.Constant;
import org.example.nativesummary.ir.utils.Type;

public class Str extends Constant {
    public String val;
    public static Str of(String s) {
        Str ret = new Str();
        ret.val = s;
        ret.type = Type.CSTR;
        return ret;
    }

    @Override
    public String toValueString() {
        return type.toString()+" \""+val+"\"";
    }
}
