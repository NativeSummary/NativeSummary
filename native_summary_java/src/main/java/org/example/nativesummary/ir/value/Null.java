package org.example.nativesummary.ir.value;

import org.example.nativesummary.ir.utils.Constant;

public final class Null extends Constant {
    public static Null instance = new Null();

    @Override
    public String toValueString() {
        return "null";
    }

    @Override
    public boolean equals(Object o) {
        return this == o || o instanceof Null;
    }

    @Override
    public int hashCode() {
        return Null.class.hashCode();
    }
}
