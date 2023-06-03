package org.example.nativesummary.ir.value;

import org.example.nativesummary.ir.utils.Type;
import org.example.nativesummary.ir.utils.Value;

public class Param extends Value {
    public Param(String n, Type t) {
        name = n;
        type = t;
    }

    @Override
    public String toString() {
        return type.toString() + " " + name;
    }
}
