package org.example.nativesummary.ir.inst;

import org.example.nativesummary.ir.Instruction;

public class Phi extends Instruction {
    @Override
    public String getOpString() {
        return "phi";
    }
}
