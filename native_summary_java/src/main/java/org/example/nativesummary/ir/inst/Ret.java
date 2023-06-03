package org.example.nativesummary.ir.inst;

import org.example.nativesummary.ir.Instruction;

public class Ret extends Instruction {
    @Override
    public String getOpString() {
        return "ret";
    }
}
