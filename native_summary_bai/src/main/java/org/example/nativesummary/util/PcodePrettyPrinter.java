package org.example.nativesummary.util;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeTranslator;

public class PcodePrettyPrinter {
    protected VarnodeTranslator trans;

    public PcodePrettyPrinter(Program program) {
        trans = new VarnodeTranslator(program);
    }

    public String printOneWithAddr(PcodeOpAST pcodeOpAST) {
        return String.format("0x%x:0x%02x\t%s\n",
                pcodeOpAST.getSeqnum().getTarget().getOffset(),
                pcodeOpAST.getSeqnum().getTime(), printOne(pcodeOpAST));
    }

    public String printOne(PcodeOpAST pcode) {
        String s;
        Varnode output =  pcode.getOutput();
        if (output != null) {
            s = printVarnode(output);
        }
        else {
            s = " --- ";
        }
        s += " " + pcode.getMnemonic() + " ";
        Varnode[] input = pcode.getInputs();
        for (int i = 0; i < input.length; i++) {
            if (input[i] == null) {
                s += "null";
            }
            else {
                s += printVarnode(input[i]);
            }

            if (i < input.length - 1) {
                s += " , ";
            }
        }
        return s;
    }

    public String printVarnode(Varnode rvnode) {
        if (rvnode == null) {
            return "<null>";
        }
        if (rvnode.isRegister()) {
            Register reg = this.trans.getRegister(rvnode);
            return (reg == null ? "<bad reg " + rvnode.getOffset() + ">" : reg.getName());
        }
        return rvnode.toString();
    }
}
