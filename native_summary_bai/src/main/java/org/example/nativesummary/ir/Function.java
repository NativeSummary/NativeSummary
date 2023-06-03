package org.example.nativesummary.ir;

import org.example.nativesummary.ir.inst.Call;
import org.example.nativesummary.ir.utils.Type;
import org.example.nativesummary.ir.value.Param;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.StringJoiner;

public class Function implements Serializable {
    public String clazz;
    public String name;
    public String signature;
    // TODO basicblock and control flow
    // null for declaration
    List<Instruction> insts = new ArrayList<>();
    // parsed from signature
    public List<Param> params = new ArrayList<>();
    public Type returnType;
    public String comment;
    public Call registeredBy;

    void setParent(Instruction inst) {
        if (inst.parent == null) {
            inst.parent = this;
        }
    }

    public boolean add(Instruction inst) {
        setParent(inst);
        return insts.add(inst);
    }

    public boolean addAll(Collection<? extends Instruction> insts) {
        for (Instruction inst: insts) {
            setParent(inst);
        }
        return this.insts().addAll(insts);
    }

    public boolean addAll(int index, Collection<? extends Instruction> insts) {
        for (Instruction inst: insts) {
            setParent(inst);
        }
        return this.insts().addAll(index, insts);
    }

    public List<Instruction> insts() {
        return insts;
    }

    @Override
    public String toString() {
        String declare = insts != null ? "define" : "declare";
        String processedClazz;
        if (clazz == null) {
            processedClazz = "";
        } else if (clazz.charAt(0) == 'L') {
            processedClazz = clazz.substring(1, clazz.length()-1);
            processedClazz = processedClazz.replace('/', '.');
        } else {
            processedClazz = clazz;
        }

        StringBuilder sb = new StringBuilder(String.format("%s %s @%s.%s", declare, returnType, processedClazz, name));
        StringJoiner sj = new StringJoiner(", ", "(", ")");
        for (Param p: params) {
            sj.add(p.toString());
        }
        sb.append(sj.toString()).append("{");
        if (registeredBy != null) {
            sb.append(" ; dynreg");
        }
        sb.append("\n");
        for (Instruction i: insts) {
            sb.append("  ").append(i.toString()).append("\n");
        }
        sb.append("}");
        if (comment != null) {
            sb.insert(0, "; " + comment + "\n");
        }
        return sb.toString();
    }
}
