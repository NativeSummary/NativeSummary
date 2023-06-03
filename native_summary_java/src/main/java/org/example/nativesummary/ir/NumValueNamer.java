package org.example.nativesummary.ir;

import java.util.HashMap;
import java.util.Map;

import org.example.nativesummary.ir.utils.Constant;
import org.example.nativesummary.ir.utils.Type;
import org.example.nativesummary.ir.utils.Value;

public class NumValueNamer {
    long count = 0;

    public void visitModule(Module m) {
        m.funcs.forEach(this::visitFunc);
    }

    public void visitFunc(Function f) {
        count = 0;
        f.params.forEach(this::visitValue);
        f.insts().forEach(this::visitInst);
    }

    public void visitInst(Instruction i) {
        visitValue(i);
        i.getUses().forEach(use -> visitValue(use.value));
    }

    public boolean isTempName(String name) {
        return name == null || name.matches("[0-9]+");
    }

    public Map<Value, Boolean> visited = new HashMap<>();

    public void visitValue(Value i) {
        if ((i.type == null || i.type.ty == null || !i.type.ty.equals(Type.BaseType.VOID)) && isTempName(i.name) && (!(i instanceof Constant))) {
            // 当后面的指令引用前面指令的返回值的时候，会再次访问前面的指令。
            if (!visited.containsKey(i)) {
                i.name = String.valueOf(count++);
                visited.put(i, true);
            }
        }
    }
}
