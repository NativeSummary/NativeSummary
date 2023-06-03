package org.example.nativesummary.jimplebuilder;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.example.nativesummary.ir.Function;
import org.example.nativesummary.ir.Instruction;
import org.example.nativesummary.ir.Module;
import org.example.nativesummary.ir.inst.Phi;
import org.example.nativesummary.ir.utils.Use;
import org.example.nativesummary.ir.utils.Value;

// 窥孔优化，如果后一个Phi指令引用了前面的Phi指令，且前面的Phi指令只有一个这一个User，
// 则可以把前面的Phi指令合并到后面的里。
// 简化单个Phi的值。合并冗余的null或者top，
public class PhiMerger {

    public static void process(Module summary) {
        for (Function func: summary.funcs) {
            for(int i=0;i<func.insts().size();i++) {
                Instruction inst = func.insts().get(i);
                List<Instruction> toRemove = visitInst(inst);
                if (toRemove != null) {
                    func.insts().removeAll(toRemove);
                    i -= toRemove.size();
                }
            }
        }
    }

    static List<Instruction> visitInst(Instruction inst) {
        if (!(inst instanceof Phi)) {
            return null;
        }
        List<Instruction> ret = new ArrayList<>();
        for (Use use: inst.operands) {
            if (!(use.value instanceof Phi)) {
                continue;
            }
            // 两个phi相互引用
            Phi prev = (Phi)use.value;
            // prev仅有一个user
            if (prev.getUses().size() != 1) {
                continue;
            }
            // 合并两个Phi
            Set<Value> vals = new HashSet<>();
            List<Use> ops = new ArrayList<>();
            for (Use u: inst.operands) {
                if (u.value == prev) {
                    continue;
                }
                if (vals.contains(u.value)) continue;
                vals.add(u.value);
                ops.add(u);
            }
            for (Use u: prev.operands) {
                if (vals.contains(u.value)) continue;
                vals.add(u.value);
                ops.add(new Use(inst, u.value));
            }
            inst.operands = ops;
            prev.removeAllOperands();
            ret.add(prev);
        }
        
        Phi phi = (Phi) inst;
        // remove duplicated value
        for (Use u: dedupPhiOps(phi.operands)) {
            u.value.removeUse(u);
            phi.operands.remove(u);
        }
        // if current Phi has only one operand, replace it.
        if (phi.operands.size() <= 1) {
            ret.add(phi);
            if (phi.operands.size() == 1) {
                Value val = phi.operands.get(0).value;
                phi.replaceAllUseWith(val);
                phi.removeAllOperands();
            }
        }
        return ret;
    }

    // TODO 2022年11月18日 现在在BodyBuilder里面已经会去重了，要不要去掉。
    static List<Use> dedupPhiOps(List<Use> ops) {
        // 使用一个Set过滤重复的Null和Top，依赖于任何Null和Top是相互equal的。
        Set<Value> valSet = new HashSet<>();
        List<Use> uses = new ArrayList<>();
        List<Use> usesToRemove = new ArrayList<>();
        for (Use u: ops) {
            if (!valSet.contains(u.value)) {
                valSet.add(u.value);
                uses.add(u);
            } else {
                usesToRemove.add(u);
            }
        }
        return usesToRemove;
    }
}
