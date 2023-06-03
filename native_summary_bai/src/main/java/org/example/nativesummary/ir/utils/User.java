package org.example.nativesummary.ir.utils;

import java.util.ArrayList;
import java.util.List;

public class User extends Value {
    public List<Use> operands = new ArrayList<>();

    public void replaceUseWith(Use oldu, Use newu) {
        int ind = operands.indexOf(oldu);
        assert ind != -1;
        operands.set(ind, newu);
    }

    public void removeAllOperands() {
        removeAllOperandUseFromValue();
        operands.clear();
    }

    public void removeAllOperandUseFromValue() {
        for (Use u: operands) {
            assert u.user == this;
            u.value.removeUse(u);
        }
    }

//    public void replaceUseWith(Use oldu, Use newu) {
//        int ind = oprands.indexOf(oldu);
//        assert ind != -1;
//        oprands.set(ind, newu);
//    }
}
