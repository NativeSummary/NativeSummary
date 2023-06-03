package org.example.nativesummary.ir.utils;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class Value implements Serializable {
    public Type type;
    private List<Use> uses = new ArrayList<>();
    public String name;


    public void addUse(Use use) {
        uses.add(use);
    }

    public List<Use> getUses() {
        return uses;
    }

    public void removeUse(Use use) {
        uses.remove(use);
    }

   public void replaceAllUseWith(Value v) {
        assert v != this;
        for (Use u: uses) {
            assert u.value == this;
            Use newu = new Use(u.user, v);
            u.user.replaceUseWith(u, newu);
        }
    }

    public String toValueString() {
        if (type != null && type.ty != null && type.ty == Type.BaseType.VOID) {
            return null;
        }
        if (name != null) {
            return "%" + name.toString();
        } else {
            return "%?"; // 没有命名
        }
    }
}
