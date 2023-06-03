package org.example.nativesummary.ir;

import org.example.nativesummary.ir.utils.User;
import org.example.nativesummary.ir.utils.Value;

import java.io.Serializable;
import java.util.StringJoiner;

public abstract class Instruction extends User implements Serializable {
    public Function parent; // 所在函数。当所在函数不是当前函数的时候，意味着引用了JNI_OnLoad

    public String preComments; // 指令前一行放注释
    public String comments; // 指令行末的注释
    public String postComments; // 指令后一行注释

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        String valStr = toValueString();
        if (valStr != null && valStr.length() > 0) {
            b.append(valStr).append(" = ");
        }
        b.append(getOpString());
        StringJoiner sj = new StringJoiner(", ", " ", "");
        operands.forEach(use -> {
            Value val = use.value;
            String str = val.toValueString();
            // handle reference to other function
            if (val instanceof Instruction && ((Instruction) val).parent != parent) {
                assert str.charAt(0) == '%';
                str = "@" + str.substring(1) + "("+ (((Instruction) val).parent).name + ")";
            }
            sj.add(str);
        });
        b.append(sj);
        if (comments != null) {
            b.append("     ; ").append(comments);
        }
        // 处理行前后注释，便于标记分析结果
        String result = b.toString();
        if (preComments != null) {
            // 开头加上 "; ", 换行替换"\n" -> "\n  ; ", 末尾加上"\n  "
            String reped = preComments.replace("\n", "\n  ; ");
            result = "; " + reped + "\n  " + result;
        }
        if (postComments != null) {
            String reped = postComments.replace("\n", "\n  ; ");
            result = result + "\n  ; " + reped;
        }
        return result;
    }

    public String getOpString() {
        return this.getClass().getName();
    }
}
