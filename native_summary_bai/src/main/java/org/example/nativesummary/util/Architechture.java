package org.example.nativesummary.util;

import com.bai.env.ALoc;

// TODO
public class Architechture {
    // ghidra_10.1.2_PUBLIC\Ghidra\Processors\ARM\data\languages\ARM.sinc
    // https://github.com/ARM-software/abi-aa/blob/60a8eb8c55e999d74dac5e368fc9d7e36e38dda4/aapcs32/aapcs32.rst
    // todo set -> pair
    // 0x20 - r0, 0x30 - r4, 0x4c - r11, 0x4f - r11 ends
    public static boolean isArm32SavedRegister(ALoc aloc) {
        if (!aloc.getRegion().isReg()) {
            return false;
        }
        long start = aloc.getBegin();
        long end = start + aloc.getLen();
        // r9 detected
        if (start == 0x44 && end == 0x48) {
            return false;
        }
        // r4-r11
        if (start >= 0x30 && end <= 0x50) {
            return true;
        }
        return false;
    }

    // C:\Users\xxx\my_programs\ghidra_10.1.2_PUBLIC\Ghidra\Processors\AARCH64\data\languages\AARCH64instructions.sinc
    // SAVE r19-r29
    // 0x4000 - x0, 0x4098 - x19, 0x40F0 - x30
    public static boolean isAArch64SavedRegister(ALoc aloc) {
        if (!aloc.getRegion().isReg()) {
            return false;
        }
        long start = aloc.getBegin();
        long end = start + aloc.getLen();
        // r19-r29
        if (start >= 0x4098 && end <= 0x40F0) {
            return true;
        }
        return false;
    }
}
