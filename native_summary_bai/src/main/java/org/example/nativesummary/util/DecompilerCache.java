package org.example.nativesummary.util;

import ghidra.app.script.GhidraState;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */
public class DecompilerCache {
    protected DecompilerHelper helper;
    protected Map<Function, HighFunction> cache = new HashMap<>();

    public DecompilerCache(GhidraState state) {
        // init helper
        helper = new DecompilerHelper(state);
    }

    public HighFunction decompileFunction(Function func) {
        if (cache.containsKey(func)) {
            return cache.get(func);
        }
        HighFunction ret = helper.decompileFunction(func);
        if (func != null) {
            cache.put(func, ret);
        }
        return ret;
    }
}
