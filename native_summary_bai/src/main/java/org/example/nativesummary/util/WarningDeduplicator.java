package org.example.nativesummary.util;

import com.bai.util.Logging;
import ghidra.program.model.listing.Function;

import java.util.*;

public class WarningDeduplicator {


    public void reset() {
        outOfRangeWarningMap = new HashSet<>();
        funcsNoModel = new HashSet<>();
        for (StrWarner w: warnsGlob) {
            w.reset();
        }
        for (StrWarner w: warnsPerFunc) {
            w.reset();
        }
    }

    public void onStartOne() {
        for (StrWarner w: warnsPerFunc) {
            w.reset();
        }
    }

    // ============== StrWarner =================
    List<StrWarner> warnsGlob = new ArrayList<>();
    List<StrWarner> warnsPerFunc = new ArrayList<>();
    public static interface Log {
        public void log(String str);
    }
    public class StrWarner {
//        String prefix;
        Set<String> dedup = new HashSet<>();
        Log action;
        public StrWarner(boolean perFunc, Log action) {
//            this.prefix = prefix;
            this.action = action;
            if (perFunc) {
                warnsPerFunc.add(this);
            } else {
                warnsGlob.add(this);
            }
        }

        public void log(String suffix) {
            if (!dedup.contains(suffix)) {
                dedup.add(suffix);
                action.log(suffix);
            }
        }
        public void reset() {dedup.clear();}
    }
    // ============== StrWarner end =================

    // function out of range: current address is not current context function
    public Set<Map.Entry<String, Function>> outOfRangeWarningMap = new HashSet<>();
    public boolean hasWarnedOutOfRange(String s1, Function containing) {
        Map.Entry<String, Function> ent = Map.entry(s1, containing);
        if (outOfRangeWarningMap.contains(ent)) {
            return true;
        } else {
            outOfRangeWarningMap.add(ent);
            return false;
        }
    }

    // no external function model
    Set<String> funcsNoModel = new HashSet<>();
    // deduplicate warning for external model.
    public void warnNoExtModel(String funcName) {
        if (!funcsNoModel.contains(funcName)) {
            funcsNoModel.add(funcName);
            Logging.warn("No external model for " + funcName);
        }
    }

    // Tail call opt detection at some address
    Set<String> tailCallAddr = new HashSet<>();
    public void infoTailCall(String addr) {
        if (!tailCallAddr.contains(addr)) {
            tailCallAddr.add(addr);
            Logging.info("Tail call opt detected at "+addr);
        }
    }

    Set<String> bottomLoaded = new HashSet<>();
    public void infoBottomLoaded(String loc) {
        if (!bottomLoaded.contains(loc)) {
            bottomLoaded.add(loc);
            Logging.debug("Bottom loaded from "+loc);
        }
    }


}
