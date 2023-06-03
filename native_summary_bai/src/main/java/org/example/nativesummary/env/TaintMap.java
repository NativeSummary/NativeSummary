package org.example.nativesummary.env;

import com.bai.util.Logging;
import org.example.nativesummary.util.JNIValue;

import java.util.*;

/**
 *  Map from JNIValue to taint.
 */
public class TaintMap {

    private static int taintId = 0;
    private static final int MAX_TAINT_CNT = 64;
    private static final Map<JNIValue, Integer> taintSourceToIdMap = new HashMap<>();

    /**
     * Reset the maintained relationship
     */
    public static void reset() {
        taintId = 0;
        taintSourceToIdMap.clear();
    }

    protected static int getTaintId(JNIValue jv) {
        if (taintId >= MAX_TAINT_CNT) {
            Logging.error("Taint id number reach " + MAX_TAINT_CNT
                    + "this may lead to false positive.");
            taintId = taintId % MAX_TAINT_CNT;
            return 0; //
        }
        Integer id = taintSourceToIdMap.get(jv);
        if (id != null) {
            return id;
        }
        taintSourceToIdMap.put(jv, taintId);
        id = taintId;
        taintId++;
        return id;
    }

    /**
     * Get the corresponding taint sources for a given taint bitmap
     * @param taints A given taint bitmap
     * @return A list of corresponding taint sources
     */
    public static List<JNIValue> getTaintSourceList(long taints) {
        ArrayList<JNIValue> res = new ArrayList<>();
        for (Map.Entry<JNIValue, Integer> entry : taintSourceToIdMap.entrySet()) {
            int taintId = entry.getValue();
            if (((taints >>> taintId) & 1) == 1) {
                res.add(entry.getKey());
            }
        }
        return res;
    }

    public static long getTaints(JNIValue jv) {
        return 1L << getTaintId(jv);
    }

    public static boolean isNewTaint(long taint) {
        if (taintId == 0) return false;
        if (taint == (1L << (taintId-1))) {
            return true;
        }
        return false;
    }

    /**
     * Get a taint bitmap for a taint source with a specific taint id
     * @param taintId Taint id for an existing taint source
     * @return Taint bitmap for the given taint id
     */
    public static long getTaints(int taintId) {
        return 1L << taintId;
    }

}
