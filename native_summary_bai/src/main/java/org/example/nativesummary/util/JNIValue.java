package org.example.nativesummary.util;

import com.bai.env.Context;
import com.bai.util.GlobalState;

import java.util.Arrays;

public class JNIValue {
    public static final String PARAM_PREFIX = "Param";
    public long[] callstring = new long[GlobalState.config.getCallStringK()];
    // TODO add callFuncs for better printing
    public String apiName;
    public long callsite;
    public JNIValue(Context ctx, String apiName, long callsite) {
        if (ctx != null) {
            System.arraycopy(ctx.getCallString(), 0, this.callstring, 0, GlobalState.config.getCallStringK());
        }
        this.apiName = apiName;
        this.callsite = callsite;
    }

    public JNIValue(long index) {
        this.apiName = PARAM_PREFIX + String.valueOf(index);
    }

    public boolean isParamValue() {
        return apiName.startsWith(JNIValue.PARAM_PREFIX);
    }
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        JNIValue jniValue = (JNIValue) o;

        if (callsite != jniValue.callsite) return false;
        if (!Arrays.equals(callstring, jniValue.callstring)) return false;
        return apiName.equals(jniValue.apiName);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(callstring);
        result = 31 * result + apiName.hashCode();
        result = 31 * result + (int) (callsite ^ (callsite >>> 32));
        return result;
    }

    public int getParamInd() {
        return Integer.parseInt(apiName.substring(JNIValue.PARAM_PREFIX.length()));
    }
}
