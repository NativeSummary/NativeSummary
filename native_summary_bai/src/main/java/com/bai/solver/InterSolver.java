package com.bai.solver;

import com.bai.env.*;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;
import org.example.nativesummary.util.MyGlobalState;

/**
 * The class for interprocedural analysis.
 */
public class InterSolver {

    private Function entry;
    private boolean isMain;

    /**
     * Constructor for InterSolver
     * @param entry The start point function for interprocedural analysis
     * @param isMain The flag to indicate whether the entry is conventional "main" function
     */
    public InterSolver(Function entry, boolean isMain) {
        this.entry = entry;
        this.isMain = isMain;
    }


    /**
     * The driver function for the interprocedural analysis  
     */
    public void run() {
        Context mainContext = Context.getEntryContext(entry);

        // is JNI_OnLoad, then set onLoadContext
        if (MyGlobalState.currentJNI.equals(MyGlobalState.onLoad)) {
            MyGlobalState.onLoadContext = mainContext;
        }

        AbsEnv e = MyGlobalState.onLoadEnv == null ? new AbsEnv() : new AbsEnv(MyGlobalState.onLoadEnv);

        mainContext.initContext(e, true);
        int timeout = GlobalState.config.getTimeout();
        if (timeout < 0) {
            Context.mainLoop(mainContext);
        } else {
            Context.mainLoopTimeout(mainContext, timeout);
        }
    }

}