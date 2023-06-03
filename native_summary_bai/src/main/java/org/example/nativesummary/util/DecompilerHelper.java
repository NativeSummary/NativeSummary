package org.example.nativesummary.util;

import com.bai.util.Logging;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraState;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

/**
 * https://github.com/nccgroup/ghostrings/blob/main/ghidra_scripts/PrintHighPCode.java
 * 由于内部还是用了GlobalState和Logger，所以虽然放在MyGlobalState里，其实本质上还是依赖于每次的GlobalState。
 */
public class DecompilerHelper {

    // Groups / root actions: firstpass, register, paramid, normalize,
    // jumptable, decompile
    public static final String[] SIMPLIFICATION_STYLES = new String[] {
            "decompile",
            "jumptable",
            "normalize",
            "paramid",
            "register",
            "firstpass"
    };

    public DecompInterface decompIfc;

    public static DecompInterface setUpDecompiler(GhidraState state, String simplificationStyle) {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options = new DecompileOptions();

        PluginTool tool = state.getTool();
        if (tool != null) {
            OptionsService service = tool.getService(OptionsService.class);
            if (service != null) {
                ToolOptions opt = service.getOptions("Decompiler");
                options.grabFromToolAndProgram(null, opt, state.getCurrentProgram());
            }
        }

        options.setEliminateUnreachable(false);

        decompInterface.setOptions(options);
        decompInterface.toggleCCode(false);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.toggleParamMeasures(false);
        decompInterface.setSimplificationStyle(simplificationStyle);

        return decompInterface;
    }

    public DecompilerHelper(GhidraState state) {
        decompIfc = setUpDecompiler(state, SIMPLIFICATION_STYLES[0]);
        if (!decompIfc.openProgram(state.getCurrentProgram())) {
            final String lastMsg = decompIfc.getLastMessage();

            decompIfc.stopProcess();
            if (lastMsg != null) {
                throw new RuntimeException("Decompiler could not open program: "+lastMsg);
            } else {
                throw new RuntimeException("Decompiler could not open program.");
            }
        }
    }

    public HighFunction decompileFunction(Function func) {
        HighFunction highFunc = null;

        TaskMonitor monitor;
//        if (GlobalState.config.isGUI()) {
//            monitor = GlobalState.flatAPI.getMonitor();
//        } else {
            monitor = TaskMonitor.DUMMY;
//        }

        try {
            DecompileResults results = decompIfc.decompileFunction(
                    func,
                    decompIfc.getOptions().getDefaultTimeout(),
                    monitor);

            // Docs suggest calling this after every decompileFunction call
            decompIfc.flushCache();

            highFunc = results.getHighFunction();

            String decompError = results.getErrorMessage();
            if (decompError != null && decompError.length() > 0) {
                Logging.error(String.format("Decompiler error for %s: %s\n", Utils.funcNameAndAddr(func),
                        decompError.trim()));
            }

            if (!results.decompileCompleted()) {
                Logging.error(String.format("Decompilation not completed for %s\n", Utils.funcNameAndAddr(func)));
                return null;
            }
        } catch (Exception e) {
            Logging.error("Decompiler exception:");
            e.printStackTrace();
        }

        return highFunc;
    }
}
