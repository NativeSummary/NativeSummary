package org.example.nativesummary.jimplebuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.example.nativesummary.SecondRepacker.SigCollector;
import org.example.nativesummary.ir.Function;
import org.example.nativesummary.ir.Module;
import org.example.nativesummary.ir.NumValueNamer;

public class Context {
    private static final Logger logger = LoggerFactory.getLogger(Context.class);
    Module m;
    String summaryFolder;
    AuxMethodManager mmgr;

    boolean isDebugLower = false;
    boolean isDebugType = false;
    boolean isDebugJimple = false;
    public Context(Module main, String summaryFolder) {
        m = main;
        this.summaryFolder = summaryFolder;
        mmgr = new AuxMethodManager();
    }

    public SigCollector doAnalysis(List<org.example.nativesummary.ir.Module> summaries, String apkPath, String platformDir) {
        ExternalFuncLoweringEarly.process(m, false);
        new NumValueNamer().visitModule(m);
        if (isDebugLower) {
            Path path = Paths.get(summaryFolder, "00-lowered.summary.ll");
            logger.info("Output typed IR to "+path.toString());
            try {
                Files.write(path, m.toString().getBytes());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        PhiMerger.process(m);
        TypeAnalysis.process(m, mmgr);
        // print ir after type analysis
        if (isDebugType) {
            Path path = Paths.get(summaryFolder, "01-typed.summary.ll");
            logger.info("Output typed IR to "+path.toString());
            try {
                Files.write(path, m.toString().getBytes());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        MethodBuilder b = new MethodBuilder(m, mmgr, isDebugJimple);
        List<Function> sigs= b.patchSoot();
        if (isDebugJimple) {
            Path path = Paths.get(summaryFolder, "02-built-bodies.jimple");
            logger.info("Output jimple to "+path.toString());
            try {
                Files.write(path, b.jimpleDebugOutput.getBytes());
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        SigCollector ret = b.repackedNative;
        // NativeSummaryAux 
        if (mmgr.hasMainClass()) {
            ret.addAuxClass(mmgr.getMain());
        }
        if (mmgr.hasNativeFuncClass()) {
            ret.addAuxClass(mmgr.getNativeFuncClass());
        }
        return ret;
    }

    public AuxMethodManager getmmgr() {
        return mmgr;
    }

    public void setDebugLower() {
        isDebugLower = true;
    }
    public void setDebugType() {
        isDebugType = true;
    }
    public void setDebugJimple() {
        isDebugJimple = true;
    }
}
