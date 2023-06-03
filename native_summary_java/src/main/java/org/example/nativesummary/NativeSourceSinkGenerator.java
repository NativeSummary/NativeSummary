package org.example.nativesummary;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParserException;

import soot.G;
import soot.Main;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.options.Options;

public class NativeSourceSinkGenerator {
    private static final Logger logger = LoggerFactory.getLogger(APKRepacker.class);
    // public boolean forceAndroidJar;
    public String apkFileLocation;
    public String platformDir;

    NativeSourceSinkGenerator(String apkFileLocation, String platformDir) {
        this.apkFileLocation = apkFileLocation;
        this.platformDir = platformDir;
    }

    public void excludeAndroidLibs() {
        Options options = Options.v();
        // explicitly include packages for shorter runtime:
        List<String> excludeList = new LinkedList<String>();
        excludeList.add("java.*");
        excludeList.add("javax.*");

        excludeList.add("sun.*");

        // exclude classes of android.* will cause layout class cannot be
        // loaded for layout file based callback analysis.

        // 2020-07-26 (SA): added back the exclusion, because removing it breaks
        // calls to Android SDK stubs. We need a proper test case for the layout
        // file issue and then see how to deal with it.
        excludeList.add("android.*");
        excludeList.add("androidx.*");

        excludeList.add("org.apache.*");
        excludeList.add("org.eclipse.*");
        excludeList.add("soot.*");
        options.set_exclude(excludeList);
        Options.v().set_no_bodies_for_excluded(true);
    }

    /**
     * Builds the classpath for this analysis
     * 
     * @return The classpath to be used for the taint analysis
     */
    private String getClasspath() {
        // final String androidJar = config.getAnalysisFileConfig().getAndroidPlatformDir();
        // final String apkFileLocation = config.getAnalysisFileConfig().getTargetAPKFile();
        // final String additionalClasspath = config.getAnalysisFileConfig().getAdditionalClasspath();

        // String classpath = forceAndroidJar ? androidJar : Scene.v().getAndroidJarPath(androidJar, apkFileLocation);
        String classpath = Scene.v().getAndroidJarPath(platformDir, apkFileLocation);
        // if (additionalClasspath != null && !additionalClasspath.isEmpty())
        // 	classpath += File.pathSeparator + additionalClasspath;
        logger.debug("soot classpath: " + classpath);
        return classpath;
    }

    private String getPackageName() {
        String packageName = null;
        try {
            ProcessManifest manifest = new ProcessManifest(apkFileLocation);
            packageName = manifest.getPackageName();
            manifest.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (XmlPullParserException e) {
            e.printStackTrace();
        }
        return packageName;
    }

    /**
     * filter by first two parts of apk package name.
     * @return
     */
    private String getFilterPrefix() {
        String packageName = getPackageName();
        if (packageName != null) {
            String[] parts = packageName.split("\\.");
            if (parts.length >= 2) {
                return parts[0] + "." + parts[1];
            }
        }
        return null;
    }

    /**
     * Only load APK class, so that output can be as identical as original.
     * based on soot.jimple.infoflow.android.SetupApplication
     */
    public void initializeSoot() {
        logger.info("Initializing Soot...");

        // final String androidJar = config.getAnalysisFileConfig().getAndroidPlatformDir();
        // final String apkFileLocation = config.getAnalysisFileConfig().getTargetAPKFile();

        // Clean up any old Soot instance we may have
        G.reset();

        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_allow_phantom_refs(true);
        // Options.v().set_output_format(Options.output_format_dex);
        // Options.v().set_whole_program(true);
        Options.v().set_process_dir(Collections.singletonList(apkFileLocation));
        // if (forceAndroidJar)
        // 	Options.v().set_force_android_jar(androidJar);
        // else
        Options.v().set_android_jars(platformDir);
        Options.v().set_src_prec(Options.src_prec_apk);
        // Options.v().set_src_prec(Options.src_prec_apk);
        // Options.v().set_keep_offset(true);
        // Options.v().set_keep_line_number(true);
        // Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
        Options.v().set_process_multiple_dex(true);
        // Options.v().set_ignore_resolution_errors(true);

        // Set soot phase option if original names should be used
        // Options.v().setPhaseOption("jb", "use-original-names:true");

        // Set the Soot configuration options. Note that this will needs to be
        // done before we compute the classpath.
        // if (sootConfig != null)
        //     sootConfig.setSootOptions(Options.v(), config);
        // TODO
        excludeAndroidLibs();

        // Options.v().set_soot_classpath(getClasspath());
        Main.v().autoSetOptions();
        // configureCallgraph();

        // Load whatever we need
        logger.info("Loading dex files...");
        Scene.v().loadNecessaryClasses();

        // Make sure that we have valid Jimple bodies
        PackManager.v().getPack("wjpp").apply();
    }
    public void output(String path, boolean packageNameFilter) {
        String prefix = null;
        if (packageNameFilter) {
            prefix = getFilterPrefix();
        }
        List<String> lines = new ArrayList<>();
        for (SootClass clz : Scene.v().getClasses()) {
            if (!clz.isApplicationClass()) {
                continue;
            }
            // filter by first two parts of apk package name.
            if (packageNameFilter && prefix != null) {
                if (!clz.getName().startsWith(prefix)) { continue; }
            }
            for (SootMethod method: clz.getMethods()) {
                if (!method.isNative()) {
                    continue;
                }
                lines.add(method.getSignature()+" -> _BOTH_");
            }
        }
        // print lines to target path
        System.out.print("obj");
    }
    public static void main(String[] args) throws JsonIOException, JsonSyntaxException, FileNotFoundException {
        // Work In Progress!!!!
        logger.error("NativeSourceSinkGenerator is still not useable.");
        logger.info("args: " + args.toString());
        NativeSourceSinkGenerator r = new NativeSourceSinkGenerator(args[0], args[1]);
        r.initializeSoot();
        r.output(args[2], true);
    }
}
