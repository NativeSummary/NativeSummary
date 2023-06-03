package org.example.nativesummary.flowdroidbridge;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.cfg.LibraryClassPatcher;
import soot.jimple.infoflow.ipc.IIPCManager;

public class SetupApplication extends soot.jimple.infoflow.android.SetupApplication {
    private final Logger logger = LoggerFactory.getLogger(getClass());
    @Override
	protected LibraryClassPatcher getLibraryClassPatcher() {
		return new NativePatcher(config.getAnalysisFileConfig().getTargetAPKFile());
	}

    public SetupApplication(String androidJar, String apkFileLocation, IIPCManager ipcManager) {
        super(androidJar, apkFileLocation, ipcManager);
    }

    public SetupApplication(String androidJar, String apkFileLocation) {
        super(androidJar, apkFileLocation);
    }


    public SetupApplication(InfoflowAndroidConfiguration config, IIPCManager ipcManager) {
        super(config, ipcManager);
    }


    public SetupApplication(InfoflowAndroidConfiguration config) {
        super(config);
    }

    // @Override
    // /**
	//  * Runs the data flow analysis.
	//  * 
	//  * @param sourcesAndSinks The sources and sinks of the data flow analysis
	//  * @return The results of the data flow analysis
	//  */
	// public InfoflowResults runInfoflow(ISourceSinkDefinitionProvider sourcesAndSinks) {
    //     InfoflowResults ret;
    //     if (config.getSootIntegrationMode() == SootIntegrationMode.CreateNewInstance) {
	// 		G.reset();
	// 		myInitializeSoot();
    //         config.setSootIntegrationMode(SootIntegrationMode.UseExistingInstance);
    //         ret = super.runInfoflow(sourcesAndSinks);
    //         config.setSootIntegrationMode(SootIntegrationMode.CreateNewInstance);    
	// 	} else {
    //         ret = super.runInfoflow(sourcesAndSinks);
    //     }
	// 	return ret;
	// }

    // void myInitializeSoot() {
	// 	logger.info("Initializing Soot...");

	// 	final String androidJar = config.getAnalysisFileConfig().getAndroidPlatformDir();
	// 	final String apkFileLocation = config.getAnalysisFileConfig().getTargetAPKFile();

	// 	// Clean up any old Soot instance we may have
	// 	G.reset();

	// 	Options.v().set_no_bodies_for_excluded(true);
	// 	Options.v().set_allow_phantom_refs(true);
	// 	if (config.getWriteOutputFiles())
	// 		Options.v().set_output_format(Options.output_format_jimple);
	// 	else
	// 		Options.v().set_output_format(Options.output_format_none);
	// 	Options.v().set_whole_program(true);
	// 	Options.v().set_process_dir(Collections.singletonList(apkFileLocation));
	// 	if (forceAndroidJar)
	// 		Options.v().set_force_android_jar(androidJar);
	// 	else
	// 		Options.v().set_android_jars(androidJar);
	// 	Options.v().set_src_prec(Options.src_prec_apk_class_jimple);
	// 	Options.v().set_keep_offset(false);
	// 	Options.v().set_keep_line_number(config.getEnableLineNumbers());
	// 	Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
	// 	Options.v().set_process_multiple_dex(config.getMergeDexFiles());
	// 	Options.v().set_ignore_resolution_errors(true);

	// 	// Set soot phase option if original names should be used
	// 	if (config.getEnableOriginalNames())
	// 		Options.v().setPhaseOption("jb", "use-original-names:true");

	// 	// Set the Soot configuration options. Note that this will needs to be
	// 	// done before we compute the classpath.
	// 	if (sootConfig != null)
	// 		sootConfig.setSootOptions(Options.v(), config);

	// 	Options.v().set_soot_classpath(getClasspath());
	// 	Main.v().autoSetOptions();
	// 	configureCallgraph();

    //     // 也就是提前了这个
    //     LibraryClassPatcher patcher = getLibraryClassPatcher(); // load necessary classes.

	// 	// Load whatever we need
	// 	logger.info("Loading dex files...");
	// 	Scene.v().loadNecessaryClasses();

	// 	// Make sure that we have valid Jimple bodies
	// 	PackManager.v().getPack("wjpp").apply();

	// 	// Patch the callgraph to support additional edges. We do this now,
	// 	// because during callback discovery, the context-insensitive callgraph
	// 	// algorithm would flood us with invalid edges.
		
	// 	patcher.patchLibraries();
    // }

    // /**
	//  * Builds the classpath for this analysis
	//  * 
	//  * @return The classpath to be used for the taint analysis
	//  */
	// private String getClasspath() {
	// 	final String androidJar = config.getAnalysisFileConfig().getAndroidPlatformDir();
	// 	final String apkFileLocation = config.getAnalysisFileConfig().getTargetAPKFile();
	// 	final String additionalClasspath = config.getAnalysisFileConfig().getAdditionalClasspath();

	// 	String classpath = forceAndroidJar ? androidJar : Scene.v().getAndroidJarPath(androidJar, apkFileLocation);
	// 	if (additionalClasspath != null && !additionalClasspath.isEmpty())
	// 		classpath += File.pathSeparator + additionalClasspath;
	// 	logger.debug("soot classpath: " + classpath);
	// 	return classpath;
	// }

}
