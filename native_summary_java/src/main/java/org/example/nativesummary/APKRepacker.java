package org.example.nativesummary;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.FileUtils;
import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.formatter.DexFormatter;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.rewriter.DexRewriter;
import org.jf.dexlib2.rewriter.Rewriter;
import org.jf.dexlib2.rewriter.RewriterModule;
import org.jf.dexlib2.rewriter.Rewriters;
import org.jf.util.ExceptionWithContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;

import org.example.nativesummary.SecondRepacker.SigCollector;
import org.example.nativesummary.ir.Module;
import org.example.nativesummary.jimplebuilder.BodyBuilder;
import org.example.nativesummary.jimplebuilder.Context;
import org.example.nativesummary.jimplebuilder.ExternalFuncLoweringEarly;
import org.example.nativesummary.jimplebuilder.PreLoadAnalysis;
import soot.G;
import soot.Main;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SourceLocator;
import soot.options.Options;
import soot.toDex.DexPrinter;

public class APKRepacker {
    private static final Logger logger = LoggerFactory.getLogger(APKRepacker.class);
    public static final String SUMMARY_SER_SUFFIX = ".summary.java_serialize";
    public static final String SUMMARY_FOLDER_SUFFIX = ".native_summary";
    public static final String DEFAULT_APK_OUT_FOLDER = "nativesummary_repacked_apks";

    // public boolean forceAndroidJar;
    public String apkFileLocation;
    public String platformDir;
    public Module summary;
    public File apkFile;

    APKRepacker(String apkFileLocation, String platformDir, Module summary) {
        this.apkFileLocation = apkFileLocation;
        this.apkFile = new File(apkFileLocation);
        this.platformDir = platformDir;
        this.summary = summary;
    }

    APKRepacker(File apkFile, String platformDir, Module summary) {
        this.apkFile = apkFile;
        this.apkFileLocation = apkFile.getPath();
        this.platformDir = platformDir;
        this.summary = summary;
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
        // final String androidJar =
        // config.getAnalysisFileConfig().getAndroidPlatformDir();
        // final String apkFileLocation =
        // config.getAnalysisFileConfig().getTargetAPKFile();
        // final String additionalClasspath =
        // config.getAnalysisFileConfig().getAdditionalClasspath();

        // String classpath = forceAndroidJar ? androidJar :
        // Scene.v().getAndroidJarPath(androidJar, apkFileLocation);
        String classpath = Scene.v().getAndroidJarPath(platformDir, apkFileLocation);
        // if (additionalClasspath != null && !additionalClasspath.isEmpty())
        // classpath += File.pathSeparator + additionalClasspath;
        logger.debug("soot classpath: " + classpath);
        return classpath;
    }

    /**
     * Only load APK class, so that output can be as identical as original.
     * based on soot.jimple.infoflow.android.SetupApplication
     */
    public void initializeSoot() {
        logger.info("Initializing Soot...");

        // final String androidJar =
        // config.getAnalysisFileConfig().getAndroidPlatformDir();
        // final String apkFileLocation =
        // config.getAnalysisFileConfig().getTargetAPKFile();

        // Clean up any old Soot instance we may have
        G.reset();

        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_output_format(Options.output_format_dex);
        Options.v().set_whole_program(true);
        Options.v().set_process_dir(Collections.singletonList(apkFileLocation));
        // if (forceAndroidJar)
        // Options.v().set_force_android_jar(androidJar);
        // else
        Options.v().set_android_jars(platformDir);
        Options.v().set_src_prec(Options.src_prec_apk_class_jimple);
        // Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_keep_offset(true);
        Options.v().set_keep_line_number(true);
        Options.v().set_throw_analysis(Options.throw_analysis_dalvik);
        Options.v().set_process_multiple_dex(true);
        // Options.v().set_ignore_resolution_errors(true);

        // Set soot phase option if original names should be used
        Options.v().setPhaseOption("jb", "use-original-names:true");

        // Set the Soot configuration options. Note that this will needs to be
        // done before we compute the classpath.
        // if (sootConfig != null)
        // sootConfig.setSootOptions(Options.v(), config);
        // TODO
        excludeAndroidLibs();

        Options.v().set_soot_classpath(getClasspath());
        Main.v().autoSetOptions();
        // configureCallgraph();

        // TODO PreLoadAnalysis
        new PreLoadAnalysis(summary).do_analysis();

        ExternalFuncLoweringEarly.process(summary, true);

        // Load whatever we need
        logger.info("Loading dex files...");
        try {
            Scene.v().loadNecessaryClasses();
        } catch (Exception e) {
            logger.error("Soot failed to load dex file: ", e);
            throw new SootFailedException(e.getMessage());
        }

        // Make sure that we have valid Jimple bodies
        PackManager.v().getPack("wjpp").apply();
    }

    public Path outputSootAPK(Set<SootClass> clzs, boolean forceOverwrite) throws IOException {
        Options.v().set_force_overwrite(forceOverwrite);
        if (cmd.hasOption("output-jimple")) {
            Options.v().set_output_format(Options.output_format_jimple);
        } else {
            Options.v().set_output_format(Options.output_format_force_dex);
        }
        // Output Dex to a temp dir, wait to be repacked.
        final Path tempPath = Files.createTempDirectory(Long.toString(System.nanoTime()));
        Options.v().set_output_dir(tempPath.toString());
        // PackManager.v().writeOutput(clzs.iterator());
        DexPrinter dexPrinter = new DexPrinter();
        for (SootClass sc : clzs) {
            dexPrinter.add(sc);
        }
        dexPrinter.print();
        return tempPath;
    }

    /**
     * 重打包以解决Soot打包会加载太多冗余的类，并报错的问题。
     * 让Soot那边加载尽量少的类，然后重新打包修改的部分，可以最小化对APK的修改。
     * 
     * @param sigs List<"ClassName"+"\t"+"MthName"+"descriptor">
     * @throws IOException
     */
    public void repackAgain(List<String> sigs) throws IOException {
        final String apkname = apkFile.getName();
        final Path sootOutputAPK = Paths.get(SourceLocator.v().getOutputDir(), apkname);
        DexFile sootAPK;
        DexFile origAPK;
        // how to support multidex ?? DexFileFactory.loadDexFile only support one dex
        try {
            origAPK = DexFileFactory.loadDexFile(apkFile, Opcodes.forApi(Scene.v().getAndroidAPIVersion()));
            // origAPK.
        } catch (IOException e) {
            logger.error("File " + apkFile.getPath() + " not found", e);
            return;
        }
        try {
            sootAPK = DexFileFactory.loadDexFile(sootOutputAPK.toFile(),
                    Opcodes.forApi(Scene.v().getAndroidAPIVersion()));
        } catch (IOException e) {
            logger.error("File " + sootOutputAPK.toString() + " not found", e);
            return;
        }

        // TODO 用DexRewriter改写
        // 重新组织一下sigs
        Map<String, String> modedMthSigs = new HashMap<>();
        for (String sig : sigs) {
            String[] parts = sig.split("\t");
            modedMthSigs.put(parts[0], sig);
        }
        // Map<String,String> modedMth = new HashMap<>();
        // 把需要重写的方法放进来。
        Map<Method, Method> modedMth = new HashMap<>();
        for (ClassDef c : sootAPK.getClasses()) {
            String clz = c.toString();
            if (modedMthSigs.containsKey(clz)) {
                String fsig = modedMthSigs.get(clz);
                String[] parts = fsig.split("\t");
                String sig = parts[2].replaceAll("\\s+", "");
                for (Method m : c.getMethods()) {
                    String sig2 = DexFormatter.INSTANCE.getShortMethodDescriptor(m);
                    sig2 = sig2.replaceAll("\\s+", "");
                    if ((parts[1] + sig).equals(sig2)) {
                        modedMth.put(m, m);
                    }
                }
            }
        }
        logger.debug("2nd phase: repacked methods:");
        logger.debug(modedMth.toString());
        // for(ClassDef c: origAPK.getClasses()) {
        // if (!classes.contains(c)) {
        // classes.add(c);
        // } else{
        // logger.debug("msg");
        // }
        // }

        File tmpClassesDex = File.createTempFile("NewClasseDex", null);
        tmpClassesDex.deleteOnExit();

        // use modedMth to rewrite
        DexRewriter rewriter = new DexRewriter(new RewriterModule() {
            public Rewriter<Method> getMethodRewriter(Rewriters rewriters) {
                return new Rewriter<Method>() {
                    public Method rewrite(Method m) {
                        if (modedMth.containsKey(m)) {
                            m = modedMth.get(m);
                        }
                        return m;
                    }
                };
            }
        });
        DexFile rewrittenDexFile = rewriter.getDexFileRewriter().rewrite(origAPK);

        DexFileFactory.writeDexFile(tmpClassesDex.getCanonicalPath(), rewrittenDexFile);

        File outApkFile = File.createTempFile("finalAPK", null);
        JarFile inputJar = new JarFile(apkFileLocation);
        try (ZipOutputStream outputJar = new ZipOutputStream(new FileOutputStream(outApkFile))) {
            Enumeration<JarEntry> entries = inputJar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                final String name = entry.getName();
                outputJar.putNextEntry(new ZipEntry(name));
                if (name.equalsIgnoreCase("classes.dex"))
                    try (final FileInputStream newClasses = new FileInputStream(tmpClassesDex)) {
                        StreamUtils.copy(newClasses, outputJar);
                    }
                else
                    try (final InputStream entryInputStream = inputJar.getInputStream(entry)) {
                        StreamUtils.copy(entryInputStream, outputJar);
                    }
                outputJar.closeEntry();
            }
        }
        inputJar.close();
        Files.copy(outApkFile.toPath(), sootOutputAPK, StandardCopyOption.REPLACE_EXISTING);
        outApkFile.delete();
        tmpClassesDex.delete();
    }

    static class StreamUtils {
        public static void copyAndClose(InputStream is, OutputStream os) throws IOException {
            copy(is, os);
            is.close();
            os.close();
        }

        public static void copy(InputStream is, OutputStream os) throws IOException {
            final byte[] buf = new byte[512];
            int nRead;
            while ((nRead = is.read(buf)) != -1) {
                os.write(buf, 0, nRead);
            }
        }
    }

    public static void doOne(String apkPath, String summaryFolder, Path outAPK, String platformDir) throws IOException {
        // 遍历summaryFolder，对每个.summary.java_serialize文件，加载Module并merge
        File folder = new File(summaryFolder);
        if (!folder.exists() || !folder.isDirectory()) {
            logger.error("summaryFolder not exist or is not directory");
            return;
        }
        List<File> summaryFiles = Arrays.asList(folder.listFiles(new FilenameFilter() {
            @Override
            public boolean accept(File dir, String name) {
                return name.endsWith(SUMMARY_SER_SUFFIX);
            }
        }));
        List<Module> summaries = new ArrayList<>();
        for (File mod : summaryFiles) {
            Module module;
            try {
                ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(mod));
                module = (Module) objectInputStream.readObject();
                objectInputStream.close();
            } catch (IOException | ClassNotFoundException e) {
                logger.error("Load sematic summary failed.", e);
                logger.error("path: {}", mod.getPath());
                continue;
            }
            summaries.add(module);
        }
        if (summaries.size() == 0) {
            logger.error("Load sematic summary failed.");
            return;
        }

        Module m = Module.merge(summaries);
        APKRepacker r = new APKRepacker(apkPath, platformDir, m);
        try {
            r.initializeSoot();
        } catch (SootFailedException e) {
            return;
        }

        Context ctx = new Context(m, summaryFolder);
        if (cmd.hasOption("debug-lower")) {
            ctx.setDebugLower();
        }
        if (cmd.hasOption("debug-type")) {
            ctx.setDebugType();
        }
        if (cmd.hasOption("debug-jimple")) {
            ctx.setDebugJimple();
        }
        SigCollector repackedNative = ctx.doAnalysis(summaries, apkPath, platformDir);

        Path sootDexFolder;
        try {
            sootDexFolder = r.outputSootAPK(repackedNative.getClasses(), true);
        } catch (RuntimeException e) {
            e.printStackTrace(System.err);
            logger.info("Soot output error, No apk is generated.");
            return;
        }
        File sootDexFolderFile = sootDexFolder.toFile();
        SecondRepacker rep = SecondRepacker.fromRepackedMthList(sootDexFolderFile.listFiles(), repackedNative.get(),
                repackedNative.getAdditionalClasses(), Opcodes.forApi(Scene.v().getAndroidAPIVersion()));
        logger.info("Repacking original APK...");
        long start = System.currentTimeMillis();
        try {
            rep.rewriteTo(r.apkFile, outAPK);
            // output generated method as source list
            String sinks = ctx.getmmgr().getFlowDroidSinks();
            Files.write(outAPK.resolveSibling(outAPK.getFileName().toString()+".sinks.txt"), sinks.getBytes());
        } catch (ExceptionWithContext e) {
            logger.error("APK repacking failed:", e);
            // soot dex
            File repackFolder = outAPK.getParent().resolve(outAPK.getFileName()+".repack").toFile();
            repackFolder.mkdirs();
            FileUtils.copyDirectory(sootDexFolderFile, repackFolder);
            logger.error("Please check: "+repackFolder);
            return;
        }
        logger.info("Repacking spent {} ms.", System.currentTimeMillis() - start);

        // r.repackAgain(b.patchedMethods);
        // remove soot temp folder
        String[] entries = sootDexFolderFile.list();
        for (String s : entries) {
            File currentFile = new File(sootDexFolderFile.getPath(), s);
            currentFile.delete();
        }
        sootDexFolderFile.delete();

    }

    public static CommandLine cmd;

    public static void main(String[] args)
            throws JsonIOException, JsonSyntaxException, IOException, ClassNotFoundException {
        org.apache.commons.cli.Options options = new org.apache.commons.cli.Options();
        Option nullphi = Option.builder().hasArg(false).longOpt("no-null-in-phi")
                .desc("filter out all meanless value in phi").build();
        Option debugType = Option.builder().hasArg(false).longOpt("debug-type").desc("print typed IR for debugging")
                .build();
        Option outputJimple = Option.builder().hasArg(false).longOpt("output-jimple")
                .desc("output jimple instead of apk for debugging (not recommended)").build();
        Option debugJimple = Option.builder().hasArg(false).longOpt("debug-jimple").desc("output jimple for debugging")
                .build();
        Option noOpt = Option.builder().hasArg(false).longOpt("no-opt").desc("not optimizing jimple for debugging")
                .build();
        Option outFolderOpt = Option.builder().hasArg(true).longOpt("out").argName("outFolder")
                .desc("output folder for repacked apk, default to nativesummary_repacked_apks/ in current dir").build();
        options.addOption(debugType);
        options.addOption(outputJimple);
        options.addOption(debugJimple);
        options.addOption(noOpt);
        options.addOption(outFolderOpt);
        options.addOption(nullphi);

        CommandLineParser parser = new DefaultParser();
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            printHelp(options, e);
            System.exit(1);
        }

        if (cmd.hasOption("no-null-in-phi")) {
            BodyBuilder.noNullInPhi = true;
        }

        Path outFolder;
        if (cmd.hasOption("out")) {
            outFolder = Path.of(cmd.getOptionValue("out"));
        } else {
            outFolder = Path.of(DEFAULT_APK_OUT_FOLDER);
        }
        if (!outFolder.toFile().exists()) {
            outFolder.toFile().mkdirs();
        }

        List<String> additionalArgs = cmd.getArgList();
        if (additionalArgs.size() != 3) {
            // TODO usage;
            printHelp(options, null);
            return;
        }
        logger.info("apk: " + additionalArgs.get(0));
        logger.info("sematicSummary: " + additionalArgs.get(1));
        logger.info("output to: " + outFolder.toString());
        logger.info("platformDir: " + additionalArgs.get(2));
        File fold = new File(additionalArgs.get(0));
        File sumFold = new File(additionalArgs.get(2));
        if (!fold.exists()) {
            logger.error("apkDir not exist or is not directory");
            return;
        }
        if (!sumFold.exists() || !sumFold.isDirectory()) {
            logger.error("sematicSummary not exist or is not directory");
            return;
        }
        // 判断分析模式并处理
        if (!fold.isDirectory()) {
            // fold is apk path
            logger.info("[#] single APK mode");
            Path outAPK = outFolder.resolve(fold.getName());
            doOne(additionalArgs.get(0), additionalArgs.get(1), outAPK, additionalArgs.get(2));
        } else {
            logger.info("[#] bulk mode");
            List<File> apksToAnalyze = Arrays.asList(fold.listFiles(new FilenameFilter() {
                @Override
                public boolean accept(File dir, String name) {
                    return name.toLowerCase().endsWith(".apk");
                }
            }));
            for (File apkFile : apksToAnalyze) {
                Path sootAPK = Paths.get(SourceLocator.v().getOutputDir(), apkFile.getName());
                if (Files.exists(sootAPK)) {
                    logger.info("[#] skip " + apkFile.getName());
                    continue;
                }


                logger.info("[#] ###### " + apkFile.getName());
                // 去除.apk后缀，加上summary文件夹的后缀
                String summaryFolder = apkFile.getName().substring(0, Math.toIntExact(apkFile.getName().length() - 4))
                        + SUMMARY_FOLDER_SUFFIX;
                Path outAPK = outFolder.resolve(apkFile.getName());
                doOne(apkFile.getAbsolutePath(), Paths.get(additionalArgs.get(1), summaryFolder).toString(), outAPK,
                        additionalArgs.get(2));
            }
        }
    }

    private static void printHelp(org.apache.commons.cli.Options options, Exception e) {
        if (e != null) {
            System.out.println(e.getMessage());
        }
        new HelpFormatter().printHelp(" [OPTIONS] <apk> <sematicSummary> <platformDir>", options);
    }

    public static class SootFailedException extends RuntimeException {
        public SootFailedException(String errorMessage) {
            super(errorMessage);
        }
    }
}
