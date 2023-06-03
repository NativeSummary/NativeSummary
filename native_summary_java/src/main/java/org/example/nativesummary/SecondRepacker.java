package org.example.nativesummary;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.Adler32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.annotation.Nonnull;

import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.formatter.DexFormatter;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.rewriter.DexRewriter;
import org.jf.dexlib2.rewriter.Rewriter;
import org.jf.dexlib2.rewriter.RewriterModule;
import org.jf.dexlib2.rewriter.Rewriters;
import org.jf.dexlib2.writer.io.MemoryDataStore;
import org.jf.dexlib2.writer.pool.DexPool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.example.nativesummary.APKRepacker.StreamUtils;
import soot.AbstractJasminClass;
import soot.SootClass;
import soot.SootMethod;
import soot.toDex.SootToDexUtils;

/**
 * 首先把soot重打包的dex文件里面需要的方法加载进来分类放好。
 * 然后当调用rewriter.getDexFileRewriter().rewrite的时候，如果发现有对应的方法，则返回之前存下来的方法。
 * 如果有需要额外增加的class，则在重打包时放到最后一个dex文件里。
 */
public class SecondRepacker {
    private static final Logger logger = LoggerFactory.getLogger(APKRepacker.class);
    Opcodes opcodes;
    // Map<"ClassDescriptor", Set<"MethodDescriptorWithSig">>
    Map<String, Map<String, Method>> modedMth = new HashMap<>();
    Map<String, Set<String>> mthSigs;
    // use Method.equals, but not use their instance
    Map<Method, Method> modedMthSet = new HashMap<>();
    Set<String> additionalClasses = new HashSet<>();
    Map<String, ClassDef> additionalClassesMap = new HashMap<>();

    // rewrite one apk
    Map<String, DexPool> rewrittenDexes = new HashMap<>();

    // handle dex overflow
    // when overflowed, classdef that cannot fit first put in a set.
    // then, try to include them in the following dex file.
    // if there still remains classdef, fit them in new DexFiles.
    Set<ClassDef> remainderDexes = new LinkedHashSet<>();
    Map<String, DexPool> additionalDexes = new LinkedHashMap<>();

    private SecondRepacker(Map<String, Set<String>> mthSigs, Set<String> additionalClasses, Opcodes opcodes) {
        this.mthSigs = mthSigs;
        this.opcodes = opcodes;
        this.additionalClasses = additionalClasses;
    }

    DexRewriter rewriter = new DexRewriter(new RewriterModule() {
        public Rewriter<Method> getMethodRewriter(@Nonnull Rewriters rewriters) {
            return new Rewriter<Method>() {
                public @Nonnull Method rewrite(@Nonnull Method m) {
                    if (modedMthSet.containsKey(m)) {
                        m = modedMthSet.get(m);
                    }
                    return m;
                }
            };
        }
    });

    // 重打包后复制到outPath
    public void rewriteTo(File origAPK, Path outPath) throws IOException {
        // 重置相关成员
        rewrittenDexes.clear();

        // 依次遍历解压原APK中的Dex到内存，设置DexRewriter
        JarFile apk = new JarFile(origAPK);
        Enumeration<JarEntry> entries = apk.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            final String name = entry.getName();
            if (isClassesDotDex(name)) {
                // extract to memory
                final InputStream entryInputStream = apk.getInputStream(entry);
                ByteArrayOutputStream memStream = new ByteArrayOutputStream(Math.toIntExact(entry.getSize()));
                StreamUtils.copyAndClose(entryInputStream, memStream);
                byte[] origBytes = memStream.toByteArray();
                // verify(origBytes);
                ByteArrayInputStream dexStream = new ByteArrayInputStream(origBytes);
                rewriteOne(name, dexStream);
            }
        }

        // 在最后一个dex里面，增加额外的class。
        remainderDexes.addAll(additionalClassesMap.values());
        rewriteFinish();

        // 把dex与原APK重写
        File outApkFile = File.createTempFile("finalAPK", null);
        JarFile inputJar = apk;
        String lastName = getLastDexFileName();
        try (ZipOutputStream outputJar = new ZipOutputStream(new FileOutputStream(outApkFile))) {
            entries = inputJar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                final String name = entry.getName();
                outputJar.putNextEntry(new ZipEntry(name));
                if (rewrittenDexes.containsKey(name)) {
                    try (InputStream newClasses = convertDex(rewrittenDexes.get(name))) {
                        StreamUtils.copy(newClasses, outputJar);
                    }
                    // 如果是最后一个dex，需要把剩余的其他dex也放进去。
                    if (name.equals(lastName)) {
                        for (String name2: additionalDexes.keySet()) {
                            outputJar.putNextEntry(new ZipEntry(name2));
                            try (InputStream is = convertDex(rewrittenDexes.get(name2))) {
                                StreamUtils.copy(is, outputJar);
                            }
                        }
                    }
                }
                else
                    try (final InputStream entryInputStream = inputJar.getInputStream(entry)) {
                        StreamUtils.copy(entryInputStream, outputJar);
                    }
                outputJar.closeEntry();
            }
        }
        apk.close();
        Files.copy(outApkFile.toPath(), outPath, StandardCopyOption.REPLACE_EXISTING); // outPath.resolveSibling(outPath.getFileName() + ".repacked.apk")
        outApkFile.delete();
    }


    void rewriteOne(String name, @Nonnull ByteArrayInputStream dexStream) throws IOException {
        long overflowedCount = remainderDexes.size();
        DexFile dex = DexBackedDexFile.fromInputStream(opcodes, dexStream);
        dex = rewriter.getDexFileRewriter().rewrite(dex);
        // MemoryDataStore memds = new MemoryDataStore();
        // DexPool.writeTo(memds, rewrittenDex);
        // byte[] buf = memds.getBuffer();
        // // verify(buf);
        // InputStream os = new ByteArrayInputStream(buf, 0, memds.getSize());

        boolean overflowed = false;
        DexPool dexPool = new DexPool(opcodes);
        // intern class till overflow
        for (ClassDef classDef: dex.getClasses()) {
            if (overflowed) {
                remainderDexes.add(classDef);
                continue;
            }
            // not overflow
            dexPool.mark();
            dexPool.internClass(classDef);
            if (dexPool.hasOverflowed()) {
                dexPool.reset();
                remainderDexes.add(classDef);
                overflowed = true;
            }
        }
        // try to fit more class
        if (!overflowed) {
            ArrayList<ClassDef> added = new ArrayList<>();
            for (ClassDef classDef: remainderDexes) {
                dexPool.mark();
                dexPool.internClass(classDef);
                if (dexPool.hasOverflowed()) {
                    dexPool.reset();
                    break;
                }
                added.add(classDef);
            }
            remainderDexes.removeAll(added);
        }
        rewrittenDexes.put(name, dexPool);

        // log 
        overflowedCount = remainderDexes.size() - overflowedCount;
        if (overflowedCount > 0) {
            logger.info("Dex file {} overflowed {} classes.", name, overflowedCount);
        }
    }

    void rewriteFinish() {
        String name = getLastDexFileName();
        DexPool dexPool = rewrittenDexes.get(name);
        if (dexPool.hasOverflowed()) {
            name = nextDexFileName(name);
            dexPool = newDexPool(name);
        }
        for (ClassDef classDef: remainderDexes) {
            dexPool.mark();
            dexPool.internClass(classDef);
            if (dexPool.hasOverflowed()) {
                dexPool.reset();
                name = nextDexFileName(name);
                dexPool = newDexPool(name);
                dexPool.internClass(classDef);
                assert !dexPool.hasOverflowed();
            }
        }
    }

    // 输入一个APK文件
    public static SecondRepacker fromAPKRepackedMthList(Path sootOutputAPK, Map<String, Set<String>> mthSigs, Set<String> additionalClasses, Opcodes opcodes) throws IOException {
        SecondRepacker thiz = new SecondRepacker(mthSigs, additionalClasses, opcodes);
        // 解压sootAPK里的每个Dex到内存，读取和设置Map
        JarFile inputJar = new JarFile(sootOutputAPK.toFile());
        Enumeration<JarEntry> entries = inputJar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            final String name = entry.getName();
            if (isClassesDotDex(name)) {
                // extract to memory TODO remove because DexBackedDexFile.fromInputStream will read to memory
                final InputStream entryInputStream = inputJar.getInputStream(entry);
                ByteArrayOutputStream memStream = new ByteArrayOutputStream(Math.toIntExact(entry.getSize()));
                StreamUtils.copyAndClose(entryInputStream, memStream);
                ByteArrayInputStream dexStream = new ByteArrayInputStream(memStream.toByteArray());
                thiz.addDex(opcodes, dexStream);
            }
        }
        inputJar.close();

        return thiz;
    }

    // 输入一个Dex文件
    public static SecondRepacker fromRepackedMthList(File[] files, Map<String, Set<String>> mthSigs, Set<String> additionalClasses, Opcodes opcodes) throws IOException {
        if (files.length > 1) {
            logger.error("Too many (Dex?) files!");
            return null;
        }
        SecondRepacker thiz = new SecondRepacker(mthSigs, additionalClasses, opcodes);

        File dexFile = files[0];
        final InputStream dexInputStream = new FileInputStream(dexFile);
        InputStream bufferedIn = new BufferedInputStream(dexInputStream);
        thiz.addDex(opcodes, bufferedIn);
        dexInputStream.close();

        return thiz;
    }

    private void addDex(Opcodes opcodes, @Nonnull InputStream dexStream) throws IOException {
        DexFile dex;
        dex = DexBackedDexFile.fromInputStream(opcodes, dexStream);
        for (ClassDef c: dex.getClasses()) {
            String clz = c.toString();
            if (mthSigs.containsKey(clz)) {
                Set<String> mths = mthSigs.get(clz);
                for(Method m: c.getMethods()) {
                    String sig2 = DexFormatter.INSTANCE.getShortMethodDescriptor(m);
                    sig2 = sig2.replaceAll("\\s+","");
                    if (mths.contains(sig2)) {
                        // add to modedClz
                        modedMth.computeIfAbsent(clz, x -> new HashMap<>()).put(sig2, m);
                        modedMthSet.put(m, m);
                    }
                }
            }
            if (additionalClasses.contains(clz)) {
                additionalClassesMap.put(clz, c);
            }
        }
    }

    public static class SigCollector {
        // for soot output to dex
        Set<SootClass> clzs = new HashSet<>();
        Set<String> additionalClasses = new HashSet<>();
        Map<String, Set<String>> sigs = new HashMap<>();
        
        public void addMethod(SootMethod sm) {
            clzs.add(sm.getDeclaringClass());
            String clzName = SootToDexUtils.getDexClassName(sm.getDeclaringClass().getName());
            String desc = AbstractJasminClass.jasminDescriptorOf(sm.makeRef());
            desc = desc.replaceAll("\\s+","");
            sigs.computeIfAbsent(clzName, x -> new HashSet<>()).add(sm.getName()+desc);
        }

        // only for NativeSummaryAux class
        public void addAuxClass(SootClass aux) {
            clzs.add(aux);
            additionalClasses.add(SootToDexUtils.getDexClassName(aux.getName()));
        }

        public Map<String, Set<String>> get() {
            return sigs;
        }

        public Set<SootClass> getClasses() {
            return clzs;
        }

        public Set<String> getAdditionalClasses() {
            return additionalClasses;
        }
    }

    public InputStream convertDex(@Nonnull DexPool dex) throws IOException {
        MemoryDataStore memds = new MemoryDataStore();
        // DexPool.writeTo(memds, dex);
        dex.writeTo(memds);
        byte[] buf = memds.getBuffer();
        // verify(buf);
        InputStream is = new ByteArrayInputStream(buf, 0, memds.getSize());
        return is;
    }

    public static String nextDexFileName(String name) {
        // return null;
        String prefix = name.substring(0,7);
        String index = name.substring(7, name.length()-4);
        String suffix = name.substring(name.length()-4);
        return prefix + String.valueOf(Long.valueOf(index)+1) + suffix;
    }

    private DexPool newDexPool(String name) {
        DexPool ret = new DexPool(opcodes);
        additionalDexes.put(name, ret);
        return ret;
    }

    public static boolean isClassesDotDex(String filename) {
        return filename.toLowerCase().matches("classes\\d*\\.dex");
    }

    String getLastDexFileName() {
        String max = null;
        for (String k: rewrittenDexes.keySet()) {
            if (max == null) {
                max = k;
            } else if (k.compareTo(max) > 0) {
                max = k;
            }
        }
        return max;
    }

    // from jadx
    public static boolean verify(byte[] content) {
		int len = content.length;
		if (len < 12) {
			return false;
		}
		int checksum = ByteBuffer.wrap(content, 8, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
		Adler32 adler32 = new Adler32();
		adler32.update(content, 12, len - 12);
		int fileChecksum = (int) (adler32.getValue());
		if (checksum != fileChecksum) {
			return false;
		}
        return true;
	}

}
