package org.example.nativesummary;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;

import org.example.nativesummary.APKRepacker.StreamUtils;
import soot.Type;
import soot.dexpler.Util;

/**
 * Hello world!
 *
 */
public class SinksGenerator 
{
    public static void main( String[] args ) throws Exception
    {
        String apk_path = args[0];
        JarFile apk = new JarFile(apk_path);
        Enumeration<JarEntry> entries = apk.entries();
        String ret = "";
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            final String name = entry.getName();
            if (SecondRepacker.isClassesDotDex(name)) {
                // extract to memory
                final InputStream entryInputStream = apk.getInputStream(entry);
                ByteArrayOutputStream memStream = new ByteArrayOutputStream(Math.toIntExact(entry.getSize()));
                StreamUtils.copyAndClose(entryInputStream, memStream);
                byte[] origBytes = memStream.toByteArray();
                // verify(origBytes);
                ByteArrayInputStream dexStream = new ByteArrayInputStream(origBytes);
                ret += analyzeOne(dexStream);
            }
        }
        apk.close();
        Files.write(Paths.get(apk_path+".sinks.txt"), ret.getBytes());
    }

    static String analyzeOne(ByteArrayInputStream dexStream) throws IOException {
        DexFile dex = DexBackedDexFile.fromInputStream(null, dexStream);
        StringWriter writer = new StringWriter();
        for (ClassDef classDef: dex.getClasses()) {
            String name = classDef.getType();
            if(!name.equals("Lorg/example/NativeSummaryFuncs;")) {
                continue;
            }
            for(Method m: classDef.getMethods()) {
                writer.write(fromDexMethod(m, name));
            }
        }
        return writer.toString();
    }

    public static String fromDexMethod(Method m, String classDesc) {
        StringWriter writer = new StringWriter();
        writer.write('<');
        writer.write(soot.dexpler.Util.dottedClassName(classDesc));
        writer.write('.');
        writer.write(m.getName());
        Type ret = Util.getType(m.getReturnType());
        writer.write(ret.toString());
        writer.write('(');
        boolean first = true;
        for (CharSequence paramType: m.getParameterTypes()) {
            if (!first) {
                writer.write(',');
            }
            first = false;
            Type ty = Util.getType(paramType.toString());
            writer.write(ty.toString());
        }
        writer.write(')');
        // DexFormatter.INSTANCE.getWriter(writer).writeShortMethodDescriptor(m);
        writer.write("> -> _SINK_\n");
        return writer.toString();
    }
}
