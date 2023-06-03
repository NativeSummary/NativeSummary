package org.example.nativesummary.flowdroidbridge;

import soot.jimple.infoflow.cfg.LibraryClassPatcher;

/**保持原有功能的同时，patch想要的方法 */
public class NativePatcher extends LibraryClassPatcher {
    protected String target;
    public NativePatcher(String targetAPKFile) {
        target = targetAPKFile;
    }

    @Override
    public void patchLibraries() {
        // 保持原有功能
        super.patchLibraries();
        // TODO fix
        // MethodBuilder b;
        // try {
        //     String t = target.replaceFirst("\\.apk", "_ss.json");
        //     b = new MethodBuilder(t);
        // } catch (JsonIOException | JsonSyntaxException | FileNotFoundException e) {
        //     e.printStackTrace();
        //     return;
        // }
        // b.patchSoot();
    }

    public void patchsourcesinkmanager() {
        
    }
}
