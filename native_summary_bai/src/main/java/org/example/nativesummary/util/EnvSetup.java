package org.example.nativesummary.util;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Library;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * notice:
 * typedef const struct JNINativeInterface* JNIEnv;
 * typedef const struct JNIInvokeInterface* JavaVM;
 * so JNIEnv* --> JNINativeInterface **
 *
 * Address layout: start = getJNIEnv(); p = defaultPointerSize
 * start -> start + 0x1000          | struct _JNIEnv
 *     0x0 JNINativeInterface_* points to start+p
 *     0xp struct JNINativeInterface_ (full of function pointers)
 * start + 0x1000 -> start + 0x2000 | external functions
 * start + 0x2000 -> start + 0x3000 |
 *     0x0 JNIInvokeInterface* points to start + 0x2000 + p
 *     0xp struct JNIInvokeInterface;
 */
public class EnvSetup {
    public static final String JNI_NAMESPACE = "_JNIEnv";
    GhidraState state;
    Program currentProgram;
    FlatProgramAPI flatAPI;
    GhidraScript script; // for debug println

    public static long getJNIEnv() {
        int defPtrSize = MyGlobalState.defaultPointerSize;
        return JNIManager.JNIEnvAddr[(defPtrSize/4)-1];
    }

    public static long getJavaVM() {
        return getJNIEnv()+0x2000L;
    }

    public EnvSetup(Program currentProgram, FlatProgramAPI flatAPI, GhidraState state, GhidraScript script) {
        this.currentProgram = currentProgram;
        this.flatAPI = flatAPI;
        this.state = state;
        this.script = script;
    }

    protected Program getCurrentProgram() {
        return currentProgram;
    }

    public static DataTypeManager getHomeArchiveDataTypeManager(FlatProgramAPI flatAPI, String gdt_name) throws Exception {
        // default to jni_all
        if (gdt_name == null) {
            gdt_name = "jni_all";
        }

//        DataTypeManagerService service = state.getTool().getService(DataTypeManagerService.class);
        AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(flatAPI.getCurrentProgram());
        DataTypeManagerService service = aam.getDataTypeManagerService();

        // Look for an already open "jni_all" archive.
        DataTypeManager[] managers = service.getDataTypeManagers();
        for (DataTypeManager m : managers) {
            if (m.getName().equals(gdt_name)) {
                return m;
            }
        }
        // TODO change to getModuleDataFile
        // If an existing archive isn't found, open it from the file.
        Path user = Paths.get(System.getProperty("user.home"));
        Path filePath = Paths.get(user.toString(), "ghidra_scripts", "data", gdt_name + ".gdt");
        File jniArchiveFile = new File(filePath.toUri());
        // Archive jniArchive = service.openArchive(jniArchiveFile.getFile(true), false);
        FileDataTypeManager jniArchive = flatAPI.openDataTypeArchive(jniArchiveFile, true);
        return jniArchive;
    }

    public static DataTypeManager getModuleDataTypeManager(FlatProgramAPI flatAPI, String gdt_name) throws Exception {
        // default to jni_all
        if (gdt_name == null) {
            gdt_name = "jni_all";
        }

//        DataTypeManagerService service = state.getTool().getService(DataTypeManagerService.class);
        AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(flatAPI.getCurrentProgram());
        DataTypeManagerService service = aam.getDataTypeManagerService();

        // Look for an already open "jni_all" archive.
        DataTypeManager[] managers = service.getDataTypeManagers();
        for (DataTypeManager m : managers) {
            if (m.getName().equals(gdt_name)) {
                return m;
            }
        }

        File jniArchiveFile = Application.getModuleDataFile("native_summary_bai", gdt_name+".gdt").getFile(true);
        // Archive jniArchive = service.openArchive(jniArchiveFile.getFile(true), false);
        FileDataTypeManager jniArchive = flatAPI.openDataTypeArchive(jniArchiveFile, true);
        return jniArchive;
    }

    public Structure getJniStructType() throws Exception {
        // 想办法从archive里导入到project里。或者之前apply过自然就有了
        DataTypeManager archive = getModuleDataTypeManager(flatAPI, "jni_all");
        DataType raw = archive.getDataType("/jni_all.h/JNINativeInterface_");
        return (Structure) raw;
    }

    // dtc is pointer datatype from jni structure.
    public ExternalLocation createExternalFunctionLocation(DataTypeComponent dtc) throws InvalidInputException {
        String name = dtc.getFieldName();
        Namespace ext = getCurrentProgram().getExternalManager().getExternalLibrary(Library.UNKNOWN);
        List<ExternalLocation> l = getCurrentProgram().getExternalManager().getExternalLocations(Library.UNKNOWN, name);
        if (l.size() != 0) {
//			script.println("External function "+name+" already exist");
            return l.get(0);
        }
        // 这里的reuse Existing好像是在extAddr有的时候复用？而我们是null，所以和上面的检查并不重复
        ExternalLocation el = getCurrentProgram().getExternalManager().addExtFunction(ext, name,null, SourceType.ANALYSIS, true);
        // set func signature
        Pointer ptr = (Pointer) dtc.getDataType();
        FunctionDefinition fd = (FunctionDefinition) ptr.getDataType();
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                el.getFunction().getEntryPoint(),
                fd,
                SourceType.USER_DEFINED
        );
        cmd.applyTo(getCurrentProgram(), TaskMonitor.DUMMY);
        return el;
    }

    // setup layout and external functions
    public void run() throws Exception {
        Structure jniStruct = getJniStructType();
        Namespace ext = getCurrentProgram().getExternalManager().getExternalLibrary("<EXTERNAL>");

        long baseaddr1 = getJNIEnv();
        long baseaddr2 = baseaddr1 + 0x1000L;
        long baseaddr3 = baseaddr1 + 0x2000L;
        if (flatAPI.getMemoryBlock("JNIFuncs") == null) {
            MemoryBlockUtils.createInitializedBlock(getCurrentProgram(), false, "JNIStruct", flatAPI.toAddr(baseaddr1), 0x1000L, "JNI analysis", "JNI analysis", true, false, false, new MessageLog());
            MemoryBlockUtils.createUninitializedBlock(getCurrentProgram(), false, "JNIFuncs", flatAPI.toAddr(baseaddr2), 0x1000L, "JNI analysis", "JNI analysis", true, false, true, new MessageLog());
            MemoryBlockUtils.createInitializedBlock(getCurrentProgram(), false, "JavaVMStruct", flatAPI.toAddr(baseaddr3), 0x1000L, "JNI analysis", "JNI analysis", true, false, true, new MessageLog());
        } else {
            script.println("JNI Related Memory blocks exist");
        }
        // 3 创建函数，设置函数为stubed，
        Address current = flatAPI.toAddr(baseaddr2);
        Address structAddr = flatAPI.toAddr(baseaddr1);
        flatAPI.setLong(structAddr, baseaddr1 + getCurrentProgram().getDefaultPointerSize()); // JNIEnv(JNINativeInterface_*) points to JNINativeInterface_
        structAddr = structAddr.add(getCurrentProgram().getDefaultPointerSize()); // JNINativeInterface_ struct (lots of function pointers)
        for (DataTypeComponent dtc : jniStruct.getComponents()) {
            if (!dtc.getFieldName().startsWith("reserved")) {
                ExternalLocation el = createExternalFunctionLocation(dtc);
                // 检查是否已经创建过
                // getExternalLinkageAddresses
                Address[] as = el.getFunction().getFunctionThunkAddresses();
                int len = as == null ? 0 : as.length;
                if (len != 0) {
//                    script.println("Thunk func already exist.");
                } else {
                    Function func = getCurrentProgram().getFunctionManager().createFunction(null, current, new AddressSet(current), SourceType.IMPORTED);
                    Symbol s = func.getSymbol();

                    func.setThunkedFunction(el.getFunction());
                    // not display in function listing
                    if (s.getSource() != SourceType.DEFAULT) {
                        getCurrentProgram().getSymbolTable().removeSymbolSpecial(func.getSymbol());
                    }
//					Function func = getCurrentProgram().getFunctionManager().createThunkFunction(dtc.getFieldName(), ext, current, new AddressSet(current, current), el.getFunction(), SourceType.IMPORTED);
//					Address extaddr = el.getExternalSpaceAddress();
//					println(dtc.getFieldName() +" at "+extaddr.toString());
//					CreateThunkFunctionCmd cmd = new CreateThunkFunctionCmd(extaddr, null, el.getSymbol());
                }
            }
            // set function pointer to created external function
            flatAPI.setLong(structAddr, current.getOffset());
            current = current.add(getCurrentProgram().getDefaultPointerSize());
            structAddr = structAddr.add(getCurrentProgram().getDefaultPointerSize());
        }
        // setup JavaVM related struct
        DataTypeManager archive = getModuleDataTypeManager(flatAPI, "jni_all");
        DataType javaVMStruct = archive.getDataType("/jni_all.h/JNIInvokeInterface_");
        structAddr = flatAPI.toAddr(baseaddr3);
        flatAPI.setLong(structAddr, baseaddr3 + getCurrentProgram().getDefaultPointerSize()); // JavaVM(JNIInvokeInterface_*) points to JNIInvokeInterface_
        structAddr = structAddr.add(getCurrentProgram().getDefaultPointerSize());
        for (DataTypeComponent dtc : ((Structure)javaVMStruct).getComponents()) {
            if (!dtc.getFieldName().startsWith("reserved")) {
                ExternalLocation el = createExternalFunctionLocation(dtc);
                // 检查是否已经创建过
                // getExternalLinkageAddresses
                Address[] as = el.getFunction().getFunctionThunkAddresses();
                int len = as == null ? 0 : as.length;
                if (len != 0) {
//                    script.println("Thunk func already exist.");
                } else {
                    Function func = getCurrentProgram().getFunctionManager().createFunction(null, current, new AddressSet(current), SourceType.IMPORTED);
                    Symbol s = func.getSymbol();

                    func.setThunkedFunction(el.getFunction());
                    // not display in function listing
                    if (s.getSource() != SourceType.DEFAULT) {
                        getCurrentProgram().getSymbolTable().removeSymbolSpecial(func.getSymbol());
                    }
                }
            }
            // set function pointer to created external function
            flatAPI.setLong(structAddr, current.getOffset());
            current = current.add(getCurrentProgram().getDefaultPointerSize());
            structAddr = structAddr.add(getCurrentProgram().getDefaultPointerSize());
        }

        // TODO a better CategoryPath for log_simple.h, like android/log.h
        Map<String, FunctionDefinition> fname2sig = getFuncDefMap(getModuleDataTypeManager(flatAPI, "android_log"), "/log_simple.h/functions");
        // Set up signature for __android_log_print
        // iterate functions in plt section and apply signature according to map.
        MemoryBlock blk = flatAPI.getMemoryBlock(".plt");
        if (blk == null) {
            script.println("ERROR: cannot find memory block for plt section.");
        } else {
            setSigAndThunkInBlock(blk, fname2sig);
        }
        // 32位程序的__android_log_print可能在External里
        blk = flatAPI.getMemoryBlock(MemoryBlock.EXTERNAL_BLOCK_NAME);
        if (blk == null) {
            script.println("ERROR: cannot find memory block for external section.");
        } else {
            setSigAndThunkInBlock(blk, fname2sig);
        }
        // 设置text段其他函数的thunk, 比如_JNIEnv::CallObjectMethod
        SymbolTable table = currentProgram.getSymbolTable();
        Namespace ns = table.getNamespace(JNI_NAMESPACE, currentProgram.getGlobalNamespace());
//        List<Namespace> c = NamespaceUtils.getNamespacesByName(currentProgram, null, JNI_NAMESPACE);
        if (ns == null) {
            script.println("cannot find _JNIEnv namespace.");
        } else {
            for (Symbol s: table.getSymbols(ns)) {
                if (!(s instanceof FunctionSymbol)) {
                    continue;
                }
                Function f = (Function) s.getObject();
                String fname = s.getName();
                if (Utils.JNISymbols.contains(fname)) {
                    // assert can find
                    Function externalTarget = getCurrentProgram().getListing().getFunctions(Library.UNKNOWN, fname).get(0);
                    f.setThunkedFunction(externalTarget);
                }
            }
        }
    }

    private void setSigAndThunkInBlock(MemoryBlock plt, Map<String, FunctionDefinition> fname2sig) throws InvalidInputException {
        // 遍历处理PLT函数，设置签名，设置thunk target
        Address start = plt.getStart();
        Address end = plt.getEnd(); // including
        FunctionIterator iterator = currentProgram.getListing().getFunctions(start, true);
        for (Function f: iterator) {
            if (f.getEntryPoint().getOffset() > end.getOffset()) {
                // out of plt section
                break;
            }
            // get name from map
            String fname = f.getName();
            if (fname2sig.containsKey(fname)) {
                // ensure function signature is uninitialized
                if (f.getParameterCount() == 0) {
                    Utils.applyFunctionSig(currentProgram, f, fname2sig.get(fname));
                }
            }
            // 对于android_log_print这样的函数直接external是true，不需要再thunk到谁，建模逻辑会直接用过来
            // set up PLT function thunk targets to our external funciton eg: _JNIEnv::CallObjectMethod
            // 只要getThunkTarget的isExternal是true就可以。这样那边建模逻辑就会用过来。
            if (f.getParentNamespace().getName().equals(JNI_NAMESPACE) && Utils.JNISymbols.contains(fname)) {
                // assert can find
                Function externalTarget = getCurrentProgram().getListing().getFunctions(Library.UNKNOWN, fname).get(0);
                f.setThunkedFunction(externalTarget);
            }
        }
    }

    public static Map<String, FunctionDefinition> getFuncDefMap(DataTypeManager dtm, String categoryPath) {
        Map<String, FunctionDefinition> dtmap = new HashMap<>();
        Category c = dtm.getCategory(new CategoryPath(categoryPath));
        for(DataType dt: c.getDataTypes()) {
            if (dt instanceof FunctionDefinition) {
                    dtmap.put(dt.getName(), (FunctionDefinition) dt);
            }
        }
        return dtmap;
    }

}
