
import json
import logging
import sys
from collections import OrderedDict
from typing import Optional
from zipfile import ZipFile

from androguard.misc import AnalyzeAPK

from .dex_analysis import DexAnalysisCenter, format_method
from .elf_analysis import so_analysis
from .symbol_parser import extract_names, get_arg_sig, refactored_class_name

logger = logging.getLogger(__name__)

arch_supported = ['arm64-v8a', 'armeabi-v7a', 'armeabi'] # , 'x86_64'?
arch_supported_prefer_32 = ['armeabi-v7a', 'armeabi', 'arm64-v8a']
debug_prefer_32 = False
if debug_prefer_32:
    def_arch_supported = arch_supported_prefer_32
else:
    def_arch_supported = arch_supported

def select_abi(apk_zip, prefer_32=None):
    is_flutter = False
    has_so = True

    so_arch_counter = OrderedDict()
    # print(f"prefer_32: {prefer_32}")
    if prefer_32 is None:
        my_arch_supported = def_arch_supported
    elif prefer_32:
        my_arch_supported = arch_supported_prefer_32
    else:
        my_arch_supported = arch_supported
    for i in my_arch_supported:
        so_arch_counter[i] = 0
    for name in apk_zip.namelist():
        if not is_flutter and name.endswith("libflutter.so"):
            is_flutter = True
            logger.warning("Flutter App detected!")
        # count so under arch
        if name.startswith('lib/') and name.endswith(".so"):
            path_parts = name.split("/")
            if len(path_parts) != 3: logger.warning("Warning: irregular path in zip file: " + name)
            arch = path_parts[1]
            if arch in so_arch_counter:
                so_arch_counter[arch] += 1
            # else:
            #     logger.warning("Warning: irregular arch in zip file:" + name)
    # If multiple items are maximal, the function returns the first one encountered
    arch_selected = max(so_arch_counter, key=so_arch_counter.get)
    if so_arch_counter[arch_selected] == 0:
        logger.error("No .so file in abi-dir.")
        has_so = False
    return arch_selected, is_flutter, has_so


def apk_pre_analysis(apk_path, analyse_dex=True, prefer_32=None):
    """
    resolve static binding. print result.
    if analyse_dex is False, dex will be None
    """
    # so_name -> (checksum, recognized_java_symbols, import, export)
    so_stat = dict()
    is_flutter = False
    has_so = True
    has_javasym = False
    apk = None
    dex = None #type: Optional[DexAnalysisCenter]

    # 2 收集Native侧Java_开头的符号，依次处理。
    apk_zip = ZipFile(apk_path)
    arch_selected, is_flutter, has_so = select_abi(apk_zip, prefer_32)
    if has_so:
        logger.info(f"Select arch {arch_selected} for analysis.")

    for so_info in apk_zip.infolist():
        if so_info.filename.startswith("lib/" + arch_selected) and so_info.filename.endswith(".so"):
            path_parts = so_info.filename.split("/")
            if len(path_parts) != 3: logger.warning("Warning: irregular path in zip file: " + so_info.filename)
            # update so_info
            filename = path_parts[-1]
            checksum = so_info.CRC
            # print(filename)
            java_syms, jni_syms, imp, exp = so_analysis(apk_zip.open(so_info))
            so_stat[filename] = (checksum, java_syms, imp, exp)
            if (java_syms != None and len(java_syms) > 0) or (jni_syms != None and len(jni_syms) > 0):
                has_javasym = True
            # TODO JNI related symbols in import

    if analyse_dex:
        # time consumeing!!!
        apk, _, dex = AnalyzeAPK(apk_path)
        # 收集Java侧有native标记的函数
        dex = DexAnalysisCenter(dex)

        for filename in so_stat:
            java_syms = so_stat[filename][1]
            if java_syms is None:
                continue
            for sym in java_syms:
                # 2.1 解析Native侧符号（考虑重载）
                clz, method, sig = extract_names(sym)
                refactored_cls_name = refactored_class_name(clz)
                # 2.2 去遍历Java侧方法找对应，找不到就放到无法解析的里面（如果对应了2个及以上报warning）
                for m in dex.native_methods:
                    if m.get_method().get_class_name() == refactored_cls_name \
                        and m.name == method:
                        if sig:
                            msig = m.get_method().get_descriptor() # (J [J [J Z)V
                            argsig = get_arg_sig(msig).replace(' ', '')
                            sig = sig.replace(' ', '')
                            if argsig != sig:
                                continue
                        dex.add_mapping(m, filename, sym)
                        break
                else:
                    dex.add_mapping(DexAnalysisCenter.UNRESOLVED, filename, sym)

            # 2.3 统计：解析失败的Java侧方法数量。
            # 3 打印解析结果：（成功解析的Java侧函数，so库）集合，失败的Java侧，（失败的Native侧，so库）集合。
    tags = {'is_flutter': is_flutter, 'has_so':has_so, 'has_javasym':has_javasym}
    return apk, dex, arch_selected, so_stat, tags


def get_resolve_report(apk_path, dex, arch_selected, so_stat):
    result = dict()
    result['file'] = apk_path
    result['arch_selected'] = arch_selected
    result['so_stat'] = so_stat
    # calculated
    result['resolve_percentage'] = dex.resolved_percentage()
    result['failed_native_symbol'] = dex.mappings[DexAnalysisCenter.UNRESOLVED]
    result['failed_java_mth'] = list(map(format_method, dex.unresolved_java()))
    result['success_java_mth'] = list(map(format_method, dex.resolved_java()))
    return result


def print_resolve_report(out_path, apk_path, dex, arch_selected, so_stat):
    with open(out_path, 'w') as f:
        report = get_resolve_report(apk_path, dex, arch_selected, so_stat)
        json.dump(report, f)
    return report


# currenly not in use
def set_exc_hook():
    import sys
    def my_except_hook(exctype, value, traceback):
        if exctype == KeyboardInterrupt:
            pass
        sys.__excepthook__(exctype, value, traceback)
    sys.excepthook = my_except_hook


if __name__ == '__main__':
    # usage: apk_path
    # TODO
    apk_path = sys.argv[1]
    
    # apk_pre_analysis("/mnt/c/Users/xxx/ExistingDatasets/NativeFlowBench-master/apks/native_leak.apk")
