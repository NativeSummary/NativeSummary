import logging
from io import BytesIO


from elftools.common.exceptions import ELFError, ELFParseError
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)


# TODO weak symbol?
def get_elf_import_export(stream, in_memory=True):
    """
    arg usually `apk_zip.open(so_info)`
    """
    import_names = list()
    export_names = list()

    # without it, become extremely slow sometimes
    if in_memory:
        import zlib
        try:
            stream = BytesIO(stream.read())
        except zlib.error:
            return import_names, export_names
    dyn = None
    try:
        elf = ELFFile(stream)
        dyn = elf.get_section_by_name('.dynsym')
    except (ELFError, ELFParseError) as e:
        logger.warning(repr(e))
        return None, None


    if dyn is None:
        return None, None
    it = dyn.iter_symbols()
    next(it)
    for sym in it:
        # skip index 0
        if sym['st_shndx'] == 'SHN_UNDEF': # import
            import_names.append(sym.name)
        else: # export
            export_names.append(sym.name)
    return import_names, export_names

def so_analysis(stream):
    imp, exp = get_elf_import_export(stream, in_memory=True)
    java_syms = None
    jni_syms = None
    if exp != None:
        java_syms = [i for i in exp if i.startswith('Java_')]
        jni_syms = [i for i in exp if i.startswith('JNI_')]
    return java_syms, jni_syms, imp, exp

SKIP_LIBS = {'Java_io_realm', 'Java_com_sun_jna'} # Java symbol prefix set

def is_skip_libs(jsymbol):
    for prefix in SKIP_LIBS:
        if jsymbol.startswith(prefix):
            return True
    return False
