import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class DexAnalysisCenter:
    """
    1. collect method marked as native
    2. store mapping result.
    解析结果表示: Java侧方法-> list[Native侧符号(so_name, symbol)]
    """
    UNRESOLVED = 'Unresolved'
    def __init__(self, dex) -> None:
        self.dex = dex
        self.native_methods = None
        self.mappings = None
        self.mappings_by_so = None # dict[soname -> list[(symbol, m)] ]

        # final native function analysis result
        self.native_logs = defaultdict(list) # dict(m -> list[API_RECORDS])
        self._analyze()

    def add_native_logs(self, m, logs):
        self.native_logs[m].append(logs)

    def get_mappings_by_so(self):
        if self.mappings_by_so is not None:
            return self.mappings_by_so
        r = defaultdict(list)
        for m in self.resolved_java():
            for so_name, symbol in self.mappings[m]:
                r[so_name].append((symbol, m))
        self.mappings_by_so = r
        return r

    def _analyze(self):
        if self.dex != None:
            self.native_methods = [m for m in self.dex.get_methods() if 'native' in m.access]
        # init mappings
        self.mappings = dict()
        for m in self.native_methods:
            self.mappings[m] = list()
        self.mappings[DexAnalysisCenter.UNRESOLVED] = list()

    def dump_native_methods(self, file_path):
        with open(file_path, 'a') as f:
            f.write("native methods in dex:\n")
            for ma in self.native_methods:
                mth = ma.get_method()
                f.write(f"  name: {mth.get_name()}, class: {mth.get_class_name()}, access_flags: {mth.get_access_flags_string()}, sig: {mth.get_descriptor()}\n")

    def add_mapping(self, m, so_name, symbol):
        self.mappings[m].append((so_name, symbol))
        if len(self.mappings[m]) != 1 and m != DexAnalysisCenter.UNRESOLVED:
            logger.warning(f"Multiple mapping: {format_method(m)} => {self.mappings[m]}")
    
    def unresolved_java(self):
        return [i for i in self.native_methods if len(self.mappings[i]) == 0]
    
    def resolved_java(self):
        return [i for i in self.native_methods if len(self.mappings[i]) != 0]


    def resolved_percentage(self):
        total = len(self.native_methods)
        if total == 0:
            return 0
        resolved = 0
        for m in self.native_methods:
            if len(self.mappings[m]) != 0:
                resolved += 1
        return resolved / total


def format_method(m):
    return f'{m.get_method().get_class_name().replace("/", ".")[1:-1]} {m.name}'
