import logging
import os

l = logging.getLogger(__name__)

from angr.misc import autoimport
from angr.sim_procedure import SimProcedure

JNI_PROCEDURES = {}

path = os.path.dirname(os.path.abspath(__file__))
skip_dirs = ['definitions']

for pkg_name, package in autoimport.auto_import_packages('native_summary.simprocedure', path, skip_dirs):
    for _, mod in autoimport.filter_module(package, type_req=type(os)):
        for name, proc in autoimport.filter_module(mod, type_req=type, subclass_req=SimProcedure):
            if hasattr(proc, "__provides__"):
                for custom_pkg_name, custom_func_name in proc.__provides__:
                    if custom_pkg_name not in JNI_PROCEDURES:
                        JNI_PROCEDURES[custom_pkg_name] = { }
                    JNI_PROCEDURES[custom_pkg_name][custom_func_name] = proc
            else:
                if pkg_name not in JNI_PROCEDURES:
                    JNI_PROCEDURES[pkg_name] = { }
                JNI_PROCEDURES[pkg_name][name] = proc
                if hasattr(proc, "ALT_NAMES") and proc.ALT_NAMES:
                    for altname in proc.ALT_NAMES:
                        JNI_PROCEDURES[pkg_name][altname] = proc
                if name == 'UnresolvableJumpTarget':
                    JNI_PROCEDURES[pkg_name]['UnresolvableTarget'] = proc

