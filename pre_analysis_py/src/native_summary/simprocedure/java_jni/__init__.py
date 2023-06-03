# Based on angr's source code 'angr.procedures.java_jni'
import collections
import logging
from typing import Optional

from angr.sim_procedure import SimProcedure
from angr.sim_type import (SimTypeChar, SimTypeFunction, SimTypeNum,
                           SimTypePointer)
from angr.state_plugins.sim_action_object import SimActionObject
from archinfo import ArchSoot
from claripy import BVS, BVV, StrSubstr

from ...api_record import add_to_records
from ...arg_resolve import (basic_arg_resolve, get_callsite_from_state,
                            load_string_from_state)
from ...common import HeapObject

l = logging.getLogger(__name__)
l.setLevel(logging.DEBUG)

# numeric value size
# referencing: HeapObject.is_numeric
jni_type_size = {'boolean':  8,
                 'byte':  8,
                 'char': 16,
                 'short': 16,
                 'int': 32,
                 'long': 64,
                 'float': 32,
                 'double': 64}



# ===================Utils=========================

def prepare_value_map_in_project(proj, jvm_ptr, jenv_ptr, dex, update=None):
    # jni return value cache map
    proj.native_summary_jni_obj_map = dict()
    # ref or symble -> object
    proj.native_summary_ref_map = dict()
    proj.native_summary_global_map = dict()
    if update:
        proj.native_summary_global_map.update(update)
    proj.native_summary_global_map['jvm_ptr'] = jvm_ptr
    proj.native_summary_global_map['jenv_ptr'] = jenv_ptr
    proj.native_summary_global_map['dex'] = dex

def get_ref_map_in_project(proj) -> dict:
    return proj.native_summary_ref_map

def get_jni_obj_map_in_project(proj) -> dict:
    """
    JNI API ret value cache map
    """
    return proj.native_summary_jni_obj_map

def get_global_map_in_project(proj) -> dict:
    return proj.native_summary_global_map

def clear_maps_in_project(proj):
    proj.native_summary_jni_obj_map.clear()
    proj.native_summary_ref_map.clear()
    

class JNISimProcedure(SimProcedure):
    """
    Base SimProcedure class for JNI interface functions.
    To use default run function, provide arguments_ty
    """

    # argument types. if this is None, then run function should not use `*args`
    # strings within is used as `resolve_arg`'s `type_hint`
    arguments_ty: Optional[tuple[str]] = None
    # Java type of return value
    return_ty: Optional[str] = None

    # jboolean constants
    JNI_TRUE = 1
    JNI_FALSE = 0
    JNI_OK = 0

    # varg processing
    # Resolve at least this count more arg for varg(`...`)
    LEAST_VARG_COUNT = 0

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        # Setup argument type
        args=self.prototype.args
        returnty = self.prototype.returnty # pointer size, when return_ty == 'reference'
        if self.arguments_ty != None:
            # TODO refine type
            if self.arguments_ty[-1] == '...':
                self.num_args = len(self.arguments_ty) - 1
            else:
                self.num_args = len(self.arguments_ty)
            charp = SimTypePointer(SimTypeChar())
            args = [charp] * self.num_args
        # Setup a SimCC using the correct type for the return value
        if not self.return_ty:
            raise ValueError("Classes implementing JNISimProcedure's must set the return type.")
        else:
            # handle return_ty
            if self.return_ty in jni_type_size:
                # TODO boolean type has only two possible value
                returnty = SimTypeNum(size=jni_type_size[self.return_ty])
            elif self.return_ty == 'void':
                returnty = None
            prototype = SimTypeFunction(args=args,
                                        returnty=returnty)
            # self.cc = DefaultCC[state.arch.name](state.arch)
            self.prototype = prototype
        super(JNISimProcedure, self).execute(state, successors, arguments, ret_to)


    def get_callsite(self):
        return get_callsite_from_state(self.project, self.state)

    def get_jni_obj_map(self):
        return get_jni_obj_map_in_project(self.state.project)

    def get_ref_map(self):
        return get_ref_map_in_project(self.state.project)
    
    def get_global_map(self):
        return get_global_map_in_project(self.state.project)

    def prepare_ret_obj(self, api_name=None):
        if self.return_ty == None or self.return_ty == 'void':
            return None
        # get call site
        callsite = self.get_callsite()
        if api_name == None:
            api_name = type(self).__name__
        # if value already exist, return it. if not, create a intrinsic value and register in map
        key = (callsite, api_name)
        hobj = self.get_jni_obj_map().get(key) #type: HeapObject
        # TODO change to debug
        l.info(f'JNI API {api_name}, callsite: {hex(callsite)}')
        if hobj is not None:
            return hobj
        source = ('ret', callsite, api_name)
        if self.return_ty in jni_type_size:
            value = BVS(f'{api_name}:{hex(callsite)}ret', jni_type_size[self.return_ty])
            hobj = HeapObject(value, self.return_ty, source, False)
            self.get_ref_map()[value._cache_key] = hobj
            pass
        elif self.return_ty == 'buffer':
            value = BVS(f'{api_name}:{hex(callsite)}ret', self.project.arch.bits)
            hobj = HeapObject(value, 'buffer', source, False)
            self.get_ref_map()[value._cache_key] = hobj
        else: # self.return_ty is 'reference'
            ref = self._allocate_native_memory()
            hobj = HeapObject(ref, 'reference', source, False)
            self.get_ref_map()[ref] = hobj
        self.get_jni_obj_map()[key] = hobj
        return hobj

    def resolve_arg(self, arg, type_hint):
        """
        returns set of HeapObject or int, (and string?)
        """
        return basic_arg_resolve(self.state, arg, self.get_ref_map(), type_hint, type(self).__name__)

    def get_self_name(self):
        # 本来可以根据函数地址，计算在函数指针表中的偏移，然后取得到名字。
        # 有一些函数存在直接hook plt的情况，所以还是不动态计算了。
        basic_name = type(self).__name__
        return basic_name

    # 
    def run(self, *args, return_constant=None):
        """
        default run function, handles return value and basic record.
        override to provide additional arg resolution.
        """
        # l.debug(f"{type(self).__name__}: Default run handler.")
        ret = None
        if return_constant != None:
            ret = return_constant
        elif (hobj := self.prepare_ret_obj()) != None:
            ret = hobj.value
        arg_result = []
        args, arguments_ty = self.resolve_vararg(args) # if varg, add additional args
        for arg_exp, argty in zip(args, arguments_ty):
            if argty == None or argty == 'jenv':
                arg_result.append(None)
                continue
            result = self.resolve_arg(arg_exp, argty)
            arg_result.append(result)
        arg_result = tuple(arg_result)
        add_to_records(self.get_callsite(), type(self).__name__, arg_result)
        return ret

    def next_arg(self):
        ptr_type = SimTypePointer(SimTypeChar())
        ptr_type = ptr_type.with_arch(self.arch)
        return self.cc.next_arg(self.arg_session, ptr_type).get_value(self.state)

    def resolve_vararg(self, args, additional_type='reference'):
        """
        handle `...` case, not `va_list`
        return args, arguments_ty
        """
        if self.arguments_ty[-1] != '...':
            return args, self.arguments_ty
        args_ty = list(self.arguments_ty[:-1])
        args = list(args)
        # handle fact generation
        proj = self.project
        cfg = self.get_global_map()['cfg']
        func_addr = self.state.regs.ip # 0x4006b0 for icc_nativetojava
        func_addr = self.state.solver.eval_exact(func_addr, 1)[0]
        callsite_addr = self.get_callsite()
        func_func = proj.kb.functions.get_by_addr(func_addr)
        from angr.analyses.calling_convention import (
            CallingConventionAnalysis, CallSiteFact, DummyFunctionHandler)
        cc_analysis = self.project.analyses[CallingConventionAnalysis].prep()(
            func_func, cfg=cfg,
            analyze_callsites=False)
        fact = CallSiteFact(
            True, # by default we treat all return values as used
        )
        current_cc = self.cc
        # test
        # print(f"callsite: {hex(callsite_addr)}")
        node = cfg.model.get_any_node(func_addr)
        in_edges = cfg.graph.in_edges(node, data=True)
        final_block_addr = None
        caller_func = None
        for src, _, data in in_edges:
            edge_type = data.get('jumpkind', 'Ijk_Call')

            block_addr, inst_addr = src.addr, src.instruction_addrs[-1]
            # print(f"blk: {hex(block_addr)}, inst: {hex(inst_addr)}")
            if inst_addr == callsite_addr:
                final_block_addr = block_addr
                caller_func = proj.kb.functions[src.function_address]
                if edge_type != 'Ijk_Call': l.warn(f"Call edge {hex(callsite_addr)} -> {hex(func_addr)} type is {edge_type}, not 'Ijk_Call'")
                break

        subgraph = cc_analysis._generate_callsite_subgraph(caller_func, final_block_addr)
        from angr.analyses.reaching_definitions.reaching_definitions import \
            ReachingDefinitionsAnalysis
        from angr.knowledge_plugins.key_definitions.constants import (
            OP_AFTER, OP_BEFORE)
        rda = self.project.analyses[ReachingDefinitionsAnalysis].prep()(
                    func_func,
                    func_graph=subgraph,
                    observation_points=[
                        ('insn', callsite_addr, OP_BEFORE),
                        ('node', final_block_addr, OP_AFTER)
                    ],
                    function_handler=DummyFunctionHandler(),
                )
        cc_analysis._analyze_callsite_arguments(current_cc, final_block_addr, callsite_addr, rda, fact)
        # analyze fact.args
        real_arg_count = len(fact.args)
        min_count = len(self.arguments_ty) - 1 + self.LEAST_VARG_COUNT
        if real_arg_count < min_count: # at least one additional
            real_arg_count = min_count
        current_len = len(args)
        for i in range(current_len, real_arg_count):
            args.append(self.next_arg())
            args_ty.append(additional_type)
        return args, args_ty


    #
    # Memory
    #

    def _allocate_native_memory(self, size=1):
        return self.state.project.loader.extern_object.allocate(size=size)

    def _store_in_native_memory(self, data, data_type, addr=None):
        """
        Store in native memory.

        :param data:      Either a single value or a list.
                          Lists get interpreted as an array.
        :param data_type: Java type of the element(s).
        :param addr:      Native store address.
                          If not set, native memory is allocated.
        :return:          Native addr of the stored data.
        """
        # check if addr is symbolic
        if addr is not None and self.state.solver.symbolic(addr):
            raise NotImplementedError('Symbolic addresses are not supported.')
        # lookup native size of the type
        type_size = ArchSoot.sizeof[data_type]
        native_memory_endness = self.state.arch.memory_endness
        # store single value
        if isinstance(data, int):
            if addr is None:
                addr = self._allocate_native_memory(size=type_size//8)
            value = self.state.solver.BVV(data, type_size)
            self.state.memory.store(addr, value, endness=native_memory_endness)
        # store array
        elif isinstance(data, list):
            if addr is None:
                addr = self._allocate_native_memory(size=type_size*len(data)//8)
            for idx, value in enumerate(data):
                memory_addr = addr+idx*type_size//8
                self.state.memory.store(memory_addr, value, endness=native_memory_endness)
        # return native addr
        return addr

    # TODO replace with load_from_state in arg_resolve.py
    def _load_from_native_memory(self, addr, data_type=None, data_size=None,
                                no_of_elements=1, return_as_list=False):
        """
        Load from native memory.

        :param addr:            Native load address.
        :param data_type:       Java type of elements.
                                If set, all loaded elements are casted to this type.
        :param data_size:       Size of each element.
                                If not set, size is determined based on the given type.
        :param no_of_elements:  Number of elements to load.
        :param return_as_list:  Whether to wrap a single element in a list.
        :return:                The value or a list of loaded element(s).
        """
        # check if addr is symbolic
        if addr is not None and self.state.solver.symbolic(addr):
            raise NotImplementedError('Symbolic addresses are not supported.')
        # if data size is not set, derive it from the type
        if not data_size:
            if data_type:
                data_size = jni_type_size[data_type]//8
            else:
                raise ValueError("Cannot determine the data size w/o a type.")
        native_memory_endness = self.state.arch.memory_endness
        # load elements
        values = []
        for i in range(no_of_elements):
            value = self.state.memory.load(addr + i*data_size,
                                          size=data_size,
                                          endness=native_memory_endness)
            if data_type:
                value = self.state.project.simos.cast_primitive(self.state, value=value, to_type=data_type)
            values.append(value)
        # return element(s)
        if no_of_elements == 1 and not return_as_list:
            return values[0]
        else:
            return values

    def _load_string_from_native_memory(self, addr_):
        """
        Load zero terminated UTF-8 string from native memory.

        :param addr_: Native load address.
        :return:      Loaded string.
        """
        return load_string_from_state(self.state, addr_)

    def _store_string_in_native_memory(self, string, addr=None):
        """
        Store given string UTF-8 encoded and zero terminated in native memory.

        :param str string:  String
        :param addr:        Native store address.
                            If not set, native memory is allocated.
        :return:            Native address of the string.
        """
        if addr is None:
            addr = self._allocate_native_memory(size=len(string)+1)
        else:
            # check if addr is symbolic
            if self.state.solver.symbolic(addr):
                l.error("Storing strings at symbolic addresses is not implemented. "
                        "Continue execution with concretized address.")
            addr = self.state.solver.eval(addr)

        # warn if string is symbolic
        if self.state.solver.symbolic(string):
            l.warning('Support for symbolic strings, passed to native code, is limited. '
                      'String will get concretized after `ReleaseStringUTFChars` is called.')

        # store chars one by one
        str_len = len(string) // 8
        for idx in range(str_len):
            str_byte = StrSubstr(idx, 1, string)
            self.state.memory.store(addr+idx, str_byte)

        # store terminating zero
        self.state.memory.store(len(string), BVV(0, 8))

        return addr

    #
    # MISC
    #

    def _normalize_array_idx(self, idx):
        """
        In Java, all array indices are represented by a 32 bit integer and
        consequently we are using in the Soot engine a 32bit bitvector for this.
        This function normalize the given index to follow this "convention".

        :return: Index as a 32bit bitvector.
        """
        if isinstance(idx, SimActionObject):
            idx = idx.to_claripy()
        if self.arch.memory_endness == "Iend_LE":
            return idx.reversed.get_bytes(index=0, size=4).reversed
        else:
            return idx.get_bytes(index=0, size=4)

#
# JNI function table
# => Map all interface function to the name of their corresponding SimProcedure
jni_functions = collections.OrderedDict() # type: collections.OrderedDict[str, str]
not_implemented = "UnsupportedJNIFunction"

# Reserved Entries
jni_functions["reserved0"] = not_implemented
jni_functions["reserved1"] = not_implemented
jni_functions["reserved2"] = not_implemented
jni_functions["reserved3"] = not_implemented

# Version Information
jni_functions["GetVersion"] = "GetVersion"

# Class and Interface Operations
jni_functions["DefineClass"] = not_implemented
jni_functions["FindClass"] = "FindClass"
jni_functions["FromReflectedMethod"] = not_implemented
jni_functions["FromReflectedField"] = not_implemented
jni_functions["ToReflectedMethod"] = not_implemented
jni_functions["GetSuperclass"] = "GetSuperclass"
jni_functions["IsAssignableFrom"] = not_implemented
jni_functions["ToReflectedField"] = not_implemented

# Exceptions
jni_functions["Throw"] = "Throw"
jni_functions["ThrowNew"] = "ThrowNew"
jni_functions["ExceptionOccurred"] = "ExceptionOccurred"
jni_functions["ExceptionDescribe"] = "ExceptionDescribe"
jni_functions["ExceptionClear"] = "ExceptionClear"
jni_functions["FatalError"] = "FatalError"

# Global and Local References
jni_functions["PushLocalFrame"] = not_implemented
jni_functions["PopLocalFrame"] = not_implemented
jni_functions["NewGlobalRef"] = "NewGlobalRef"
jni_functions["DeleteGlobalRef"] = "DeleteGlobalRef"
jni_functions["DeleteLocalRef"] = "DeleteLocalRef"

# Object Operations
jni_functions["IsSameObject"] = "IsSameObject"
jni_functions["NewLocalRef"] = "NewLocalRef"
jni_functions["EnsureLocalCapacity"] = not_implemented
jni_functions["AllocObject"] = "AllocObject"
jni_functions["NewObject"] = "NewObject"
jni_functions["NewObjectV"] = not_implemented
jni_functions["NewObjectA"] = not_implemented
jni_functions["GetObjectClass"] = "GetObjectClass"
jni_functions["IsInstanceOf"] = "IsInstanceOf"

# Instance Method Calls
jni_functions["GetMethodID"] = "GetMethodID"
jni_functions["CallObjectMethod"] = "CallObjectMethod"
jni_functions["CallObjectMethodV"] = not_implemented
jni_functions["CallObjectMethodA"] = "CallObjectMethodA"
jni_functions["CallBooleanMethod"] = "CallBooleanMethod"
jni_functions["CallBooleanMethodV"] = not_implemented
jni_functions["CallBooleanMethodA"] = "CallBooleanMethodA"
jni_functions["CallByteMethod"] = "CallByteMethod"
jni_functions["CallByteMethodV"] = not_implemented
jni_functions["CallByteMethodA"] = "CallByteMethodA"
jni_functions["CallCharMethod"] = "CallCharMethod"
jni_functions["CallCharMethodV"] = not_implemented
jni_functions["CallCharMethodA"] = "CallCharMethodA"
jni_functions["CallShortMethod"] = "CallShortMethod"
jni_functions["CallShortMethodV"] = not_implemented
jni_functions["CallShortMethodA"] = "CallShortMethodA"
jni_functions["CallIntMethod"] = "CallIntMethod"
jni_functions["CallIntMethodV"] = not_implemented
jni_functions["CallIntMethodA"] = "CallIntMethodA"
jni_functions["CallLongMethod"] = "CallLongMethod"
jni_functions["CallLongMethodV"] = not_implemented
jni_functions["CallLongMethodA"] = "CallLongMethodA"
jni_functions["CallFloatMethod"] = not_implemented
jni_functions["CallFloatMethodV"] = not_implemented
jni_functions["CallFloatMethodA"] = not_implemented
jni_functions["CallDoubleMethod"] = not_implemented
jni_functions["CallDoubleMethodV"] = not_implemented
jni_functions["CallDoubleMethodA"] = not_implemented
jni_functions["CallVoidMethod"] = "CallVoidMethod"
jni_functions["CallVoidMethodV"] = not_implemented
jni_functions["CallVoidMethodA"] = "CallVoidMethodA"

#Calling Instance Methods of a Superclass
jni_functions["CallNonvirtualObjectMethod"] = "CallNonvirtualObjectMethod"
jni_functions["CallNonvirtualObjectMethodV"] = not_implemented
jni_functions["CallNonvirtualObjectMethodA"] = "CallNonvirtualObjectMethodA"
jni_functions["CallNonvirtualBooleanMethod"] = "CallNonvirtualBooleanMethod"
jni_functions["CallNonvirtualBooleanMethodV"] = not_implemented
jni_functions["CallNonvirtualBooleanMethodA"] = "CallNonvirtualBooleanMethodA"
jni_functions["CallNonvirtualByteMethod"] = "CallNonvirtualByteMethod"
jni_functions["CallNonvirtualByteMethodV"] = not_implemented
jni_functions["CallNonvirtualByteMethodA"] = "CallNonvirtualByteMethodA"
jni_functions["CallNonvirtualCharMethod"] = "CallNonvirtualCharMethod"
jni_functions["CallNonvirtualCharMethodV"] = not_implemented
jni_functions["CallNonvirtualCharMethodA"] = "CallNonvirtualCharMethodA"
jni_functions["CallNonvirtualShortMethod"] = "CallNonvirtualShortMethod"
jni_functions["CallNonvirtualShortMethodV"] = not_implemented
jni_functions["CallNonvirtualShortMethodA"] = "CallNonvirtualShortMethodA"
jni_functions["CallNonvirtualIntMethod"] = "CallNonvirtualIntMethod"
jni_functions["CallNonvirtualIntMethodV"] = not_implemented
jni_functions["CallNonvirtualIntMethodA"] = "CallNonvirtualIntMethodA"
jni_functions["CallNonvirtualLongMethod"] = "CallNonvirtualLongMethod"
jni_functions["CallNonvirtualLongMethodV"] = not_implemented
jni_functions["CallNonvirtualLongMethodA"] = "CallNonvirtualLongMethodA"
jni_functions["CallNonvirtualFloatMethod"] = not_implemented
jni_functions["CallNonvirtualFloatMethodV"] = not_implemented
jni_functions["CallNonvirtualFloatMethodA"] = not_implemented
jni_functions["CallNonvirtualDoubleMethod"] = not_implemented
jni_functions["CallNonvirtualDoubleMethodV"] = not_implemented
jni_functions["CallNonvirtualDoubleMethodA"] = not_implemented
jni_functions["CallNonvirtualVoidMethod"] = "CallNonvirtualVoidMethod"
jni_functions["CallNonvirtualVoidMethodV"] = not_implemented
jni_functions["CallNonvirtualVoidMethodA"] = "CallNonvirtualVoidMethodA"

# Instance Field Access
jni_functions["GetFieldID"] = "GetFieldID"
jni_functions["GetObjectField"] = "GetObjectField"
jni_functions["GetBooleanField"] = "GetBooleanField"
jni_functions["GetByteField"] = "GetByteField"
jni_functions["GetCharField"] = "GetCharField"
jni_functions["GetShortField"] = "GetShortField"
jni_functions["GetIntField"] =  "GetIntField"
jni_functions["GetLongField"] = "GetLongField"
jni_functions["GetFloatField"] = not_implemented
jni_functions["GetDoubleField"] = not_implemented
jni_functions["SetObjectField"] = "SetObjectField"
jni_functions["SetBooleanField"] = "SetBooleanField"
jni_functions["SetByteField"] = "SetByteField"
jni_functions["SetCharField"] = "SetCharField"
jni_functions["SetShortField"] = "SetShortField"
jni_functions["SetIntField"] = "SetIntField"
jni_functions["SetLongField"] = "SetLongField"
jni_functions["SetFloatField"] = not_implemented
jni_functions["SetDoubleField"] = not_implemented

# Static Method Calls
jni_functions["GetStaticMethodID"] = "GetStaticMethodID"
jni_functions["CallStaticObjectMethod"] = "CallStaticObjectMethod"
jni_functions["CallStaticObjectMethodV"] = not_implemented
jni_functions["CallStaticObjectMethodA"] = "CallStaticObjectMethodA"
jni_functions["CallStaticBooleanMethod"] = "CallStaticBooleanMethod"
jni_functions["CallStaticBooleanMethodV"] = not_implemented
jni_functions["CallStaticBooleanMethodA"] = "CallStaticBooleanMethodA"
jni_functions["CallStaticByteMethod"] = "CallStaticByteMethod"
jni_functions["CallStaticByteMethodV"] = not_implemented
jni_functions["CallStaticByteMethodA"] = "CallStaticByteMethodA"
jni_functions["CallStaticCharMethod"] = "CallStaticCharMethod"
jni_functions["CallStaticCharMethodV"] = not_implemented
jni_functions["CallStaticCharMethodA"] = "CallStaticCharMethodA"
jni_functions["CallStaticShortMethod"] = "CallStaticShortMethod"
jni_functions["CallStaticShortMethodV"] = not_implemented
jni_functions["CallStaticShortMethodA"] = "CallStaticShortMethodA"
jni_functions["CallStaticIntMethod"] = "CallStaticIntMethod"
jni_functions["CallStaticIntMethodV"] = not_implemented
jni_functions["CallStaticIntMethodA"] = "CallStaticIntMethodA"
jni_functions["CallStaticLongMethod"] = "CallStaticLongMethod"
jni_functions["CallStaticLongMethodV"] = not_implemented
jni_functions["CallStaticLongMethodA"] = "CallStaticLongMethodA"
jni_functions["CallStaticFloatMethod"] = not_implemented
jni_functions["CallStaticFloatMethodV"] = not_implemented
jni_functions["CallStaticFloatMethodA"] = not_implemented
jni_functions["CallStaticDoubleMethod"] = not_implemented
jni_functions["CallStaticDoubleMethodV"] = not_implemented
jni_functions["CallStaticDoubleMethodA"] = not_implemented
jni_functions["CallStaticVoidMethod"] = "CallStaticVoidMethod"
jni_functions["CallStaticVoidMethodV"] = not_implemented
jni_functions["CallStaticVoidMethodA"] = "CallStaticVoidMethodA"

# Static Field Access
jni_functions["GetStaticFieldID"] = "GetStaticFieldID"
jni_functions["GetStaticObjectField"] = "GetStaticObjectField"
jni_functions["GetStaticBooleanField"] = "GetStaticBooleanField"
jni_functions["GetStaticByteField"] = "GetStaticByteField"
jni_functions["GetStaticCharField"] = "GetStaticCharField"
jni_functions["GetStaticShortField"] = "GetStaticShortField"
jni_functions["GetStaticIntField"] = "GetStaticIntField"
jni_functions["GetStaticLongField"] = "GetStaticLongField"
jni_functions["GetStaticFloatField"] = not_implemented
jni_functions["GetStaticDoubleField"] = not_implemented
jni_functions["SetStaticObjectField"] = "SetStaticObjectField"
jni_functions["SetStaticBooleanField"] = "SetStaticBooleanField"
jni_functions["SetStaticByteField"] = "SetStaticByteField"
jni_functions["SetStaticCharField"] = "SetStaticCharField"
jni_functions["SetStaticShortField"] = "SetStaticShortField"
jni_functions["SetStaticIntField"] = "SetStaticIntField"
jni_functions["SetStaticLongField"] = "SetStaticLongField"
jni_functions["SetStaticFloatField"] = not_implemented
jni_functions["SetStaticDoubleField"] = not_implemented

# String Operations
jni_functions["NewString"] = not_implemented
jni_functions["GetStringLength"] = not_implemented
jni_functions["GetStringChars"] = not_implemented
jni_functions["ReleaseStringChars"] = not_implemented
jni_functions["NewStringUTF"] = "NewStringUTF"
jni_functions["GetStringUTFLength"] = "GetStringUTFLength"
jni_functions["GetStringUTFChars"] = "GetStringUTFChars"
jni_functions["ReleaseStringUTFChars"] = "ReleaseStringUTFChars"

# Array Operations
jni_functions["GetArrayLength"] =  "GetArrayLength"
jni_functions["NewObjectArray"] = "NewObjectArray"
jni_functions["GetObjectArrayElement"] = "GetObjectArrayElement"
jni_functions["SetObjectArrayElement"] = "SetObjectArrayElement"
jni_functions["NewBooleanArray"] = "NewBooleanArray"
jni_functions["NewByteArray"] = "NewByteArray"
jni_functions["NewCharArray"] = "NewCharArray"
jni_functions["NewShortArray"] = "NewShortArray"
jni_functions["NewIntArray"] =  "NewIntArray"
jni_functions["NewLongArray"] = "NewLongArray"
jni_functions["NewFloatArray"] = not_implemented
jni_functions["NewDoubleArray"] = not_implemented
jni_functions["GetBooleanArrayElements"] = "GetArrayElements"
jni_functions["GetByteArrayElements"] = "GetArrayElements"
jni_functions["GetCharArrayElements"] = "GetArrayElements"
jni_functions["GetShortArrayElements"] = "GetArrayElements"
jni_functions["GetIntArrayElements"] = "GetArrayElements"
jni_functions["GetLongArrayElements"] = "GetArrayElements"
jni_functions["GetFloatArrayElements"] = not_implemented
jni_functions["GetDoubleArrayElements"] = not_implemented
jni_functions["ReleaseBooleanArrayElements"] = not_implemented
jni_functions["ReleaseByteArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseCharArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseShortArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseIntArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseLongArrayElements"] = "ReleaseArrayElements"
jni_functions["ReleaseFloatArrayElements"] = not_implemented
jni_functions["ReleaseDoubleArrayElements"] = not_implemented
jni_functions["GetBooleanArrayRegion"] = "GetArrayRegion"
jni_functions["GetByteArrayRegion"] = "GetArrayRegion"
jni_functions["GetCharArrayRegion"] = "GetArrayRegion"
jni_functions["GetShortArrayRegion"] = "GetArrayRegion"
jni_functions["GetIntArrayRegion"] = "GetArrayRegion"
jni_functions["GetLongArrayRegion"] = "GetArrayRegion"
jni_functions["GetFloatArrayRegion"] = not_implemented
jni_functions["GetDoubleArrayRegion"] = not_implemented
jni_functions["SetBooleanArrayRegion"] = "SetArrayRegion"
jni_functions["SetByteArrayRegion"] = "SetArrayRegion"
jni_functions["SetCharArrayRegion"] = "SetArrayRegion"
jni_functions["SetShortArrayRegion"] = "SetArrayRegion"
jni_functions["SetIntArrayRegion"] = "SetArrayRegion"
jni_functions["SetLongArrayRegion"] = "SetArrayRegion"
jni_functions["SetFloatArrayRegion"] = not_implemented
jni_functions["SetDoubleArrayRegion"] = not_implemented

# Native Method Registration
jni_functions["RegisterNatives"] = "RegisterNatives"
jni_functions["UnregisterNatives"] = "UnregisterNatives"

# Monitor Operations
jni_functions["MonitorEnter"] = not_implemented
jni_functions["MonitorExit"] = not_implemented

# JavaVM Interface
jni_functions["GetJavaVM"] = not_implemented

# Misc
jni_functions["GetStringRegion"] = not_implemented
jni_functions["GetStringUTFRegion"] = not_implemented
jni_functions["GetPrimitiveArrayCritical"] = "GetArrayElements"
jni_functions["ReleasePrimitiveArrayCritical"] = "ReleaseArrayElements"
jni_functions["GetStringCritical"] = not_implemented
jni_functions["ReleaseStringCritical"] = not_implemented
jni_functions["NewWeakGlobalRef"] = "NewGlobalRef"
jni_functions["DeleteWeakGlobalRef"] = "DeleteGlobalRef"
jni_functions["ExceptionCheck"] = "ExceptionCheck"
jni_functions["NewDirectByteBuffer"] = "NewDirectByteBuffer"
jni_functions["GetDirectBufferAddress"] = "GetDirectBufferAddress"
jni_functions["GetDirectBufferCapacity"] = "GetDirectBufferCapacity"
jni_functions["GetObjectRefType"] = not_implemented

jvm_functions = collections.OrderedDict()
not_implemented = "UnsupportedJENVFunction"

# Reserved Entries
jvm_functions["reserved1"] = not_implemented
jvm_functions["reserved2"] = not_implemented
jvm_functions["reserved3"] = not_implemented

jvm_functions["DestroyJavaVM"] = not_implemented
jvm_functions["AttachCurrentThread"] = not_implemented
jvm_functions["DetachCurrentThread"] = not_implemented

jvm_functions["GetEnv"] = "GetEnv"

jvm_functions["AttachCurrentThreadAsDaemon"] = not_implemented
