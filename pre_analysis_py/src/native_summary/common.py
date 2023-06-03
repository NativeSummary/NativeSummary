import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class HeapObject:
    """
    representing a JNI API return value or JNI argument.
    """
    def __init__(self, value, native_type, source, is_arg, java_type=None) -> None:
        # addr(reference) or BVS(buffer)
        self.value = value
        # 'reference' 'buffer' or keys in jni_type_size
        self.native_type = native_type
        # is JNI argument
        self.is_arg = is_arg
        # ('ret', callsite, api_name) or ('arg', function_addr, argument_ind)
        self.source = source
        self.java_type = java_type #type: str

    def to_json(self):
        return list(self.source)

    @property
    def is_numeric(self):
        from .simprocedure.java_jni import jni_type_size
        return self.native_type in jni_type_size
    
    @property
    def is_buffer(self):
        return self.native_type == 'buffer'

    def __str__(self):
        if self.source[0] == 'arg':
            return f'HeapObject(func {hex(self.source[1])} arg {self.source[2]})'
        elif self.source[0] == 'ret':
            return f'HeapObject({self.source[2]} ret val from {hex(self.source[1])})'
        else:
            return f'HeapObject(Unknown)'
    
    def __repr__(self) -> str:
        return str(self)

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
            getattr(other, 'source', None) == self.source) #and
            # getattr(other, 'arguments', None) == self.arguments)

    def __hash__(self):
        return hash(self.source)


class JNINativeMethod:
    """
    representing the struct
    """
    def __init__(self, name, sig, ptr) -> None:
        self.name = name
        self.sig = sig
        self.ptr = ptr

    def __eq__(self, other):
        return (isinstance(other, self.__class__) and
            getattr(other, 'name', None) == self.name and
            getattr(other, 'sig', None) == self.sig and
            getattr(other, 'ptr', None) == self.ptr)

    def __str__(self):
        return f'JNINativeMethod{{{repr(self.name)}, {repr(self.sig)}, {hex(self.ptr)}}}'

    def __hash__(self):
        return hash((self.name, self.sig, self.ptr))

class stream_tee(object):
    # Based on https://gist.github.com/327585 by Anand Kunal
    def __init__(self, stream1, stream2):
        self.stream1 = stream1
        self.stream2 = stream2
        self.__missing_method_name = None # Hack!
 
    def __getattribute__(self, name):
        return object.__getattribute__(self, name)
 
    def __getattr__(self, name):
        self.__missing_method_name = name # Could also be a property
        return getattr(self, '__methodmissing__')
 
    def __methodmissing__(self, *args, **kwargs):
            # Emit method call to the log copy
            callable2 = getattr(self.stream2, self.__missing_method_name)
            callable2(*args, **kwargs)
 
            # Emit method call to stdout (stream 1)
            callable1 = getattr(self.stream1, self.__missing_method_name)
            return callable1(*args, **kwargs)

class TeeObject(object):
    
    def __init__(self, outf, errf) -> None:
        import sys
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        self.outf = outf
        self.errf = errf

    def __enter__(self):
        import sys
        sys.stdout = stream_tee(sys.stdout, self.outf)
        sys.stderr = stream_tee(sys.stderr, self.errf)
        return self

    def exit(self):
        import sys
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr

    def __exit__(self, exc_type, exc_val, exc_tb):
        import sys
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr

# logging.Formatter('%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s')

class TimeoutException(Exception):
    pass

def timeout_handler(num, frame):
    import signal
    signal.alarm(5) # 重复，防止被内层逻辑catch
    raise TimeoutException()

# use set_alarm(0) to cancel. 必须手动取消才会完全终止，所以可以放到finally里。
def set_alarm(sec):
    import signal
    if sec == 0: signal.alarm(0) # cancel
    if not signal.getsignal(signal.SIGALRM):
        signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(sec)
