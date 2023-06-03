import re
import logging


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def get_arg_sig(full_sig):
    assert full_sig[0] == '('
    # split by '(' ')' and remove all space
    argsig = full_sig[1:].split(")")[0]
    return argsig


def extract_names(symbol):
    """Extract class and method name from exported JNI function symbol name.
    https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/design.html
    provides the naming convention.
    sig returned only contains arg. for example, only "J[J[JZ" in "(J [J [J Z)V"
    TODO: this analysis do not support Unicode characters in the name.
    """
    # special case 'Java_com_snappydb_internal_DBImpl__1_1put__Ljava_lang_String_2Ljava_lang_String_2'
    # 'com.googlecode.javacpp.Pointer_00024NativeDeallocator'
    sig = None
    # remove prefix
    assert symbol[:5] == 'Java_'
    symbol = symbol[5:]

    def match2chr(match):
        return chr(int(match.group(1),16))
    symbol = re.sub(r'_0([a-z0-9]{4})', match2chr, symbol)
    symbol = symbol.replace('_2',';').replace('_3', '[')
    # no undersocre, because sig cannot startwith underscore.
    # but may start with '['now
    parts = re.split(r'__(?=[a-zA-Z\[])', symbol)
    assert len(parts) < 3 
    if len(parts) == 2:
        full_method, sig = parts
    else:
        full_method = symbol
    # has undersocre, because method name and classname can contain underscore
    parts = re.split(r'_(?=[a-zA-Z_])', full_method)
    method_name = parts[-1].replace('_1', '_')
    cls_name = '.'.join(parts[0:-1]).replace('_1', '_')
    if sig is not None:
        sig = '/'.join(re.split(r'_(?=[a-zA-Z])', sig))
    return cls_name, method_name, sig


def refactored_class_name(name):
    return f'L{name.replace(".", "/")};'

# https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html
JNI_BASE_TYPES = 'ZBCSIJFD'

# FieldType:
#     BaseType
#     ObjectType
#     ArrayType

# ObjectType:
#     L ClassName ;

# ArrayType:
#     [ ComponentType

# ComponentType:
#     FieldType


def param_str_iter(param_str):
    prefix = ''
    while len(param_str) > 0:
        # match [
        while param_str[0] == '[':
            prefix += '['
            param_str = param_str[1:]
        if param_str[0] in JNI_BASE_TYPES:
            yield prefix + param_str[0]
            prefix = ''
            param_str = param_str[1:]
        elif param_str[0] == 'L':
            ind = param_str.find(';')
            yield prefix + param_str[1:ind].replace('/', '.')
            prefix = ''
            param_str = param_str[ind+1:]
        else:
            raise RuntimeError("parse failed for signature")


def parse_params_from_sig(signature):
    if signature is None:
        return None, False
    signature = signature.replace(' ','')
    # MethodDescriptor: ( ParameterDescriptor* ) ReturnDescriptor
    params_pat = r'^\((?P<params>[\w\d[/;$]*)\)'
    cls_pat = r'L[\d\w/$]*;'
    has_obj = False
    plist = None
    match = re.match(params_pat, signature)
    if match is None:
        return plist, has_obj
    param_str = match.group('params')
    ms = re.findall(cls_pat, param_str)
    if len(ms) > 0:
        has_obj = True
    plist = list(param_str_iter(param_str))
    return plist, has_obj
