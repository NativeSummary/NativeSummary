import logging

from . import JNISimProcedure
# from ...engines.soot.field_dispatcher import resolve_field

l = logging.getLogger(__name__)

# pylint: disable=arguments-differ,unused-argument, missing-class-docstring

#
# GetFieldID / GetStaticFieldID
#

class GetFieldID(JNISimProcedure):

    # ptr_env, field_class_, ptr_field_name, ptr_field_sig
    arguments_ty = ('jenv', 'reference', 'string', 'string')
    return_ty = "reference"

    # TODO return null and throw an NoSuchFieldError ?
    def run(self, *args, **kwargs):
        l.warning(f'GetFieldID: return value is nullable, but currently not implemented.')
        # .union(0) ? TODO
        return super().run(*args, **kwargs)


class GetStaticFieldID(GetFieldID):
    pass


#
# GetStatic<Type>Field
#

class GetStaticField(JNISimProcedure):
    # ptr_env, jclass clazz, field_id_
    arguments_ty = ('jenv', 'reference', 'reference')

class GetStaticBooleanField(GetStaticField):
    return_ty = 'boolean'
class GetStaticByteField(GetStaticField):
    return_ty = 'byte'
class GetStaticCharField(GetStaticField):
    return_ty = 'char'
class GetStaticShortField(GetStaticField):
    return_ty = 'short'
class GetStaticIntField(GetStaticField):
    return_ty = 'int'
class GetStaticLongField(GetStaticField):
    return_ty = 'long'
class GetStaticObjectField(GetStaticField):
    return_ty = 'reference'

#
# SetStaticField
#

class SetStaticField(JNISimProcedure):

    # ptr_env, field_class_, field_id_, value_
    arguments_ty = ('jenv', 'reference', 'reference', 'reference')
    return_ty = 'void'


# TODO type_hint for `value_`
class SetStaticBooleanField(SetStaticField):
    pass
class SetStaticByteField(SetStaticField):
    pass
class SetStaticCharField(SetStaticField):
    pass
class SetStaticShortField(SetStaticField):
    pass
class SetStaticIntField(SetStaticField):
    pass
class SetStaticLongField(SetStaticField):
    pass
class SetStaticObjectField(SetStaticField):
    pass


#
# Get<Type>Field
#

class GetField(JNISimProcedure):
    # ptr_env, obj_, field_id_
    arguments_ty = ('jenv', 'reference', 'reference')


class GetBooleanField(GetField):
    return_ty = 'boolean'
class GetByteField(GetField):
    return_ty = 'byte'
class GetCharField(GetField):
    return_ty = 'char'
class GetShortField(GetField):
    return_ty = 'short'
class GetIntField(GetField):
    return_ty = 'int'
class GetLongField(GetField):
    return_ty = 'long'
class GetObjectField(GetField):
    return_ty = 'reference'

#
# Set<Type>Field
#

class SetField(JNISimProcedure):

    # ptr_env, obj_, field_id_, value_
    arguments_ty = ('jenv', 'reference', 'reference', 'reference')
    return_ty = 'void'

class SetBooleanField(SetField):
    pass
class SetByteField(SetField):
    pass
class SetCharField(SetField):
    pass
class SetShortField(SetField):
    pass
class SetIntField(SetField):
    pass
class SetLongField(SetField):
    pass
class SetObjectField(SetField):
    pass
