import unittest,os,json,sys
import tempfile

file_path = os.path.realpath(__file__)
file_dir = os.path.dirname(file_path)
sys.path.insert(1, file_dir)

from utils import *

MIN_SS_FILE = os.path.join(file_dir, "..", "benchmarks", "minSourcesAndSinks.txt")

NFB_DATASET_PATH = os.path.join(file_dir, "..", "benchmarks", "nfb")
NFBE_DATASET_PATH = os.path.join(file_dir, "..", "benchmarks", "nfbe")
JUB_DATASET_PATH = os.path.join(file_dir, "..", "benchmarks", "jucifybench")


# sink(method, statement) => source(method, statement)
NativeFlowBenchAnswer = {
    # ICC related requires ICC model, here we check native related partial flows.
#   'icc_javatonative.apk': None,
  'icc_nativetojava.apk': { ( ( '<org.arguslab.icc_nativetojava.FooActivity: '
                                'void onCreate(android.os.Bundle)>',
                                'staticinvoke <android.util.Log: int '
                                'i(java.lang.String,java.lang.String)>("imei", '
                                '$r)'),
                              ( '<org.arguslab.icc_nativetojava.FooActivity: '
                                'void onCreate(android.os.Bundle)>',
                                '$r = virtualinvoke '
                                '$r.<android.content.Intent: java.lang.String '
                                'getStringExtra(java.lang.String)>("data")')),
                            ( ( '<org.arguslab.icc_nativetojava.MainActivity: '
                                'void sendIntent(java.lang.String)>',
                                'virtualinvoke $r.<android.content.Context: '
                                'void '
                                'startActivity(android.content.Intent)>($r)'),
                              ( '<org.arguslab.icc_nativetojava.MainActivity: '
                                'void leakImei()>',
                                '$r = virtualinvoke '
                                '$r.<android.telephony.TelephonyManager: '
                                'java.lang.String getDeviceId()>()'))},
  'native_complexdata.apk': { ( ( '<org.arguslab.native_complexdata.MainActivity: '
                                  'void '
                                  'send(org.arguslab.native_complexdata.ComplexData)>',
                                  'staticinvoke <android.util.Log: int '
                                  'i(java.lang.String,java.lang.String)>("data", '
                                  '$r)'),
                                ( '<org.arguslab.native_complexdata.MainActivity: '
                                  'void leakImei()>',
                                  '$r = virtualinvoke '
                                  '$r.<android.telephony.TelephonyManager: '
                                  'java.lang.String getDeviceId()>()'))},
#   'native_complexdata_stringop.apk': None,
  'native_dynamic_register_multiple.apk': { ( ( '<org.arguslab.native_dynamic_register_multiple.MainActivity: '
                                                'void send(java.lang.String)>',
                                                'staticinvoke '
                                                '<android.util.Log: int '
                                                'i(java.lang.String,java.lang.String)>("dynamic_register_multiple", '
                                                '$r)'),
                                              ( '<org.arguslab.native_dynamic_register_multiple.MainActivity: '
                                                'void leakImei()>',
                                                '$r = virtualinvoke '
                                                '$r.<android.telephony.TelephonyManager: '
                                                'java.lang.String '
                                                'getDeviceId()>()'))},
  'native_heap_modify.apk': { ( ( '<org.arguslab.native_heap_modify.MainActivity: '
                                  'void leakImei()>',
                                  'staticinvoke <android.util.Log: int '
                                  'i(java.lang.String,java.lang.String)>("str", '
                                  '$r)'),
                                ( '<org.arguslab.native_heap_modify.MainActivity: '
                                  'void '
                                  'heapModify(android.content.Context,org.arguslab.native_heap_modify.Data)>',
                                  '$r = virtualinvoke '
                                  '$r.<android.telephony.TelephonyManager: '
                                  'java.lang.String getDeviceId()>()'))},
  'native_leak.apk': { ( ( '<org.arguslab.native_leak.MainActivity: void '
                           'send(java.lang.String)>',
                           'staticinvoke <android.util.Log: int '
                           'i(java.lang.String,java.lang.String)>("leak", '
                           '$r)'),
                         ( '<org.arguslab.native_leak.MainActivity: void '
                           'leakImei()>',
                           '$r = virtualinvoke '
                           '$r.<android.telephony.TelephonyManager: '
                           'java.lang.String getDeviceId()>()'))},
  'native_leak_array.apk': { ( ( '<org.arguslab.native_leak_array.MainActivity: '
                                 'void send(java.lang.String[])>',
                                 'staticinvoke <android.util.Log: int '
                                 'i(java.lang.String,java.lang.String)>("leak", '
                                 '$r)'),
                               ( '<org.arguslab.native_leak_array.MainActivity: '
                                 'void leakImei()>',
                                 '$r = virtualinvoke '
                                 '$r.<android.telephony.TelephonyManager: '
                                 'java.lang.String getDeviceId()>()'))},
  'native_leak_dynamic_register.apk': { ( ( '<org.arguslab.native_leak_dynamic_register.MainActivity: '
                                            'void send(java.lang.String)>',
                                            'staticinvoke <android.util.Log: '
                                            'int '
                                            'i(java.lang.String,java.lang.String)>("leak_dynamic_register", '
                                            '$r)'),
                                          ( '<org.arguslab.native_leak_dynamic_register.MainActivity: '
                                            'void leakImei()>',
                                            '$r = virtualinvoke '
                                            '$r.<android.telephony.TelephonyManager: '
                                            'java.lang.String '
                                            'getDeviceId()>()'))},
  'native_method_overloading.apk': { ( ( '<org.arguslab.native_method_overloading.MainActivity: '
                                         'void '
                                         'send(int[],java.lang.String[],java.lang.String,double)>',
                                         'staticinvoke <android.util.Log: int '
                                         'i(java.lang.String,java.lang.String)>("method_overloading", '
                                         '$r)'),
                                       ( '<org.arguslab.native_method_overloading.MainActivity: '
                                         'void leakImei()>',
                                         '$r = virtualinvoke '
                                         '$r.<android.telephony.TelephonyManager: '
                                         'java.lang.String getDeviceId()>()'))},
  'native_multiple_interactions.apk': { ( ( '<org.arguslab.native_multiple_interactions.MainActivity: '
                                            'void leakImei(java.lang.String)>',
                                            'staticinvoke <android.util.Log: '
                                            'int '
                                            'i(java.lang.String,java.lang.String)>("multiple_interactions", '
                                            '$r)'),
                                          ( '<org.arguslab.native_multiple_interactions.MainActivity: '
                                            'void '
                                            'onRequestPermissionsResult(int,java.lang.String[],int[])>',
                                            '$r = virtualinvoke '
                                            '$r.<android.telephony.TelephonyManager: '
                                            'java.lang.String '
                                            'getDeviceId()>()'))},
  'native_multiple_libraries.apk': { ( ( '<org.arguslab.native_multiple_libraries.MainActivity: '
                                         'void masterSend(java.lang.String)>',
                                         'staticinvoke <android.util.Log: int '
                                         'i(java.lang.String,java.lang.String)>("master", '
                                         '$r)'),
                                       ( '<org.arguslab.native_multiple_libraries.MainActivity: '
                                         'void leakImei()>',
                                         '$r = virtualinvoke '
                                         '$r.<android.telephony.TelephonyManager: '
                                         'java.lang.String getDeviceId()>()'))},
  'native_noleak.apk': None,
  # false positive: native_noleak_array
#   'native_noleak_array.apk': { ( ( '<org.arguslab.native_noleak_array.MainActivity: '
#                                    'void send(java.lang.String[])>',
#                                    'staticinvoke <android.util.Log: int '
#                                    'i(java.lang.String,java.lang.String)>("noleak", '
#                                    '$r)'),
#                                  ( '<org.arguslab.native_noleak_array.MainActivity: '
#                                    'void leakImei()>',
#                                    '$r = virtualinvoke '
#                                    '$r.<android.telephony.TelephonyManager: '
#                                    'java.lang.String getDeviceId()>()'))},
  'native_nosource.apk': None,
#   'native_pure.apk': None,
#   'native_pure_direct.apk': None,
#   'native_pure_direct_customized.apk': None,

    # two flows are identical.
  'native_set_field_from_arg.apk': { ( ( '<org.arguslab.native_set_field_from_arg.MainActivity: '
                                         'void leakImei()>',
                                         'staticinvoke <android.util.Log: int '
                                         'd(java.lang.String,java.lang.String)>("setField", '
                                         '$r)'),
                                       ( '<org.arguslab.native_set_field_from_arg.MainActivity: '
                                         'void leakImei()>',
                                         '$r = virtualinvoke '
                                         '$r.<android.telephony.TelephonyManager: '
                                         'java.lang.String getDeviceId()>()'))},
  'native_set_field_from_arg_field.apk': { ( ( '<org.arguslab.native_set_field_from_arg_field.MainActivity: '
                                               'void leakImei()>',
                                               'staticinvoke '
                                               '<android.util.Log: int '
                                               'd(java.lang.String,java.lang.String)>("set_field_from_arg_field", '
                                               '$r)'),
                                             ( '<org.arguslab.native_set_field_from_arg_field.MainActivity: '
                                               'void leakImei()>',
                                               '$r = virtualinvoke '
                                               '$r.<android.telephony.TelephonyManager: '
                                               'java.lang.String '
                                               'getDeviceId()>()'))},
  'native_set_field_from_native.apk': { ( ( '<org.arguslab.native_set_field_from_native.MainActivity: '
                                            'void leakImei()>',
                                            'staticinvoke <android.util.Log: '
                                            'int '
                                            'd(java.lang.String,java.lang.String)>("set_field_from_native", '
                                            '$r)'),
                                          ( '<org.arguslab.native_set_field_from_native.MainActivity: '
                                            'org.arguslab.native_set_field_from_native.Foo '
                                            'setField(org.arguslab.native_set_field_from_native.ComplexData)>',
                                            '$r = virtualinvoke '
                                            '$r.<android.telephony.TelephonyManager: '
                                            'java.lang.String '
                                            'getDeviceId()>()'))},
  'native_source.apk': { ( ( '<org.arguslab.native_source.MainActivity: void '
                             'leakImei()>',
                             'staticinvoke <android.util.Log: int '
                             'i(java.lang.String,java.lang.String)>("imei", '
                             '$r)'),
                           ( '<org.arguslab.native_source.MainActivity: '
                             'java.lang.String '
                             'getImei(android.content.Context)>',
                             '$r = virtualinvoke '
                             '$r.<android.telephony.TelephonyManager: '
                             'java.lang.String getDeviceId()>()'))},
  # wrong: native_source_clean
#   'native_source_clean.apk': { ( ( '<org.arguslab.native_source_clean.MainActivity: '
#                                    'void leakImei()>',
#                                    'staticinvoke <android.util.Log: int '
#                                    'd(java.lang.String,java.lang.String)>("source_clean", '
#                                    '$r3)'),
#                                  ( '<org.arguslab.native_source_clean.MainActivity: '
#                                    'void leakImei()>',
#                                    '$r3 = virtualinvoke '
#                                    '$r2.<android.telephony.TelephonyManager: '
#                                    'java.lang.String getDeviceId()>()'))}
}

NativeFlowBenchExtendedAnswer = {
    # 'native_array_elements-release-unsigned.apk': { ( ( '<org.example.nativearrayelements.MainActivity: '
    #                                                   'void doLeak(byte[])>',
    #                                                   'staticinvoke '
    #                                                   '<android.util.Log: int '
    #                                                   'i(java.lang.String,java.lang.String)>("array_elements", '
    #                                                   '$r)'),
    #                                                 ( '<org.example.nativearrayelements.MainActivity: '
    #                                                   'void doLeak(byte[])>',
    #                                                   '$r = virtualinvoke '
    #                                                   '$r.<java.lang.Object: '
    #                                                   'java.lang.String '
    #                                                   'toString()>()')),
    #                                               ( ( '<org.example.nativearrayelements.MainActivity: '
    #                                                   'void doLeak(byte[])>',
    #                                                   'staticinvoke '
    #                                                   '<org.example.NativeSummaryFuncs: '
    #                                                   'int '
    #                                                   'GetArrayLength(java.lang.Object,byte[])>(null, '
    #                                                   '$r)'),
    #                                                 ( '<org.example.nativearrayelements.MainActivity: '
    #                                                   'void '
    #                                                   'onCreate(android.os.Bundle)>',
    #                                                   '$r = virtualinvoke '
    #                                                   '$r.<java.lang.String: '
    #                                                   'byte[] getBytes()>()'))},
#   'native_array_region-release-unsigned.apk': { ( ( '<org.example.nativearrayregion.MainActivity: '
#                                                     'void doLeak(byte[])>',
#                                                     '$i0 = staticinvoke '
#                                                     '<org.example.NativeSummaryFuncs: '
#                                                     'int '
#                                                     'GetArrayLength(java.lang.Object,byte[])>(null, '
#                                                     '$r)'),
#                                                   ( '<org.example.nativearrayregion.MainActivity: '
#                                                     'void '
#                                                     'onCreate(android.os.Bundle)>',
#                                                     '$r = virtualinvoke '
#                                                     '$r.<java.lang.String: '
#                                                     'byte[] getBytes()>()')),
#                                                 ( ( '<org.example.nativearrayregion.MainActivity: '
#                                                     'void doLeak(byte[])>',
#                                                     'staticinvoke '
#                                                     '<org.example.NativeSummaryFuncs: '
#                                                     'int '
#                                                     'GetByteArrayRegion(java.lang.Object,byte[],java.lang.Object,int,java.lang.Object)>(null, '
#                                                     '$r, null, $i0, null)'),
#                                                   ( '<org.example.nativearrayregion.MainActivity: '
#                                                     'void '
#                                                     'onCreate(android.os.Bundle)>',
#                                                     '$r = virtualinvoke '
#                                                     '$r.<java.lang.String: '
#                                                     'byte[] getBytes()>()'))},
  'native_copy-release-unsigned.apk': { ( ( '<org.example.nativecopy.MainActivity: '
                                            'void doleak(java.lang.String)>',
                                            'staticinvoke <android.util.Log: '
                                            'int '
                                            'i(java.lang.String,java.lang.String)>("copy", '
                                            '$r)'),
                                          ( '<org.example.nativecopy.MainActivity: '
                                            'java.lang.String '
                                            'getImei(android.content.Context)>',
                                            '$r = virtualinvoke '
                                            '$r.<android.telephony.TelephonyManager: '
                                            'java.lang.String '
                                            'getDeviceId()>()')),
                                        ( ( '<org.example.nativecopy.MainActivity: '
                                            'void doleak(java.lang.String)>',
                                            'staticinvoke <android.util.Log: '
                                            'int '
                                            'i(java.lang.String,java.lang.String)>("copy", '
                                            '$r)'),
                                          ( '<org.example.nativecopy.MainActivity: '
                                            'java.lang.String '
                                            'getImei(android.content.Context)>',
                                            '$r = virtualinvoke '
                                            '$r.<android.telephony.TelephonyManager: '
                                            'java.lang.String getImei()>()'))},
#   'native_copy_strdup-release-unsigned.apk': { ( ( '<org.example.nativecopystrdup.MainActivity: '
#                                                    'void '
#                                                    'doleak(java.lang.String)>',
#                                                    '$r = staticinvoke '
#                                                    '<org.example.NativeSummaryFuncs: '
#                                                    'java.lang.String '
#                                                    'strdup(java.lang.String)>($r)'),
#                                                  ( '<org.example.nativecopystrdup.MainActivity: '
#                                                    'java.lang.String '
#                                                    'getImei(android.content.Context)>',
#                                                    '$r = virtualinvoke '
#                                                    '$r.<android.telephony.TelephonyManager: '
#                                                    'java.lang.String '
#                                                    'getDeviceId()>()'))},
  'native_direct_buffer-release-unsigned.apk': { ( ( '<org.example.nativedirectbuffer.MainActivity: '
                                                     'void '
                                                     'doLeak(java.nio.ByteBuffer)>',
                                                     'staticinvoke '
                                                     '<android.util.Log: int '
                                                     'i(java.lang.String,java.lang.String)>("direct_buffer", '
                                                     '$r)'),
                                                   ( '<org.example.nativedirectbuffer.MainActivity: '
                                                     'java.lang.String '
                                                     'getImei(android.content.Context)>',
                                                     '$r = virtualinvoke '
                                                     '$r.<android.telephony.TelephonyManager: '
                                                     'java.lang.String '
                                                     'getDeviceId()>()')),
                                                 ( ( '<org.example.nativedirectbuffer.MainActivity: '
                                                     'void '
                                                     'doLeak(java.nio.ByteBuffer)>',
                                                     'staticinvoke '
                                                     '<android.util.Log: int '
                                                     'i(java.lang.String,java.lang.String)>("direct_buffer", '
                                                     '$r)'),
                                                   ( '<org.example.nativedirectbuffer.MainActivity: '
                                                     'java.lang.String '
                                                     'getImei(android.content.Context)>',
                                                     '$r = virtualinvoke '
                                                     '$r.<android.telephony.TelephonyManager: '
                                                     'java.lang.String '
                                                     'getImei()>()'))},
#   'native_encode-release-unsigned.apk': None,
  'native_file_leak-release-unsigned.apk': { ( ( '<org.example.nativefileleak.MainActivity: '
                                                 'void '
                                                 'doleak(java.lang.String)>',
                                                 'staticinvoke '
                                                 '<org.example.NativeSummaryFuncs: '
                                                 'int '
                                                 'write(int,java.lang.String,int)>($i0, '
                                                 '$r, 30)'),
                                               ( '<org.example.nativefileleak.MainActivity: '
                                                 'java.lang.String '
                                                 'getImei(android.content.Context)>',
                                                 '$r = virtualinvoke '
                                                 '$r.<android.telephony.TelephonyManager: '
                                                 'java.lang.String '
                                                 'getDeviceId()>()')),
                                             ( ( '<org.example.nativefileleak.MainActivity: '
                                                 'void '
                                                 'doleak(java.lang.String)>',
                                                 'staticinvoke '
                                                 '<org.example.NativeSummaryFuncs: '
                                                 'int '
                                                 'write(int,java.lang.String,int)>($i0, '
                                                 '$r, 30)'),
                                               ( '<org.example.nativefileleak.MainActivity: '
                                                 'java.lang.String '
                                                 'getImei(android.content.Context)>',
                                                 '$r = virtualinvoke '
                                                 '$r.<android.telephony.TelephonyManager: '
                                                 'java.lang.String '
                                                 'getImei()>()'))},
  'native_global_id-release-unsigned.apk': { ( ( '<org.example.nativeglobalid.MainActivity: '
                                                 'void leakimei()>',
                                                 'staticinvoke '
                                                 '<android.util.Log: int '
                                                 'i(java.lang.String,java.lang.String)>("imei", '
                                                 '$r)'),
                                               ( '<org.example.nativeglobalid.MainActivity: '
                                                 'java.lang.String '
                                                 'getImei(android.content.Context)>',
                                                 '$r = virtualinvoke '
                                                 '$r.<android.telephony.TelephonyManager: '
                                                 'java.lang.String '
                                                 'getDeviceId()>()'))},
#   'native_handle-release-unsigned.apk': None,
  'native_socket_leak-release-unsigned.apk': { ( ( '<org.example.nativesocketleak.MainActivity: '
                                                   'void '
                                                   'doleak(java.lang.String)>',
                                                   'staticinvoke '
                                                   '<org.example.NativeSummaryFuncs: '
                                                   'int '
                                                   'write(int,java.lang.String,int)>($i0, '
                                                   '$r, 16)'),
                                                 ( '<org.example.nativesocketleak.MainActivity: '
                                                   'java.lang.String '
                                                   'getImei(android.content.Context)>',
                                                   '$r = virtualinvoke '
                                                   '$r.<android.telephony.TelephonyManager: '
                                                   'java.lang.String '
                                                   'getDeviceId()>()')),
                                               ( ( '<org.example.nativesocketleak.MainActivity: '
                                                   'void '
                                                   'doleak(java.lang.String)>',
                                                   'staticinvoke '
                                                   '<org.example.NativeSummaryFuncs: '
                                                   'int '
                                                   'write(int,java.lang.String,int)>($i0, '
                                                   '$r, 16)'),
                                                 ( '<org.example.nativesocketleak.MainActivity: '
                                                   'java.lang.String '
                                                   'getImei(android.content.Context)>',
                                                   '$r = virtualinvoke '
                                                   '$r.<android.telephony.TelephonyManager: '
                                                   'java.lang.String '
                                                   'getImei()>()'))}
    }

JucifyBenchAnswer = { 'delegation_imei.apk': { ( ( '<lu.uni.trux.delegation_imei.MainActivity: '
                               'void nativeDelegation()>',
                               'staticinvoke <android.util.Log: int '
                               'd(java.lang.String,java.lang.String)>("Test", '
                               '$r)'),
                             ( '<lu.uni.trux.delegation_imei.MainActivity: '
                               'void nativeDelegation()>',
                               '$r = virtualinvoke '
                               '$r.<android.telephony.TelephonyManager: '
                               'java.lang.String getDeviceId()>()'))},
  'delegation_proxy.apk': { ( ( '<lu.uni.trux.delegation_proxy.MainActivity: '
                                'void nativeDelegation()>',
                                'staticinvoke <android.util.Log: int '
                                'd(java.lang.String,java.lang.String)>("Test", '
                                '$r)'),
                              ( '<lu.uni.trux.delegation_proxy.MainActivity: '
                                'void nativeDelegation()>',
                                '$r = virtualinvoke '
                                '$r.<android.telephony.TelephonyManager: '
                                'java.lang.String getDeviceId()>()'))},
  'getter_imei.apk': { ( ( '<lu.uni.trux.getter_imei.MainActivity: void '
                           'onCreate(android.os.Bundle)>',
                           'staticinvoke <android.util.Log: int '
                           'd(java.lang.String,java.lang.String)>("IMEI", $r)'),
                         ( '<lu.uni.trux.getter_imei.MainActivity: '
                           'java.lang.String '
                           'nativeGetImei(android.telephony.TelephonyManager)>',
                           '$r = virtualinvoke '
                           '$r.<android.telephony.TelephonyManager: '
                           'java.lang.String getDeviceId()>()'))},
  'getter_imei_deep.apk': { ( ( '<lu.uni.trux.getter_imei_deep.MainActivity: '
                                'void onCreate(android.os.Bundle)>',
                                'staticinvoke <android.util.Log: int '
                                'd(java.lang.String,java.lang.String)>("IMEI", '
                                '$r)'),
                              ( '<lu.uni.trux.getter_imei_deep.MainActivity: '
                                'java.lang.String '
                                'nativeGetImei(android.telephony.TelephonyManager)>',
                                '$r = virtualinvoke '
                                '$r.<android.telephony.TelephonyManager: '
                                'java.lang.String getDeviceId()>()'))},
  'getter_leaker.apk': { ( ( '<lu.uni.trux.getter_leaker.MainActivity: void '
                             'nativeLeaker(java.lang.String)>',
                             'staticinvoke <android.util.Log: int '
                             'd(java.lang.String,java.lang.String)>("Test", '
                             '$r)'),
                           ( '<lu.uni.trux.getter_leaker.MainActivity: '
                             'java.lang.String '
                             'nativeGetImei(android.telephony.TelephonyManager)>',
                             '$r = virtualinvoke '
                             '$r.<android.telephony.TelephonyManager: '
                             'java.lang.String getDeviceId()>()'))},
  'getter_proxy_leaker.apk': { ( ( '<lu.uni.trux.getter_proxy_leaker.MainActivity: '
                                   'void nativeLeaker(java.lang.String)>',
                                   'staticinvoke <android.util.Log: int '
                                   'd(java.lang.String,java.lang.String)>("Test", '
                                   '$r)'),
                                 ( '<lu.uni.trux.getter_proxy_leaker.MainActivity: '
                                   'java.lang.String '
                                   'nativeGetImei(android.telephony.TelephonyManager)>',
                                   '$r = virtualinvoke '
                                   '$r.<android.telephony.TelephonyManager: '
                                   'java.lang.String getDeviceId()>()'))},
  'getter_string.apk': None,
  'leaker_imei.apk': { ( ( '<lu.uni.trux.leaker_imei.MainActivity: void '
                           'nativeLeaker(java.lang.String)>',
                           'staticinvoke <android.util.Log: int '
                           'd(java.lang.String,java.lang.String)>("Test", $r)'),
                         ( '<lu.uni.trux.leaker_imei.MainActivity: void '
                           'onCreate(android.os.Bundle)>',
                           '$r = virtualinvoke '
                           '$r.<android.telephony.TelephonyManager: '
                           'java.lang.String getDeviceId()>()'))},
  'leaker_string.apk': None,
  'proxy.apk': { ( ( '<lu.uni.trux.proxy_imei.MainActivity: void '
                     'onCreate(android.os.Bundle)>',
                     'staticinvoke <android.util.Log: int '
                     'd(java.lang.String,java.lang.String)>("Test", $r)'),
                   ( '<lu.uni.trux.proxy_imei.MainActivity: void '
                     'onCreate(android.os.Bundle)>',
                     '$r = virtualinvoke '
                     '$r.<android.telephony.TelephonyManager: java.lang.String '
                     'getDeviceId()>()'))},
  'proxy_double.apk': { ( ( '<lu.uni.trux.proxy_double.MainActivity: void '
                            'onCreate(android.os.Bundle)>',
                            'staticinvoke <android.util.Log: int '
                            'd(java.lang.String,java.lang.String)>("Test", '
                            '$r)'),
                          ( '<lu.uni.trux.proxy_double.MainActivity: void '
                            'onCreate(android.os.Bundle)>',
                            '$r = virtualinvoke '
                            '$r.<android.telephony.TelephonyManager: '
                            'java.lang.String getDeviceId()>()'))}}

class TestNativeFlowBench(unittest.TestCase):

    def test_nfb(self):
        DATASET_PATH = NFB_DATASET_PATH
        if not os.path.isdir(DATASET_PATH):
            self.fail(f"Cannot find dataset, please download dataset to {DATASET_PATH}.")
        temp_dir = tempfile.TemporaryDirectory()
        tdir = temp_dir.name
        for apk, ans in NativeFlowBenchAnswer.items():
            apk_path = os.path.join(DATASET_PATH, apk)
            out_path = os.path.join(tdir, apk)
            docker_run(apk_path, out_path, MIN_SS_FILE)
            result = get_ss_list(os.path.join(out_path, "repacked_apks", 'fd.xml'))
            if result is None:
                self.assertEqual(result, ans)
                continue
            result_count = len(result)
            result = set(result)
            self.assertEqual(result, ans, f"{apk} result mismatch, check: {out_path}")
            if apk.startswith('native_set'):
                self.assertEqual(result_count, 2, f"{apk} count mismatch, check: {out_path}")
            else:
                self.assertEqual(result_count, len(ans), f"{apk} count mismatch, check: {out_path}")

        temp_dir.cleanup()
    
    def test_nfbe(self):
        DATASET_PATH = NFBE_DATASET_PATH
        if not os.path.isdir(DATASET_PATH):
            self.fail(f"Cannot find dataset, please download dataset to {DATASET_PATH}.")
        temp_dir = tempfile.TemporaryDirectory()
        tdir = temp_dir.name
        for apk, ans in NativeFlowBenchExtendedAnswer.items():
            apk_path = os.path.join(DATASET_PATH, apk)
            out_path = os.path.join(tdir, apk)
            docker_run(apk_path, out_path, MIN_SS_FILE)
            result = get_ss_list(os.path.join(out_path, "repacked_apks", 'fd.xml'))
            if result is None:
                self.assertEqual(result, ans)
                continue
            result_count = len(result)
            result = set(result)
            self.assertEqual(result, ans, f"{apk} result mismatch, check: {out_path}")
            self.assertEqual(result_count, len(ans), f"{apk} count mismatch, check: {out_path}")

        temp_dir.cleanup()

    def test_jucifybench(self):
        DATASET_PATH = JUB_DATASET_PATH
        if not os.path.isdir(DATASET_PATH):
            self.fail(f"Cannot find dataset, please download dataset to {DATASET_PATH}.")
        temp_dir = tempfile.TemporaryDirectory()
        tdir = temp_dir.name
        for apk, ans in JucifyBenchAnswer.items():
            apk_path = os.path.join(DATASET_PATH, apk)
            out_path = os.path.join(tdir, apk)
            docker_run(apk_path, out_path, MIN_SS_FILE)
            result = get_ss_list(os.path.join(out_path, "repacked_apks", 'fd.xml'))
            if result is None:
                self.assertEqual(result, ans)
                continue
            result_count = len(result)
            result = set(result)
            self.assertEqual(result, ans, f"{apk} result mismatch, check: {out_path}")
            self.assertEqual(result_count, len(ans), f"{apk} count mismatch, check: {out_path}")

        temp_dir.cleanup()

def generate_answer_audit(temp_dir, dataset_path):
    # temp_dir = '/tmp/test_nfb'
    # dataset_path = NFB_DATASET_PATH
    # temp_dir = '/tmp/test_nfbe'
    # dataset_path = NFBE_DATASET_PATH
    # temp_dir = '/tmp/test_jub'
    # dataset_path = JUB_DATASET_PATH
    tdir = temp_dir
    Answer = {}
    
    for apk in os.listdir(dataset_path):
        if not apk.endswith('.apk'):
            continue
        apk_path = os.path.join(dataset_path, apk)
        out_path = os.path.join(tdir, apk)
        docker_run(apk_path, out_path, MIN_SS_FILE)
        result = get_ss_list(os.path.join(out_path, "repacked_apks", 'fd.xml'))
        if result is not None:
            result = set(result)
        Answer[apk] = result
    import pprint
    pprint.pprint(Answer, indent=2)


if __name__ == '__main__':
    # unittest.main()
    # generate_answer_audit('/tmp/test_nfb', NFB_DATASET_PATH)
    # generate_answer_audit('/tmp/test_nfbe', NFBE_DATASET_PATH)
    # generate_answer_audit('/tmp/test_jub', JUB_DATASET_PATH)
