import json

import androguard

from native_summary.common import HeapObject


def init_sematic_summary(apk_name, globals=[]):
    sematic_summary = dict()
    sematic_summary['apk_name'] = apk_name
    sematic_summary['globals'] = globals
    sematic_summary['mth_logs'] = dict()
    return sematic_summary

def encode_method(mth):
    # androguard.core.analysis.analysis.MethodClassAnalysis
    cls_name = mth.get_method().get_class_name()
    mth_name = mth.name
    sig = mth.descriptor
    return f'{cls_name}\t{mth_name}\t{sig}'

def transform_key(k):
    if isinstance(k, androguard.core.analysis.analysis.MethodClassAnalysis):
        return encode_method(k)
    elif isinstance(k, tuple):
        return '\t'.join([str(i) for i in k])
    else:
        return k

def recursive_transform_key(obj):
    if isinstance(obj, dict):
        return {transform_key(k): recursive_transform_key(v) for k, v in obj.items()}
    elif isinstance(obj, list) or isinstance(obj, set):
        return [recursive_transform_key(l) for l in obj]
    else:
        return obj

class SummaryEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, HeapObject):
            return obj.to_json()
        return json.JSONEncoder.default(self, obj)
    
    def encode(self, obj):
        return super(SummaryEncoder, self).encode(obj)


def dump_sematic_summary(sematic_summary, fname):
    # sematic_summary['mth_logs'] = {encode_method(k): v for k, v in sematic_summary['mth_logs'].items()}
    sematic_summary = recursive_transform_key(sematic_summary)
    with open(fname, 'w') as f:
        json.dump(sematic_summary, f, cls=SummaryEncoder)
        # f.write(json.dumps(sematic_summary, cls=SummaryEncoder))
