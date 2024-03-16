


def get_jnsaf_native_flow(flow, apkname, native_methods, filter_set=None):
    ret = collections.defaultdict(lambda:[])
    # print(path)
    nms = native_methods[apkname]
    m = get_set_jnsaf(flow)
    for f, steps in m.items():
        native_parts = []
        for step in steps:
            if contains_native_method_jnsaf(nms, step):
                native_parts.append(step)
        if len(native_parts) != 0:
            ret[f].append(native_parts) 
    return dict(ret)
