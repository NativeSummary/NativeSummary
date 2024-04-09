
from .utils import load_json, read_file, match_in_str
from .ns_stats import contains_native_method
from html.parser import HTMLParser

# [{
#     "details": {
#         "Sink": [
#             "<agersant.polaris.features.settings.SettingsFragment: void updatePreferenceSummary(android.preference.Preference,java.lang.String)>->$r2_5"
#         ],
#         "position": "<agersant.polaris.features.settings.SettingsFragment: void updatePreferenceSummary(android.preference.Preference,java.lang.String)>",
#         "Manifest": {
#             "exported": false,
#             "trace": [
#                 "<agersant.polaris.features.settings.SettingsActivity: void onCreate(android.os.Bundle)>",
#                 "<agersant.polaris.features.settings.SettingsFragment: void onSharedPreferenceChanged(android.content.SharedPreferences,java.lang.String)>",
#                 "<agersant.polaris.features.settings.SettingsFragment: void updatePreferenceSummary(android.preference.Preference,java.lang.String)>"
#             ],
#             "<activity name=agersant.polaris.features.settings.SettingsActivity>": [
#             ]
#         },
#         "entryMethod": "<agersant.polaris.features.settings.SettingsFragment: void updatePreferenceSummary(android.preference.Preference,java.lang.String)>",
#         "Source": [
#             "<agersant.polaris.features.settings.SettingsFragment: void updatePreferenceSummary(android.preference.Preference,java.lang.String)>->$r6"
#         ],
#         "url": "/home/user/ns/tmp/results/appshark/fdroid/agersant.polaris_48.apk/vulnerability/32-InfoFlow.html",
#         "target": [
#             "<agersant.polaris.features.settings.SettingsFragment: void updatePreferenceSummary(android.preference.Preference,java.lang.String)>->$r6",
#             "<agersant.polaris.features.settings.SettingsFragment: void updatePreferenceSummary(android.preference.Preference,java.lang.String)>->$r2",
#             "<agersant.polaris.features.settings.SettingsFragment: void updatePreferenceSummary(android.preference.Preference,java.lang.String)>->$r2_5"
#         ]
#     },
#     "hash": "be122066b35a6fc28fa75be7324eb7510785d6b0",
#     "possibility": "4"
# },]

# the total number of flows are counted by loading the result.json file
def appshark_results(json_path):
    obj = load_json(json_path)
    if "SecurityInfo" not in obj: return []
    return obj["SecurityInfo"]["Common"]["InfoFlow"]["vulners"]

# find native related flows in appshark results
# map: flow set -> [(native flow xml, native part)]
def get_native_flow_appshark(elems, apkname, native_methods):
    natives = {}
    for elem in elems:
        elem = elem['details']
        html_path = elem["url"]
        flow_lines, native_parts = get_native_flow_one(html_path, apkname, native_methods)
        if len(native_parts) > 0:
            natives[(flow_lines[0], flow_lines[-1])] = (flow_lines, native_parts)
    return natives

# parse html, return (flow_lines, native_parts)
def get_native_flow_one(html_path, apkname, native_methods):

    html_data = read_file(html_path)

    # match for code detail part
    import re
    code_details = re.findall(r'code detail: </div>(.+)</div></body></html>', html_data, re.DOTALL)[0]
    # print(code_details)
    
    datas = []
    class MyHTMLParser(HTMLParser):
        def handle_data(self, data):
            datas.append(data)

    MyHTMLParser().feed(code_details)
    flat = '\n'.join(datas)
    flat_lines = flat.split('\n')
    flow_lines = []
    for line in flat_lines:
        line = line.strip()
        matched = re.match(r'^[0-9]+:->\[.+\] (.+)$', line)
        if matched is not None:
            flow_lines.append(matched[1])
    # print('\n'.join(flow_lines))
    # flow_lines:
    # first line: source
    # middle lines: path
    # last line: sink
    
    native_parts = []
    nms = native_methods[apkname]
    for line in flow_lines:
        if contains_native_method(nms, line):
            native_parts.append(line)
    return (flow_lines, native_parts)

