import os,subprocess,re
import xml.etree.ElementTree as ET

IMAGE_NAME='ns'

def docker_run(fpath, result_dir, sources_sinks_file):
    # how to 
    os.makedirs(result_dir, exist_ok=True)
    apk_name = os.path.basename(fpath)
    run_cmd = f"docker run -i --name ns-{apk_name} --rm  -e NS_TIMEOUT=10m -v {sources_sinks_file}:/root/ss.txt -v {fpath}:/apk -v {result_dir}:/out {IMAGE_NAME} --taint"
    subprocess.run(run_cmd, check=True, shell=True)

def source_sink_normalize(elem):
    strs = [re.sub(r'r[0-9]+', 'r', i) for i in elem]
    return (strs[0], strs[1])

def convert_source_or_sink(elem):
    return source_sink_normalize((elem.attrib['Method'], elem.attrib['Statement']))

def get_ss_list(xml_path):
    if not os.path.exists(xml_path):
        return None
    root = ET.parse(xml_path).getroot()
    ret = []
    for result in root.findall('./Results/Result'):
        assert result[0].tag == 'Sink'
        assert result[1].tag == 'Sources'
        sink = convert_source_or_sink(result[0])
        # sources = []
        for sour in result[1]:
            assert sour.tag == 'Source'
            # sources.append(convert_source_or_sink(sour))
            ret.append((sink, convert_source_or_sink(sour)))
    return ret
