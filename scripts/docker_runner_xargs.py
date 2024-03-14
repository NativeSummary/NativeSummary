#!/usr/bin/python3
import os
import sys

IMAGE_NAME = 'ns'

def get_ns_docker_command(apk_path: str, result_dir: str, apk_name=None, timeout=None,
                          binary_timeout=None, ss_file=None, max_cpu=None, max_mem=None,
                          container_name_template="ns-{}", run_flowdroid=False,
                          change_uid=True, selected_arch=None, perfer_32=False, no_opt=False,
                          no_model=False, call_string_k=None, k_set_k=None, binary_jni_timeout=None,
                          flowdroid_timeout=None, flowdroid_callback_timeout=None, flowdroid_result_timeout=None) -> str:
    '''Returns the docker command to analyze an apk.

    Keyword arguments:
    max_cpu: maximum CPU core count for this run. (see docker's "--cpus" flag)
    max_mem: maximum memory usage for this run. (see docker's "--memory" flag)
    timeout: total timeout for the docker. (/usr/bin/timeout format: a number with optional suffix: 's' for seconds (the default), 'm' for minutes, 'h' for hours or 'd' for days.)
    binary_timeout: timeout for binary analysis (/usr/bin/timeout format)
        it is recommended that setting binary_timeout to total timeout minus (about) 20 minutes, so that existing results is correctly shown.
    ss_file: source sink file
    binary_jni_timeout: limit the analysis time for each jni method. (pure number in seconds)
    '''
    # configure the run using docker_args and image_args
    docker_args = ''
    image_args = ''
    if max_cpu is not None:
        docker_args += f' --cpus {max_cpu}'
    if max_mem is not None:
        docker_args += f' --memory {max_mem}'
    if binary_timeout is not None:
        docker_args += f' -e BINARY_TIMEOUT={binary_timeout}'
    if timeout is not None:
        docker_args += f' -e NS_TIMEOUT={timeout}'
    if ss_file is not None:
        docker_args += f' -v {ss_file}:/root/ss.txt'
    # run taint analysis
    if run_flowdroid:
        image_args += ' --taint'
        if flowdroid_timeout is not None:
            docker_args += f' -e FLOWDROID_TIMEOUT={flowdroid_timeout}'
        if flowdroid_callback_timeout is not None:
            docker_args += f' -e FLOWDROID_CALLBACK_TIMEOUT={flowdroid_callback_timeout}'
        if flowdroid_result_timeout is not None:
            docker_args += f' -e FLOWDROID_RESULT_TIMEOUT={flowdroid_result_timeout}'
    else:
        assert flowdroid_timeout is None and flowdroid_callback_timeout is None and flowdroid_result_timeout is None, "FlowDroid timeout set but taint analysis not enabled!!"
    # Changing the file owner to this uid, or else it will be owned by root
    if type(change_uid) is int:
        docker_args += f' -e CHANGE_UID={change_uid}'
    elif change_uid is True:
        docker_args += f' -e CHANGE_UID={os.getuid()}'
    else:
        assert change_uid is False, "unknown type for change_uid"

    if selected_arch is not None:
        docker_args += f' -e NS_SELECT_ARCH={os.getuid()}'
    if perfer_32:
        docker_args += ' -e NS_PREFER_32=True'

    GHIDRA_NS_ARGS = ''
    if no_opt:
        GHIDRA_NS_ARGS += f' -noOpt'
    if no_model:
        GHIDRA_NS_ARGS += f' -noModel'
    if call_string_k is not None:
        GHIDRA_NS_ARGS += f' -callStringK {call_string_k}'
    if k_set_k is not None:
        GHIDRA_NS_ARGS += f' -K {k_set_k}'
    if binary_jni_timeout is not None:
        GHIDRA_NS_ARGS += f' -timeout {binary_jni_timeout}'
    if len(GHIDRA_NS_ARGS) > 0:
        GHIDRA_NS_ARGS = GHIDRA_NS_ARGS.strip()
        docker_args += f' -e GHIDRA_NS_ARGS="@@{GHIDRA_NS_ARGS}"'

    # handle output input paths
    if apk_name is None:
        apk_name = os.path.basename(apk_path)
    container_name = container_name_template.format(apk_name)
    if not os.path.exists(result_dir):
        os.makedirs(result_dir)
    run_cmd_suffix = f' {docker_args} -v {apk_path}:/apk -v {result_dir}:/out'
    run_cmd = f"docker run -i --name {container_name} --rm {run_cmd_suffix} {IMAGE_NAME} {image_args}"
    return run_cmd


def ns_analyze_dataset_xargs(dataset_path, out_dataset_path, print_for_xargs=True,
                             timeout=None, binary_timeout=None, ss_file=None,
                             max_cpu=None, max_mem=None,
                             container_name_template="ns-{}",
                             run_flowdroid=False, change_uid=True, selected_arch=None,
                             perfer_32=False, no_opt=False, no_model=False,
                             call_string_k=None, k_set_k=None, binary_jni_timeout=None,
                             flowdroid_timeout=None, flowdroid_callback_timeout=None, flowdroid_result_timeout=None):
    '''
    print_for_xargs: if true, print the commands with separator '\x00'
    '''
    cmds = []
    # allow dataset_path to be single file.
    if not os.path.isfile(dataset_path):
        dirs = sorted(os.listdir(dataset_path))
    else:
        dirs = [os.path.basename(dataset_path)]
        dataset_path = os.path.dirname(dataset_path)
    for file in dirs:
        if not file.endswith('.apk'):
            continue
        fpath = os.path.join(dataset_path, file)
        result_dir = os.path.join(out_dataset_path, file)
        # check run finished
        if os.path.exists(os.path.join(result_dir, "NS_FINISHED")):
            print(f"{file} finished.", file=sys.stderr)
        else:
            if not os.path.exists(result_dir):
                os.makedirs(result_dir)
            run_cmd = get_ns_docker_command(fpath, result_dir, ss_file=ss_file, container_name_template=container_name_template, run_flowdroid=run_flowdroid, change_uid=change_uid, timeout=timeout, max_cpu=max_cpu, max_mem=max_mem,
                                            binary_timeout=binary_timeout, selected_arch=selected_arch, perfer_32=perfer_32, no_opt=no_opt, no_model=no_model, call_string_k=call_string_k, k_set_k=k_set_k, binary_jni_timeout=binary_jni_timeout,
                                            flowdroid_timeout=flowdroid_timeout, flowdroid_callback_timeout=flowdroid_callback_timeout, flowdroid_result_timeout=flowdroid_result_timeout)
            cmds.append(run_cmd+';')
            if print_for_xargs:
                print(run_cmd, end=';')
                # print(f"mv {result_dir}/repacked_apks/apk {fpath}.repacked.apk", end=';')
                print("\x00", end="")
    return cmds

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description=f'NativeSummary docker run command generator. Pipe output to xargs to execute commands. Usage: {sys.argv[0]} | xargs -0 -I CMD --max-procs=1 bash -c CMD')
    parser.add_argument('--apk', type=str, required=True,
                        help='apk or apk folder path')
    parser.add_argument('--out', type=str, required=True,
                        help='output folder path')
    parser.add_argument('--timeout', type=str,
                        default='50m', help='Timeout value')
    parser.add_argument('--binary_timeout', type=str,
                        default='25m', help='Binary timeout value')
    parser.add_argument('--ss_file', default=None, help='SS file')
    parser.add_argument('--run_flowdroid', action='store_true',
                        default=False, help='Run FlowDroid')
    parser.add_argument('--selected_arch', default=None,
                        help='Selected architecture')
    parser.add_argument('--perfer_32', action='store_true',
                        default=False, help='Prefer 32-bit')
    parser.add_argument('--no_opt', action='store_true',
                        default=False, help='Disable optimization')
    parser.add_argument('--no_model', action='store_true',
                        default=False, help='Disable model')
    parser.add_argument('--call_string_k', default=None, help='Call string K')
    parser.add_argument('--k_set_k', default=None, help='K set K')
    parser.add_argument('--binary_jni_timeout',
                        default=None, help='Binary JNI timeout')
    parser.add_argument('--flowdroid_timeout', default=None, help='flowdroid dataflow analysis timeout')
    parser.add_argument('--flowdroid_callback_timeout', default=None, help='flowdroid callback callgraph analysis timeout')
    parser.add_argument('--flowdroid_result_timeout',
                        default=None, help='flowdroid result collection timeout')
    args = parser.parse_args(sys.argv[1:])
    kwargs = vars(args)
    dataset_path = kwargs.pop("apk")
    out_dataset_path = kwargs.pop("out")
    ns_analyze_dataset_xargs(dataset_path, out_dataset_path, **kwargs)
