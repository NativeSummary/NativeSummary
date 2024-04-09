
import os

limit_cmd_template = 'systemd-run --scope --same-dir --collect {} bash -c "{}"' #  --wait
time_cmd_template = '/usr/bin/time -v {} {} 1> {} 2> {}'
tool_cmd_template = '/usr/lib/jvm/java-{}-openjdk-amd64/bin/java -jar /home/user/ns/tools/flowdroid-2.10/soot-infoflow-cmd-jar-with-dependencies.jar {}'

def run_flowdroid(fpath, out_path, ss_file, platform_dir='/home/user/ns/tools/platforms',
                  max_memory=None, max_cpu=None, timeout=None, timeout_kill_after='60s', java_version='17',
                  max_thread_number=None, path_reconstruction_mode=None, format=True,
                  print_for_xargs=True):
    '''
    max_memory: example: 6G
    max_cpu: in percentage, for example: 100%
    '''
    stdout_path = os.path.join(out_path, 'stdout.txt')
    stderr_path = os.path.join(out_path, 'stderr.txt')

    # ubuntu java install path
    assert os.path.exists(f'/usr/lib/jvm/java-{java_version}-openjdk-amd64/bin/java')
    flowdroid_args = f' --mergedexfiles -p {platform_dir} -s {ss_file} -a {fpath} -o {out_path} '
    if max_thread_number is not None:
        flowdroid_args = f" --maxthreadnum {max_thread_number} " + flowdroid_args
    if path_reconstruction_mode is not None:
        flowdroid_args = f" --pathreconstructionmode {path_reconstruction_mode} "  + flowdroid_args
    tool_cmd = tool_cmd_template.format(java_version, flowdroid_args)

    timeout_args = ''
    if timeout is not None:
        timeout_args += ' /usr/bin/timeout '
        if timeout_kill_after is not None:
            timeout_args += f' --kill-after={timeout_kill_after} '
        timeout_args += f' {timeout} '
    time_cmd = time_cmd_template.format(timeout_args, tool_cmd, stdout_path, stderr_path)

    # limit memory and cpu
    limit_cmd_args = ''
    if max_memory is not None:
        limit_cmd_args += f' -p MemoryMax={max_memory} '
    if max_cpu is not None:
        limit_cmd_args += f' -p CPUQuota={max_cpu} '
    if len(limit_cmd_args) > 0:
        time_cmd = limit_cmd_template.format(limit_cmd_args, time_cmd)
    if format:
        xml_out = out_path
        if os.path.isdir(out_path):
            xml_out = f'{out_path}/{os.path.basename(fpath).removesuffix(".apk")}.xml'
        time_cmd += f'; xmllint --format {xml_out} -o {xml_out}'
    if print_for_xargs:
        print(time_cmd, end='\x00')
    return time_cmd

