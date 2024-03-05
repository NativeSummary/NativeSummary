#!/usr/bin/python3
import json
import os,sys
import shutil
import time
from multiprocessing import Process, Queue
import subprocess

IMAGE_NAME = 'ns'
# docker_args = '-e NS_TIMEOUT=4h --cpus=1 --memory=32G'
docker_args = f'-e CHANGE_UID={os.getuid()} -e NS_TIMEOUT=50m -e BINARY_TIMEOUT=25m -v /home/user/ns/dev/NativeSummary/benchmarks/minSourcesAndSinks.txt:/root/ss.txt'
image_args = '--taint'
# image_args = '--taint'

def gen(dataset_path, out_dataset_path, container_name_template="ns-{}"):
    if not os.path.isfile(dataset_path):
        dirs = sorted(os.listdir(dataset_path))
    else:
        dirs = [os.path.basename(dataset_path)]
        dataset_path = os.path.dirname(dataset_path)
    for file in dirs:
        if not file.endswith('.apk'):
            continue
        fpath = os.path.join(dataset_path, file)
        # check run finished
        if os.path.exists(os.path.join(fpath, "NS_FINISHED")):
            print(f"{file} finished.", file=sys.stderr)
        else:
            container_name = container_name_template.format(file)
            result_dir = os.path.join(out_dataset_path, file)
            if not os.path.exists(result_dir):
                os.makedirs(result_dir)
            run_cmd_suffix = f' {docker_args} -v {fpath}:/apk -v {result_dir}:/out'
            run_cmd = f"docker run -i --name {container_name} --rm {run_cmd_suffix} {IMAGE_NAME} {image_args}"
            print(run_cmd, end=';')
            # print(f"mv {result_dir}/repacked_apks/apk {fpath}.repacked.apk", end=';')
        print("\x00", end="")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f'command generator. Usage: {sys.argv[0]} | xargs -0 -I CMD --max-procs=1 bash -c CMD')
    parser.add_argument('--apk', type=str, required=True, help='apk folder path')
    parser.add_argument('--out', type=str, required=True, help='output folder path')
    # parser.add_argument('--process', default=1, type=int, help="multiprocessing process count. default: 1 (single process) (depricated)")
    args = parser.parse_args(sys.argv[1:])
    gen(args.apk, args.out)
