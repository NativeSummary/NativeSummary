#!/usr/bin/python3
import json
import os,sys
import shutil
import time
from multiprocessing import Process, Queue
import subprocess

IMAGE_NAME = 'ns'
# docker_args = '-e NS_TIMEOUT=4h --cpus=1 --memory=32G'
docker_args = '-e NS_TIMEOUT=4h'
image_args = '--taint'

def gen(dataset_path, out_dataset_path, container_name_template="ns-{}"):
    for file in sorted(os.listdir(dataset_path)):
        if not file.endswith('.apk'):
            continue
        fpath = os.path.join(dataset_path, file)
        # check run finished
        if os.path.exists(os.path.join(fpath, "NS_FINISHED")):
            print(f"{file} finished.", file=sys.stderr)
        else:
            container_name = container_name_template.format(file)
            result_dir = os.path.join(out_dataset_path, file)
            run_cmd_suffix = f' {docker_args} -v {fpath}:/apk -v {result_dir}:/out'
            run_cmd = f"docker run -i --name {container_name} --rm {run_cmd_suffix} {IMAGE_NAME} {image_args}"
            print(run_cmd)
        print("\x00", end="")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=f'command generator. Usage: {sys.argv[0]} | sudo xargs -0 -I CMD --max-procs=1 bash -c CMD')
    parser.add_argument('--apk', type=str, required=True, help='apk folder path')
    parser.add_argument('--out', type=str, required=True, help='output folder path')
    # parser.add_argument('--process', default=1, type=int, help="multiprocessing process count. default: 1 (single process) (depricated)")
    args = parser.parse_args(sys.argv[1:])
    gen(args.apk, args.out)