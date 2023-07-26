# NativeSummary

A new inter-language Android application static analysis framework using static analysis (based on BinAbsInspector) instead of symbolic execution to make binary code analysis more efficient. To make binary analysis results more generic, we translate the semantic summary extracted from binary code to java bytecode, inject the generated method body into the corresponding native method on the java side, and repack it as a new apk file.

## projects layout

main projects layout for this organization account:

- native_summary_bai/pre_analysis: preanalysis module.
    - requires platforms folder
- native_summary_bai: binary analysis module based on BinAbsInspector
    - uses NativeSummaryIR
- native_summary_java: Generate body for native methods in APK.
    - uses NativeSummaryIR
    - requires platforms folder

## Docker

the docker image is publicly available at https://hub.docker.com/u/nativesummary

### Quick Start

mount apk or a folder containing apk files as /apk. create a output folder and mount to `/out`. (the repacked apk is under `/out/repacked_apks/`)

1. analyze single apk file: (recommended)
    ```bash
    docker run --rm -it -v /dataset/nfbe/native_handle-release-unsigned.apk:/apk -v /nfbe-results/native_handle-release-unsigned.apk:/out nativesummary/nativesummary
    ```
1. analyze apk files in a folder
    ```bash
    docker run --rm -it -v /dataset/nfbe:/apk -v /nfbe-results:/out nativesummary/nativesummary
    ```
1. get a shell.
    ```bash
    docker run -it -v -v /dataset/nfbe:/apk -v /nfbe-results:/out --entrypoint /bin/bash nativesummary/nativesummary
    ```

use `NS_TIMEOUT` to limit the running time of the whole analysis. the value is directly passed to `timeout`. for example: `NS_TIMEOUT=2h`
use `GHIDRA_NS_ARGS` env variable to pass arguments to ghidra scripts.
use `NS_PREFER_32=True` to prefer select 32bit arm.
use `NS_SELECT_ARCH` to directly select an arch. (must in ['arm64-v8a', 'armeabi-v7a', 'armeabi'])

## Development - build docker image

- recursive clone this project. 
    - `git clone`
    - `git submodule update --init --recursive`
- build native_summary_bai and build native_summary_java.
- download `ghidra_10.1.2_PUBLIC_20220125.zip` here
- run `copy-release.sh` to copy build artifacts to `./root` directory
- build docker image

```bash
docker build . --tag ns --build-arg UBUNTU_MIRROR=mirrors.ustc.edu.cn --build-arg PYTHON_MIRROR=pypi.tuna.tsinghua.edu.cn
```

to move image to another machine, first export image to a tar file using `docker save ns -o ns.tar`, then import using `docker load -i ns.tar`
