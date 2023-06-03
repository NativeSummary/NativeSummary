# NativeSummary

A new inter-language Android application static analysis framework using static analysis (based on BinAbsInspector) instead of symbolic execution to make binary code analysis more efficient. To make binary analysis results more generic, we translate the semantic summary extracted from binary code to java bytecode, inject the generated method body into the corresponding native method on the java side, and repack it as a new apk file.

## projects layout

main projects layout for this organization account:

- pre_analysis_py: preanalysis module. used to be binary analysis module using angr's VSA, but now depricated
    - requires platforms folder
- native_summary_bai: binary analysis module based on BinAbsInspector
    - uses NativeSummaryIR
- native_summary_java: Generate body for native methods in APK.
    - uses NativeSummaryIR
    - requires platforms folder

## Docker

### Quick Start

Download `ns.7z` in release, extract and get the tar file, load it to docker using `docker load -i ns.tar`.

mount apk or a folder containing apk files as /apk. create a output folder and mount to `/out`. (the repacked apk is under `/out/repacked_apks/`)

1. analyze single apk file:
    ```bash
    docker run --rm -it -v /dataset/nfbe/native_handle-release-unsigned.apk:/apk -v /nfbe-results/native_handle-release-unsigned.apk:/out ns
    ```
1. analyze apk files in a folder
    ```bash
    docker run --rm -it -v /dataset/nfbe:/apk -v /nfbe-results:/out ns
    ```
1. get a shell. you can modify source code, build, run.
    ```bash
    docker run -it -v -v /dataset/nfbe:/apk -v /nfbe-results:/out --entrypoint /bin/bash ns
    ```


### build

1. download ghidra_10.1.2_PUBLIC_20220125.zip here

```bash
docker build . --tag ns --build-arg UBUNTU_MIRROR=mirrors.ustc.edu.cn --build-arg PYTHON_MIRROR=pypi.tuna.tsinghua.edu.cn --build-arg GHIDRA_PATH=ghidra_10.1.2_PUBLIC_20220125.zip
```

to move image to another machine, first export using `docker save ns -o ns.tar`, then import using `docker load -i ns.tar`

