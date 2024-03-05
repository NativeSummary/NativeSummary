#!/bin/bash

set -e

pushd native_summary_bai
./build-and-install.sh
popd

pushd native_summary_java
mvn package
popd

./copy-release.sh

echo root ok

docker image rm ns || true
docker build . --tag ns --build-arg UBUNTU_MIRROR=mirrors.ustc.edu.cn --build-arg PYTHON_MIRROR=pypi.tuna.tsinghua.edu.cn
