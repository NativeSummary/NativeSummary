FROM ubuntu:22.04

# docker build . --tag ns --build-arg UBUNTU_MIRROR=mirrors.ustc.edu.cn --build-arg PYTHON_MIRROR=pypi.tuna.tsinghua.edu.cn --build-arg GHIDRA_PATH=ghidra_10.1.2_PUBLIC_20220125.zip
ARG UBUNTU_MIRROR
# =mirrors.tuna.tsinghua.edu.cn
ARG PYTHON_MIRROR
# =pypi.tuna.tsinghua.edu.cn
# ARG UBUNTU_MIRROR

SHELL ["/bin/bash", "-c"]

# openjdk-8-jdk
RUN if [[ ! -z "$UBUNTU_MIRROR" ]] ; then sed -i "s/archive.ubuntu.com/$UBUNTU_MIRROR/g" /etc/apt/sources.list \
 && sed -i "s/security.ubuntu.com/$UBUNTU_MIRROR/g" /etc/apt/sources.list ; fi ; \
 apt update && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends time wget unzip 7zip sudo software-properties-common nano python3-pip openjdk-17-jdk-headless libxml2-utils \
 && if [[ ! -z "$PYTHON_MIRROR" ]] ; then python3 -m pip config set global.index-url https://$PYTHON_MIRROR/simple ; fi ; \
 python3 -m pip install pyelftools androguard \
 && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /root

ENV GHIDRA_INSTALL_DIR=/root/ghidra_10.1.2_PUBLIC

COPY root/ /root/

RUN python3 -m pip install -r /root/pre_analysis/requirements.txt \
    && mkdir -p ~/.ghidra/.ghidra_10.1.2_PUBLIC/Extensions/ \
    && unzip /root/ghidra_10.1.2_PUBLIC_native_summary_bai.zip -d ~/.ghidra/.ghidra_10.1.2_PUBLIC/Extensions/

WORKDIR /root
ENTRYPOINT [ "/usr/bin/bash", "timeout.sh" ]
