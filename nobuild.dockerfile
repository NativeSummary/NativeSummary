FROM ubuntu:22.04

# docker build -f ./nobuild.dockerfile . --tag ns --build-arg UBUNTU_MIRROR=mirrors.ustc.edu.cn --build-arg PYTHON_MIRROR=pypi.tuna.tsinghua.edu.cn --build-arg GHIDRA_PATH=ghidra_10.1.2_PUBLIC_20220125.zip
ARG UBUNTU_MIRROR
# =mirrors.tuna.tsinghua.edu.cn
ARG PYTHON_MIRROR
# =pypi.tuna.tsinghua.edu.cn
# ARG UBUNTU_MIRROR

SHELL ["/bin/bash", "-c"]

# openjdk-8-jdk
RUN if [[ ! -z "$UBUNTU_MIRROR" ]] ; then sed -i "s/archive.ubuntu.com/$UBUNTU_MIRROR/g" /etc/apt/sources.list \
 && sed -i "s/security.ubuntu.com/$UBUNTU_MIRROR/g" /etc/apt/sources.list ; fi ; \
 apt update && DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends wget unzip 7zip sudo software-properties-common nano python3-pip openjdk-11-jdk-headless maven gradle \
 && if [[ ! -z "$PYTHON_MIRROR" ]] ; then python3 -m pip config set global.index-url https://$PYTHON_MIRROR/simple ; fi ; \
 apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /root

ARG GHIDRA_PATH="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip"
ADD ${GHIDRA_PATH} /opt/ghidra.zip
RUN unzip /opt/ghidra.zip -d /opt && rm /opt/ghidra.zip
ENV GHIDRA_INSTALL_DIR=/opt/ghidra_10.1.2_PUBLIC

COPY . /root/

RUN rm -f ghidra*.zip \
    && cd /root/pre_analysis_py \
    && python3 setup.py develop \
    && python3 -m pip install -r requirements-new.txt \
    && cd /root/native_summary_java \
    && ls target/native_summary-1.0-SNAPSHOT.jar \
    && cd /root/native_summary_bai \
    && mkdir -p ~/.gradle && echo "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" >> ~/.gradle/gradle.properties \
    && bash ./auto-install.sh nobuild

WORKDIR /root
ENTRYPOINT [ "/usr/bin/python3", "main.py" ]

# docker run -it --name ns fbe9abab37a6
