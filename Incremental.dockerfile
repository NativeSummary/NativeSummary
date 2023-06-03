FROM ns-old:latest

ENV GHIDRA_INSTALL_DIR=/opt/ghidra_10.1.2_PUBLIC
SHELL ["/bin/bash", "-c"]

WORKDIR /

RUN rm -rf /root/*

WORKDIR /root

COPY . /root/

RUN cd /root/pre_analysis_py \
    && python3 setup.py develop \
    && python3 -m pip install -r requirements-new.txt \
    && cd /root/native_summary_java \
    && mvn package \
    && cd /root/native_summary_bai \
    && mkdir -p ~/.gradle && echo "GHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR" >> ~/.gradle/gradle.properties \
    && bash ./auto-install.sh

ENTRYPOINT [ "/usr/bin/python3", "main.py" ]
