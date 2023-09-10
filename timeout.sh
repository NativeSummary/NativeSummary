#!/bin/bash

TIMEOUT=${NS_TIMEOUT:-0}
echo NS_TIMEOUT: $TIMEOUT
stdbuf -e 0 /usr/bin/time -v /usr/bin/timeout --kill-after=60s $TIMEOUT  /usr/bin/python3 main.py "$@" 2> >(tee /out/docker_stderr.txt)
# create an empty file as a flag for finished.
touch /out/NS_FINISHED

sleep 10s
