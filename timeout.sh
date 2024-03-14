#!/bin/bash

TIMEOUT=${NS_TIMEOUT:-0}
echo NS_TIMEOUT: $TIMEOUT
stdbuf -e 0 /usr/bin/time -v /usr/bin/timeout --kill-after=60s $TIMEOUT  /usr/bin/python3 main.py "$@" 2> >(tee /out/docker_stderr.txt)
# create an empty file as a flag for finished.
touch /out/NS_FINISHED

if [[ ! -v CHANGE_UID ]]; then
    echo "CHANGE_UID is not set, not changing owner."
elif [[ -z "$CHANGE_UID" ]]; then
    echo "CHANGE_UID is set to the empty string"
else
    echo "Changing output dir owner to: $CHANGE_UID"
    chown $CHANGE_UID:$CHANGE_UID -R /out
fi

sleep 10s
