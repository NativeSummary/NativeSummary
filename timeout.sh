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

if [[ ! -z "$GHIDRA_PROJECT_OWNER" ]]; then
    echo "Changing ghidra project owner to: $GHIDRA_PROJECT_OWNER"
    sed -i "s/root/$GHIDRA_PROJECT_OWNER/" /out/project/native_summary.rep/project.prp
fi

if [[ "$@" == *"--taint"* ]]; then
    echo Run flowdroid!
    bash /root/run_flowdroid.sh /out
fi

sleep 10s
