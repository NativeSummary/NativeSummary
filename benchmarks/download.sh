#!/bin/bash

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# this script requires subversion
# apt install subversion

if [ ! -e "$SCRIPTPATH/nfb" ]; then
    svn export https://github.com/arguslab/NativeFlowBench/trunk/apks "$SCRIPTPATH/nfb"
fi

if [ ! -e "$SCRIPTPATH/jucifybench" ]; then
    svn export --depth=files https://github.com/JordanSamhi/JuCify/trunk/benchApps "$SCRIPTPATH/jucifybench"
fi

if [ ! -e "$SCRIPTPATH/nfbe" ]; then
    svn export https://github.com/NativeSummary/NativeFlowBenchExtended/trunk/apks "$SCRIPTPATH/nfbe"
fi
