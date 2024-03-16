#!/bin/bash

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# analyzing native flow bench
python $SCRIPTPATH/../scripts/docker_runner_xargs.py --ss_file $SCRIPTPATH/minSourcesAndSinks.txt --run_flowdroid --apk $SCRIPTPATH/nfb --out $SCRIPTPATH/out_nfb | xargs -0 -I CMD --max-procs=30 bash -c CMD

