#!/bin/bash

TIMEOUT=${NS_TIMEOUT:-0}
echo Timeout: $TIMEOUT
/usr/bin/time -v /usr/bin/timeout $TIMEOUT /usr/bin/python3 main.py "$@"
