#!/bin/bash
# run flowdroid after ns finishes.

# source and sinks file
SS=/root/ss.txt

if [ -z "$1" ]
  then
    echo "No argument 1: ns folder (single apk mode)"
fi

if [ ! -e "$1/repacked_apks/apk" ]
then
    echo "cannot find apk to run flowdroid."
    exit 0
fi

if [ -e "$1/repacked_apks/FD_FINISH" ]
then
    echo $1/repacked_apks/FD_FINISH
    echo "flowdroid already run."
    exit 0
fi

# copy
cp $1/repacked_apks/apk $1/repacked_apks/apk.apk
cp $SS $1/repacked_apks/sources-sinks.txt
cat $1/repacked_apks/apk.sinks.txt >> $1/repacked_apks/sources-sinks.txt
SS=$1/repacked_apks/sources-sinks.txt

# --pathalgo CONTEXTSENSITIVE --pathreconstructionmode PRECISE 
# --pathspecificresults --staticmode CONTEXTFLOWSENSITIVE \

/usr/bin/time -v java -jar /root/flowdroid.jar \
--mergedexfiles --pathreconstructionmode PRECISE \
-s $SS \
-p /root/platforms -o $1/repacked_apks/fd.xml -a $1/repacked_apks/apk.apk \
 1> $1/repacked_apks/fd.stdout.txt 2> $1/repacked_apks/fd.stderr.txt

xmllint --format $1/repacked_apks/fd.xml -o $1/repacked_apks/fd.xml

touch $1/repacked_apks/FD_FINISH
