#!/bin/bash

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
set -e

mkdir -p $SCRIPTPATH/root

# https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip
# if ghidra not extracted, extract it.
if [ ! -e "$SCRIPTPATH/root/ghidra_10.1.2_PUBLIC" ]; then
  unzip $SCRIPTPATH/ghidra_10.1.2_PUBLIC_20220125.zip -d $SCRIPTPATH/root/
fi

# copy native_summary_bai release file to root folder
pushd $SCRIPTPATH/native_summary_bai/dist
unset -v latest
for file in ./*; do
  [[ $file -nt $latest ]] && latest=$file
done
echo using $latest
cp $latest $SCRIPTPATH/root/ghidra_10.1.2_PUBLIC_native_summary_bai.zip
popd

# copy native_summary_java release jar
cp $SCRIPTPATH/native_summary_java/target/native_summary-1.0-SNAPSHOT.jar $SCRIPTPATH/root/

# copy pre_analysis module
rm -r $SCRIPTPATH/native_summary_bai/pre_analysis/__pycache__ 2> /dev/null || true
cp -r $SCRIPTPATH/native_summary_bai/pre_analysis $SCRIPTPATH/root/
cp $SCRIPTPATH/native_summary_bai/preana.py $SCRIPTPATH/root/

# copy platforms folder (big)
if [ ! -e "$SCRIPTPATH/root/platforms" ]; then
  echo copying platforms folder
  mkdir -p $SCRIPTPATH/root/platforms
  cp -r $SCRIPTPATH/platforms/* $SCRIPTPATH/root/platforms/
fi

# copy related scripts
cp $SCRIPTPATH/native_summary_bai/runner.py $SCRIPTPATH/root/
cp $SCRIPTPATH/README.md $SCRIPTPATH/root/
cp $SCRIPTPATH/main.py $SCRIPTPATH/root/
