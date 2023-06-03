# Description

### native_summary

now only pre analysis part of this module is used. (`native_summary.pre_analysis`, especially `native_summary.pre_analysis.bai`) 

angr based framework is depricated, but not deleted.

when bulk analyzing apks and to interrupt, only press once Ctrl-C and wait program to stop. press twice or more may result in progress not saved correctly.

### setup

```
pip install androguard pyelftools
python ./setup.py install
```

Usage:

```
python -m native_summary.pre_analysis.bai "D:\~datasets\malradar" "D:\~datasets\malradar_bai_preana"
```

### TODO

completely rewrite with java. using something like jadx.

## below is depricated

### efficiency

The initilization time, especially `import angr` takes really long. So bulk running really should be done within python level.


### native_summary.pre_analysis module

This module is designed to be efficient(not import angr), and do basic static JNI native function resolving.


### History

This project initially is based on a fork of [nativediscloser](https://github.com/gaojun0816/nativediscloser), but now basically 99% of the original code is replaced.

JNI API model is based on angr's code.
