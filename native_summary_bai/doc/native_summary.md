# Native Summary

###  分析架构

分析一个so，对每个JNI函数启动一次BAI分析。因此单次执行会启动多次BinAbsInspector，导致原来的GlobalState不再是真正“Global”的了。因此引入新的MyGlobalState。

### 尾调用

为了解决部分函数尾调用的问题，增加一个outOfRangeAddrMap。在call指令处检查当前的pcodeVisitor的context的函数是不是当前指令地址的函数。如果不是则加入map。后面在找callsites的context的时候如果找不到，就可以到map对应的函数里寻找。
