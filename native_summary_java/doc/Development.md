

### Jadx 反编译opaque predicate异常

出现下面的情况
```
if (opred != 1) {
    if (opred != 2) {
        if (opred == 3) {
            xxx = xxx;
        }
    }
}
```

当类型相同时不生成cast表达式后解决。

### type analysis

顺序推断：
- 函数返回值

逆向推断类型：
- 函数参数，
- 
