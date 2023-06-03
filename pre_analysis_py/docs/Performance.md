
### Performance info

一次performance数据 = 一个APK的时间 = Dex时间 + 每个SO的时间 * n + 其他时间

每个so的时间 = 一次CFG时间 + 每个JNI函数的时间 * n

CFG成功的才会被计数到analyzed_so中

每个JNI函数的时间 = cfg_time（plot的时间） + vfg_time + ddg_time，被分类累加起来。

超时和失败的JNI函数不会被累加。

### 文件中的数据

第二行elapsed,dex_time,cfg_time,vfg_time,ddg_time,other_time,analyzed_so,analyzed_func,func_timeout,dymamic_timeout

第三行str(dict(self.failed_javamth))

第四行str(self.func_times)各个函数花的时间

add_analyzed_func 是分析过的函数总数，包括失败的和timeout的。失败的数量可以通过failed_javamth内部方法数量获取。

cfg_time 包含so的cfg，和plot每个函数的cfg所花费的时间。但是数据集分析时一般都需要关闭每个函数的cfg和ddg。

other_time = self.elapsed - self.dex_time - self.cfg_time - self.vfg_time - self.ddg_time

但是数据集分析时一般都需要关闭每个函数的cfg和ddg，所以总elapsed就是四部分，dex_time cfg_time vfg_time other_time

### 数据计算

先解释一下运行设置，即两个超时时间。

首先是用户感知的运行时间，即平均的总运行时间，画个关于APK大小的散点图。

能生成非空ss.json的应用占比。平均每个应用生成的函数体数量

总时间占比上，dex，CFG和VFG比例。

对每一个so库，统计CFG失败的so占比（搜索打印分析失败的记录的数量加上analyzed_so为总数）

对每一个函数，统计超时和失败的JNI函数数量的占比。。最后画个每个函数所花时间的箱形图

~语义信息不为空的函数数量，占总本地函数数量，占总Java侧函数数量。~
```
 总应用数 516
 用户平均运行时间：137.94533908103844 秒
 ss非空的应用占比：0.5852713178294574 
 平均每个应用生成函数数量：18.410852713178294 
 SO-CFG构建失败占比：0.017543859649122806
 SO-CFG构建超时占比：0.10721247563352826
 超时函数占比：0.011923076923076923
 失败函数占比：0.13153846153846155
 用户平均运行时间：137.94533908103844
 dex平均运行时间：28.003591591688167, 0.2030049857301591
 cfg平均运行时间：48.464796378430684, 0.35133333754726703
 vfg平均运行时间：25.604453368824135, 0.18561303730445247
 其他平均运行时间：35.87249774209545, 0.26004863941812134
```