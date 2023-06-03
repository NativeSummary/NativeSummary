### interfunction_hook

传入VFG分析中，返回Bool值表示是否跳过这个call指令。True表示跳过

参数：self(VFG), job, successor（Ijk_call state）, all_successors[-1]（FakeRet state）

返回值：is_skip

func = self.kb.functions.function(addr=job.call_target)

对successor判断是否需要跳过，如果要对返回值建模就修改FakeRet state。

