from collections import defaultdict
import timeit


class Performance:
    """
    _num_analyzed_func是总数，减去failed和timeout得到正常分析的函数。failed和timeout的不会将时间计入vfg_time等。
    """
    def __init__(self):
        self._start_at = None
        self._end_at = None
        self._num_analyzed_func = 0
        self._num_analyzed_so = 0
        self._num_timeout = 0
        self._num_failed = 0
        self._dynamic_func_reg_analysis_timeout = 0 # TODO
        self.prev_cfg = None
        self.cfg_time = 0.0
        self.vfg_time = 0.0
        self.ddg_time = 0.0
        self.dex_time = None
        self.failed_javamth = defaultdict(list)
        self.func_times = []

    def add_failed_javamth(self, so_name, symbol):
        self.failed_javamth[so_name].append(symbol)

    def add_so_times(self, cfg_time, vfg_time, ddg_time):
        self.cfg_time += cfg_time
        self.vfg_time += vfg_time
        self.ddg_time += ddg_time
        self.func_times.append(vfg_time)

    # CFG支持多次开始结束
    def start_cfg(self):
        self.prev_cfg = timeit.default_timer()
    
    def end_cfg(self):
        self.cfg_time += (timeit.default_timer() - self.prev_cfg)

    # DEX不支持多次开始结束
    def start_dex(self):
        self.dex_time = timeit.default_timer()
    
    def end_dex(self):
        self.dex_time = (timeit.default_timer() - self.dex_time)


    def start(self):
        self._start_at = timeit.default_timer()

    def end(self):
        self._end_at = timeit.default_timer()

    def add_analyzed_func(self):
        self._num_analyzed_func += 1

    def add_analyzed_so(self):
        self._num_analyzed_so += 1

    def add_timeout(self):
        self._num_timeout += 1
    
    def add_failed(self):
        self._num_failed += 1

    def add_dynamic_reg_timeout(self):
        self._dynamic_func_reg_analysis_timeout += 1

    @property
    def elapsed(self):
        if self._start_at is None or self._end_at is None:
            return None
        else:
            return self._end_at - self._start_at

    def __str__(self):
        other_time = self.elapsed - self.dex_time - self.cfg_time - self.vfg_time - self.ddg_time
        s = 'elapsed,dex_time,cfg_time,vfg_time,ddg_time,other_time,analyzed_so,analyzed_func,func_timeout,dymamic_timeout\n'
        s += f'{self.elapsed},{self.dex_time},{self.cfg_time},{self.vfg_time},{self.ddg_time},{other_time},{self._num_analyzed_so},{self._num_analyzed_func},{self._num_timeout},{self._dynamic_func_reg_analysis_timeout}\n'
        s += str(dict(self.failed_javamth))
        s += '\n'
        s += str(self.func_times)
        return s


class SubPerformance():
    """
    CFG_time is time to plot out cfg
    """
    def __init__(self):
        self.cfg_start = None
        self.vfg_start = None
        self.ddg_start = None
        self.cfg_time = 0.0
        self.vfg_time = 0.0
        self.ddg_time = 0.0

    def get_times(self):
        return (self.cfg_time, self.vfg_time, self.ddg_time)

    def start_cfg(self):
        self.cfg_start = timeit.default_timer()
    
    def end_cfg(self):
        self.cfg_time = (timeit.default_timer() - self.cfg_start)

    def start_vfg(self):
        self.vfg_start = timeit.default_timer()
    
    def end_vfg(self):
        self.vfg_time = (timeit.default_timer() - self.vfg_start)

    def start_ddg(self):
        self.ddg_start = timeit.default_timer()
    
    def end_ddg(self):
        self.ddg_time = (timeit.default_timer() - self.ddg_start)

