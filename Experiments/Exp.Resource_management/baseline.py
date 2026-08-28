from __future__ import annotations
from dataclasses import dataclass
from collections import defaultdict
from typing import DefaultDict, Optional, Tuple
import math

EPS = 1e-6

def clip(x: float, lo: float, hi: float) -> float:
    return lo if x < lo else hi if x > hi else x

@dataclass
class PodState:
    active: bool = False
    on_cnt: int = 0
    off_cnt: int = 0

    # generic baselines
    cpu_ema: Optional[float] = None
    net_ema: Optional[float] = None

    # cusum
    cusum_cpu: float = 0.0
    cusum_net: float = 0.0

    # token/leaky bucket
    last_t: Optional[float] = None
    tokens: float = 0.0
    backlog: float = 0.0

def ema(old: Optional[float], x: float, g: float) -> float:
    return x if old is None else (1.0 - g) * old + g * x

def net_burst_ratio(net: float, net_ema: Optional[float], net_min: float) -> float:
    if net_ema is None or net_ema < net_min:
        return 0.0
    return max(0.0, (net - net_ema) / (net_ema + EPS))

class _BaseRisk:
    """
    update(pod, cpu_core, net_bps, t=None) -> (R, changed, active)
      - t: seconds (float). Passing it makes the dt used by the token/leaky bucket and cusum exact.
    """
    def __init__(self, th_on=3.0, th_off=0.8, k_on=2, k_off=3):
        self.th_on = float(th_on)
        self.th_off = float(th_off)
        self.k_on = int(k_on)
        self.k_off = int(k_off)
        self.state: DefaultDict[str, PodState] = defaultdict(PodState)

    def _hysteresis(self, s: PodState, R: float) -> Tuple[bool, bool]:
        if R > self.th_on:
            s.on_cnt += 1
            s.off_cnt = 0
        elif R < self.th_off:
            s.off_cnt += 1
            s.on_cnt = 0
        else:
            s.on_cnt = 0
            s.off_cnt = 0

        changed = False
        if (not s.active) and (s.on_cnt >= self.k_on):
            s.active = True
            changed = True
        if s.active and (s.off_cnt >= self.k_off):
            s.active = False
            changed = True
        return changed, s.active

    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None) -> Tuple[float, bool, bool]:
        raise NotImplementedError


# =========================================================
# 1) Kubernetes HPA-style ratio risk
#   r_cpu = max(0, c/c* - 1), r_net = max(0, n/n* - 1)
#   combine: max OR / sum
# =========================================================
class RiskHPARatio(_BaseRisk):
    def __init__(
        self,
        cpu_target: float = 0.5,   # c*
        net_target: float = 50_000.0,  # n*
        use_cpu: bool = True,
        use_net: bool = True,
        combine: str = "max",      # "max" | "sum"
        th_on=3.0, th_off=0.8, k_on=2, k_off=3,
    ):
        super().__init__(th_on=th_on, th_off=th_off, k_on=k_on, k_off=k_off)
        self.cpu_target = float(cpu_target)
        self.net_target = float(net_target)
        self.use_cpu = bool(use_cpu)
        self.use_net = bool(use_net)
        self.combine = combine.lower().strip()

    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s = self.state[pod]
        cpu = float(cpu_core)
        net = float(net_bps)

        r_cpu = max(0.0, cpu / (self.cpu_target + EPS) - 1.0) if self.use_cpu else 0.0
        r_net = max(0.0, net / (self.net_target + EPS) - 1.0) if self.use_net else 0.0

        if self.combine == "sum":
            R = r_cpu + r_net
        else:
            R = max(r_cpu, r_net)

        changed, active = self._hysteresis(s, R)
        return R, changed, active


# =========================================================
# 2) EWMA baseline + CPU excess only (log-compressed)
#   c_ema, allow = c_ema(1+m), excess = max(0, c - allow)
#   R = log(1 + excess/(c_ema+eps))
# =========================================================
class RiskCPUOnlyEWMA(_BaseRisk):
    def __init__(
        self,
        cpu_gamma: float = 0.02,
        cpu_margin: float = 0.25,
        th_on=3.0, th_off=0.8, k_on=2, k_off=3,
    ):
        super().__init__(th_on=th_on, th_off=th_off, k_on=k_on, k_off=k_off)
        self.cpu_gamma = float(cpu_gamma)
        self.cpu_margin = float(cpu_margin)

    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s = self.state[pod]
        cpu = float(cpu_core)

        s.cpu_ema = ema(s.cpu_ema, cpu, self.cpu_gamma)
        if s.cpu_ema is None:
            s.cpu_ema = cpu

        cpu_allow = s.cpu_ema * (1.0 + self.cpu_margin)
        cpu_excess = max(0.0, cpu - cpu_allow)
        R = math.log1p(cpu_excess / (s.cpu_ema + EPS))

        changed, active = self._hysteresis(s, R)

        return R, changed, active

    # def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
    #     s = self.state[pod]
    #     cpu = float(cpu_core)

    #     # baseline init
    #     if s.cpu_ema is None:
    #         s.cpu_ema = cpu

    #     prev_active = s.active  # state before hysteresis

    #     # freeze the baseline while active, update it while inactive
    #     if prev_active:
    #         cpu_ema = s.cpu_ema
    #     else:
    #         cpu_ema = ema(s.cpu_ema, cpu, self.cpu_gamma)
    #         s.cpu_ema = cpu_ema  # store only while inactive

    #     cpu_allow = cpu_ema * (1.0 + self.cpu_margin)
    #     cpu_excess = max(0.0, cpu - cpu_allow)
    #     R = math.log1p(cpu_excess / (cpu_ema + EPS))

    #     changed, active = self._hysteresis(s, R)  # assumes s.active is updated inside
    #     return R, changed, active


# =========================================================
# 3) NET burst ratio only (log-compressed)
#   b = max(0, (n - n_ema)/(n_ema+eps)), R = lam*log(1+b)
# =========================================================
class RiskNetOnlyBurst(_BaseRisk):
    def __init__(
        self,
        net_gamma: float = 0.02,
        net_min: float = 1024.0,
        lam: float = 2.0,
        th_on=3.0, th_off=0.8, k_on=2, k_off=3,
    ):
        super().__init__(th_on=th_on, th_off=th_off, k_on=k_on, k_off=k_off)
        self.net_gamma = float(net_gamma)
        self.net_min = float(net_min)
        self.lam = float(lam)

    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s = self.state[pod]
        net = float(net_bps)

        s.net_ema = ema(s.net_ema, net, self.net_gamma)
        if s.net_ema is None:
            s.net_ema = net

        b = net_burst_ratio(net, s.net_ema, self.net_min)
        R = self.lam * math.log1p(b)

        changed, active = self._hysteresis(s, R)
        return R, changed, active


# =========================================================
# 4) Weighted sum (no gate)
#   R = w_net*log(1+b) + w_cpu*log(1+cpu_excess/c_ema)
# =========================================================
class RiskWeightedSum(_BaseRisk):
    def __init__(
        self,
        net_gamma: float = 0.02,
        cpu_gamma: float = 0.02,
        net_min: float = 1024.0,
        cpu_margin: float = 0.25,
        w_net: float = 2.0,
        w_cpu: float = 1.0,
        th_on=3.0, th_off=0.8, k_on=2, k_off=3,
    ):
        super().__init__(th_on=th_on, th_off=th_off, k_on=k_on, k_off=k_off)
        self.net_gamma = float(net_gamma)
        self.cpu_gamma = float(cpu_gamma)
        self.net_min = float(net_min)
        self.cpu_margin = float(cpu_margin)
        self.w_net = float(w_net)
        self.w_cpu = float(w_cpu)

    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s = self.state[pod]
        cpu = float(cpu_core)
        net = float(net_bps)

        s.net_ema = ema(s.net_ema, net, self.net_gamma)
        s.cpu_ema = ema(s.cpu_ema, cpu, self.cpu_gamma)
        if s.net_ema is None: s.net_ema = net
        if s.cpu_ema is None: s.cpu_ema = cpu

        b = net_burst_ratio(net, s.net_ema, self.net_min)
        r_net = math.log1p(b)

        cpu_allow = s.cpu_ema * (1.0 + self.cpu_margin)
        cpu_excess = max(0.0, cpu - cpu_allow)
        r_cpu = math.log1p(cpu_excess / (s.cpu_ema + EPS))

        R = self.w_net * r_net + self.w_cpu * r_cpu
        changed, active = self._hysteresis(s, R)
        return R, changed, active


# =========================================================
# 5) OR / AND combination (hard logical combination)
#   OR: max(w_net*r_net, w_cpu*r_cpu)
#   AND-min: min(...)
#   AND-prod: (...) * (...)
# =========================================================
class RiskLogicORMax(_BaseRisk):
    def __init__(
        self,
        net_gamma=0.02, cpu_gamma=0.02, net_min=1024.0, cpu_margin=0.25,
        w_net=2.0, w_cpu=1.0,
        th_on=3.0, th_off=0.8, k_on=2, k_off=3,
    ):
        super().__init__(th_on=th_on, th_off=th_off, k_on=k_on, k_off=k_off)
        self.net_gamma=float(net_gamma); self.cpu_gamma=float(cpu_gamma)
        self.net_min=float(net_min); self.cpu_margin=float(cpu_margin)
        self.w_net=float(w_net); self.w_cpu=float(w_cpu)

    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s=self.state[pod]
        cpu=float(cpu_core); net=float(net_bps)
        s.net_ema=ema(s.net_ema, net, self.net_gamma)
        s.cpu_ema=ema(s.cpu_ema, cpu, self.cpu_gamma)
        if s.net_ema is None: s.net_ema=net
        if s.cpu_ema is None: s.cpu_ema=cpu

        b=net_burst_ratio(net, s.net_ema, self.net_min)
        r_net=self.w_net*math.log1p(b)

        cpu_allow=s.cpu_ema*(1.0+self.cpu_margin)
        cpu_excess=max(0.0, cpu-cpu_allow)
        r_cpu=self.w_cpu*math.log1p(cpu_excess/(s.cpu_ema+EPS))

        R=max(r_net, r_cpu)
        changed, active=self._hysteresis(s, R)
        return R, changed, active

class RiskLogicANDMin(RiskLogicORMax):
    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s=self.state[pod]
        cpu=float(cpu_core); net=float(net_bps)
        s.net_ema=ema(s.net_ema, net, self.net_gamma)
        s.cpu_ema=ema(s.cpu_ema, cpu, self.cpu_gamma)
        if s.net_ema is None: s.net_ema=net
        if s.cpu_ema is None: s.cpu_ema=cpu

        b=net_burst_ratio(net, s.net_ema, self.net_min)
        r_net=self.w_net*math.log1p(b)

        cpu_allow=s.cpu_ema*(1.0+self.cpu_margin)
        cpu_excess=max(0.0, cpu-cpu_allow)
        r_cpu=self.w_cpu*math.log1p(cpu_excess/(s.cpu_ema+EPS))

        R=min(r_net, r_cpu)
        changed, active=self._hysteresis(s, R)
        return R, changed, active

class RiskLogicANDProduct(RiskLogicORMax):
    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s=self.state[pod]
        cpu=float(cpu_core); net=float(net_bps)
        s.net_ema=ema(s.net_ema, net, self.net_gamma)
        s.cpu_ema=ema(s.cpu_ema, cpu, self.cpu_gamma)
        if s.net_ema is None: s.net_ema=net
        if s.cpu_ema is None: s.cpu_ema=cpu

        b=net_burst_ratio(net, s.net_ema, self.net_min)
        r_net=self.w_net*math.log1p(b)

        cpu_allow=s.cpu_ema*(1.0+self.cpu_margin)
        cpu_excess=max(0.0, cpu-cpu_allow)
        r_cpu=self.w_cpu*math.log1p(cpu_excess/(s.cpu_ema+EPS))

        R=r_net * r_cpu
        changed, active=self._hysteresis(s, R)
        return R, changed, active


# =========================================================
# 6) CUSUM (change-point score) - CPU/NET separately + combined
#   S_t = max(0, S_{t-1} + (z_t - k))
#   z_t is (x - ema_mean)/(ema_mean+eps) so that the scale matches
# =========================================================
class RiskCUSUMMax(_BaseRisk):
    def __init__(
        self,
        cpu_gamma: float = 0.02,
        net_gamma: float = 0.02,
        net_min: float = 1024.0,
        k_cpu: float = 0.02,   # reference (sensitivity) - dimensionless
        k_net: float = 0.02,
        th_on=3.0, th_off=0.8, k_on=2, k_off=3,
    ):
        super().__init__(th_on=th_on, th_off=th_off, k_on=k_on, k_off=k_off)
        self.cpu_gamma=float(cpu_gamma); self.net_gamma=float(net_gamma)
        self.net_min=float(net_min)
        self.k_cpu=float(k_cpu); self.k_net=float(k_net)

    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s=self.state[pod]
        cpu=float(cpu_core); net=float(net_bps)

        # update means
        s.cpu_ema=ema(s.cpu_ema, cpu, self.cpu_gamma)
        s.net_ema=ema(s.net_ema, net, self.net_gamma)
        if s.cpu_ema is None: s.cpu_ema=cpu
        if s.net_ema is None: s.net_ema=net

        # normalized residuals (dimensionless)
        z_cpu=max(0.0, (cpu - s.cpu_ema) / (s.cpu_ema + EPS))
        z_net=0.0
        if s.net_ema >= self.net_min:
            z_net=max(0.0, (net - s.net_ema) / (s.net_ema + EPS))

        s.cusum_cpu=max(0.0, s.cusum_cpu + (z_cpu - self.k_cpu))
        s.cusum_net=max(0.0, s.cusum_net + (z_net - self.k_net))

        R=max(s.cusum_cpu, s.cusum_net)
        changed, active=self._hysteresis(s, R)
        return R, changed, active


# =========================================================
# 7) Token Bucket / Leaky Bucket burstiness score (NET)
#   - TokenBucket: tokens += rate*dt, tokens<=burst, consume=net*dt
#     if there are not enough tokens, the deficit (= excess) is the score
#   - LeakyBucket: backlog += net*dt - drain*dt; a backlog > 0 is the score
# =========================================================
class RiskTokenBucket(_BaseRisk):
    def __init__(
        self,
        rate_bps: float = 50_000.0,   # average allowed rate (bytes/sec)
        burst_bytes: float = 200_000.0,  # allowed burst size
        th_on=3.0, th_off=0.8, k_on=2, k_off=3,
    ):
        super().__init__(th_on=th_on, th_off=th_off, k_on=k_on, k_off=k_off)
        self.rate=float(rate_bps)
        self.burst=float(burst_bytes)

    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s=self.state[pod]
        net=float(net_bps)

        # dt
        if t is None or s.last_t is None:
            dt=1.0
        else:
            dt=max(1e-3, float(t) - float(s.last_t))
        s.last_t = float(t) if t is not None else s.last_t

        # refill
        s.tokens = min(self.burst, s.tokens + self.rate * dt)

        need = net * dt
        if s.tokens >= need:
            s.tokens -= need
            excess = 0.0
        else:
            excess = need - s.tokens
            s.tokens = 0.0

        # score: log(1+excessBytes)
        R = math.log1p(excess)
        changed, active=self._hysteresis(s, R)
        return R, changed, active

class RiskLeakyBucket(_BaseRisk):
    def __init__(
        self,
        drain_bps: float = 50_000.0,   # drain rate (allowed average)
        burst_bytes: float = 200_000.0, # buffer size (burst allowance)
        th_on=3.0, th_off=0.8, k_on=2, k_off=3,
    ):
        super().__init__(th_on=th_on, th_off=th_off, k_on=k_on, k_off=k_off)
        self.drain=float(drain_bps)
        self.burst=float(burst_bytes)

    def update(self, pod: str, cpu_core: float, net_bps: float, t: Optional[float] = None):
        s=self.state[pod]
        net=float(net_bps)

        # dt
        if t is None or s.last_t is None:
            dt=1.0
        else:
            dt=max(1e-3, float(t) - float(s.last_t))
        s.last_t = float(t) if t is not None else s.last_t

        # backlog evolves
        s.backlog = max(0.0, s.backlog + net*dt - self.drain*dt)
        # cap at burst (overflow == excess)
        excess = max(0.0, s.backlog - self.burst)
        if excess > 0.0:
            s.backlog = self.burst

        R = math.log1p(excess)
        changed, active=self._hysteresis(s, R)
        return R, changed, active


# =========================================================
# Factory
# =========================================================
def make_baseline(name: str, **kwargs):
    name = (name or "").lower().strip()
    table = {
        # 1) HPA ratio
        "hpa_cpu": lambda **kw: RiskHPARatio(use_cpu=True, use_net=False, **kw),
        "hpa_net": lambda **kw: RiskHPARatio(use_cpu=False, use_net=True, **kw),
        "hpa_max": lambda **kw: RiskHPARatio(use_cpu=True, use_net=True, combine="max", **kw),
        "hpa_sum": lambda **kw: RiskHPARatio(use_cpu=True, use_net=True, combine="sum", **kw),

        # 2) EWMA CPU-only
        "ewma_cpu": RiskCPUOnlyEWMA,

        # 3) net burst only
        "burst_net": RiskNetOnlyBurst,

        # 4) weighted sum
        "w_sum": RiskWeightedSum,

        # 5) OR/AND
        "or_max": RiskLogicORMax,
        "and_min": RiskLogicANDMin,
        "and_prod": RiskLogicANDProduct,

        # 6) CUSUM
        "cusum_max": RiskCUSUMMax,

        # 7) token/leaky bucket
        "token_bucket": RiskTokenBucket,
        "leaky_bucket": RiskLeakyBucket,
    }
    if name not in table:
        raise ValueError(f"Unknown baseline '{name}'. choose one of: {sorted(table.keys())}")

    ctor = table[name]
    return ctor(**kwargs) if callable(ctor) and not isinstance(ctor, type) else ctor(**kwargs)
