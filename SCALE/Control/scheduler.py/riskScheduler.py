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
    net_ema: Optional[float] = None
    cpu_ema: Optional[float] = None

class RiskScheduler:
    def __init__(
        self,
        # EMA
        net_gamma: float = 0.02,      
        cpu_gamma: float = 0.02,

        net_min: float = 1024.0,      
        b0: float = 1.0,              
        b1: float = 2.0,              

        cpu_margin: float = 0.25,     

        lam: float = 2.0,
        th_on: float = 2.0,
        th_off: float = 0.8,
        k_on: int = 2,
        k_off: int = 3,

        freeze_baseline_when_bursty: bool = True,
    ):
        self.net_gamma = float(net_gamma)
        self.cpu_gamma = float(cpu_gamma)

        self.net_min = float(net_min)
        self.b0 = float(b0)
        self.b1 = float(b1)
        if self.b1 <= self.b0:
            self.b1 = self.b0 + 1e-3

        self.cpu_margin = float(cpu_margin)

        self.lam = float(lam)
        self.th_on = float(th_on)
        self.th_off = float(th_off)
        self.k_on = int(k_on)
        self.k_off = int(k_off)

        self.freeze_baseline_when_bursty = bool(freeze_baseline_when_bursty)

        self.state: DefaultDict[str, PodState] = defaultdict(PodState)

    def _ema(self, old: Optional[float], x: float, g: float) -> float:
        return x if old is None else (1.0 - g) * old + g * x

    def _net_burst(self, net: float, net_ema: Optional[float]) -> float:
        if net_ema is None or net_ema < self.net_min:
            return 0.0
        return max(0.0, (net - net_ema) / (net_ema + EPS))

    def _gate(self, b: float) -> float:
        return clip((b - self.b0) / (self.b1 - self.b0), 0.0, 1.0)

    def update(self, pod: str, cpu_core: float, net_bps: float) -> Tuple[float, bool, bool]:
        s = self.state[pod]
        cpu = float(cpu_core)
        net = float(net_bps)

        if net < self.net_min:
            s.cpu_ema = self._ema(s.cpu_ema, cpu, self.cpu_gamma)
            R = 0.0
            if R < self.th_off:
                s.off_cnt += 1
                s.on_cnt = 0
            else:
                s.on_cnt = s.off_cnt = 0
            changed = False
            if s.active and (s.off_cnt >= self.k_off):
                s.active = False
                changed = True
            return R, changed, s.active

        b = self._net_burst(net, s.net_ema)
        g = self._gate(b)

        if not (self.freeze_baseline_when_bursty and g > 0.0):
            s.net_ema = self._ema(s.net_ema, net, self.net_gamma)
            s.cpu_ema = self._ema(s.cpu_ema, cpu, self.cpu_gamma)

        if s.net_ema is None:
            s.net_ema = net
        if s.cpu_ema is None:
            s.cpu_ema = cpu

        b = self._net_burst(net, s.net_ema)
        g = self._gate(b)

        r_net = math.log1p(b)

        cpu_allow = s.cpu_ema * (1.0 + self.cpu_margin)
        cpu_excess = max(0.0, cpu - cpu_allow)
        r_cpu = math.log1p(cpu_excess / (s.cpu_ema + EPS))

        R = self.lam * r_net + g * r_cpu

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

        return R, changed, s.active
