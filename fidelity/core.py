"""Fidelity cores via delta debugging.

Given a source configuration C, a base profile B and a property phi, the
*fidelity core* is a subset K of C's directives such that the twin built from
K (plus B's fill-ins) returns the same phi-verdict as the full source, and no
single directive can be dropped from K without changing that verdict
(1-minimality, Zeller and Hildebrandt's ddmin).  Cores are relative to B and
need not be unique; we report the one ddmin finds from a fixed order.
"""
from __future__ import annotations

from .config import Config, materialize


def ddmin(ok, items: list[int]) -> list[int]:
    c = list(items)
    n = 2
    while len(c) >= 2:
        size = len(c)
        chunks = [c[i * size // n:(i + 1) * size // n] for i in range(n)]
        chunks = [ch for ch in chunks if ch]
        reduced = False
        for ch in chunks:
            if ok(ch):
                c, n, reduced = ch, 2, True
                break
        if not reduced:
            for ch in chunks:
                comp = [x for x in c if x not in ch]
                if ok(comp):
                    c, n, reduced = comp, max(n - 1, 2), True
                    break
        if not reduced:
            if n >= len(c):
                break
            n = min(len(c), 2 * n)
    return c


def fidelity_core(ev, cfg: Config, base: str, prop: str, target) -> dict:
    tests = {"n": 0}
    memo: dict[tuple, bool] = {}

    def ok(idx):
        key = tuple(sorted(idx))
        if key not in memo:
            tests["n"] += 1
            memo[key] = ev.verdict(materialize(cfg.subset(key), base), prop) == target
        return memo[key]

    full = list(range(len(cfg)))
    if not ok(full):
        return {"core": None, "tests": tests["n"], "reason": "base_conflict"}
    if ok([]):
        return {"core": [], "tests": tests["n"]}
    if len(full) == 1:
        return {"core": full, "tests": tests["n"]}
    core = ddmin(ok, full)
    if len(core) == 1 and ok([]):
        core = []
    return {"core": core, "tests": tests["n"]}
