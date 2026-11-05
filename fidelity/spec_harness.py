"""Spec-driven evaluation, corpus generation and drift for any declared service.

Everything here mirrors the hand-written path (harness.py, corpus.py), but is
parameterized only by a spec, so new services need no code.
"""
from __future__ import annotations

import random

from .config import Config, D
from .core import fidelity_core
from .spec import SpecService, load_spec, materialize, properties

_SVC: dict = {}
_SPECS: dict = {}


def spec_of(name: str) -> dict:
    if name not in _SPECS:
        _SPECS[name] = load_spec(name)
    return _SPECS[name]


class SpecEv:
    """Evaluator with the same interface as harness.Evaluator (raw/verdict/runs),
    caching through the pool's shared cache under a spec-specific key."""

    def __init__(self, ev, name: str, image: str | None = None):
        self.ev, self.spec, self.image = ev, spec_of(name), image
        key = (name, image, ev.slot)
        if key not in _SVC:
            _SVC[key] = SpecService(self.spec, ev.slot, image)
        self.svc = _SVC[key]
        self.runs = 0

    def key(self, twin: Config) -> str:
        return f"spec|{self.spec['name']}|{self.image or self.spec['runtime'].get('image', 'native')}|{twin.canonical()}"

    def raw(self, twin: Config) -> dict:
        import time
        k = self.key(twin)
        if k in self.ev.cache:
            return self.ev.cache[k]
        props = properties(self.spec)
        t = time.monotonic()
        out = self.svc.run(twin)
        if any(out.get(p) == "inconclusive" for p in props):
            out = self.svc.run(twin)
        self.runs += 1
        self.ev.runs += 1
        clean = {p: ("error" if out.get("_start") != "ok" else out.get(p)) for p in props}
        clean["_wire"] = str(out.get("_wire", out.get("_detail", "")))[:300]
        self.ev.cache[k] = clean
        self.ev.new[k] = (clean, time.monotonic() - t)
        return clean

    def verdict(self, twin: Config, prop: str):
        return self.raw(twin)[prop]


def core_and_pivots(sev: SpecEv, cfg: Config, prop: str, truth) -> dict:
    """Algorithm 1 for any spec (bases V and P, plus single-removal pivots)."""
    spec = sev.spec
    out = {}
    for base in ("vendor", "platform"):
        out[base] = fidelity_core(sev, cfg, base, prop, truth, mat=lambda c, b: materialize(spec, c, b))
    flips = []
    for i in range(len(cfg)):
        keep = [j for j in range(len(cfg)) if j != i]
        flips.append(sev.verdict(materialize(spec, cfg.subset(keep), "vendor"), prop) != truth)
    out["pivots"] = [i for i, f in enumerate(flips) if f]
    return out


# ------------------------------------------------------------------ corpus and drift
def generate(spec: dict, seed: int, cid: str) -> Config:
    """With probability 3/4 a declared posture (deployment pattern) from the spec,
    otherwise 1-3 random security directives; plus 3-8 operational directives,
    shuffled.  Specs without postures use the random branch only."""
    r = random.Random(seed)
    cat = spec["catalog"]
    array = set(spec.get("array_keys", []))
    sec = [e for e in cat if e["class"] == "security"]
    ops = [e for e in cat if e["class"] == "operational"]
    postures = spec.get("postures")
    ds, used = [], set()
    if postures and r.random() < 0.75:
        # a declared deployment pattern, optionally plus one more security directive
        for k, v in r.choice(postures):
            e = next(x for x in cat if x["key"] == k)
            ds.append((e.get("section", ""), k, str(v), "security"))
            used.add(k)
        chosen = (r.sample(sec, 1) if r.random() < 0.4 else []) + r.sample(ops, r.randint(3, min(8, len(ops))))
    else:
        chosen = r.sample(sec, r.randint(1, min(3, len(sec)))) + r.sample(ops, r.randint(3, min(8, len(ops))))
    for e in chosen:
        s = e.get("section", "")
        if e["key"] in used and e["key"] not in array:
            continue
        used.add(e["key"])
        ds.append((s, e["key"], str(r.choice(e["values"])), e["class"]))
    r.shuffle(ds)
    return Config(spec["name"], tuple(D(s, k, v, i + 1, c) for i, (s, k, v, c) in enumerate(ds)), cid)


def edit(spec: dict, cfg: Config, r: random.Random, q: float, next_uid: int):
    cat = spec["catalog"]
    array = set(spec.get("array_keys", []))
    ds = list(cfg.directives)
    want = "security" if r.random() < q else "operational"
    for _ in range(50):
        kind = r.choice(["modify", "modify", "modify", "add", "delete", "move"])
        if kind != "add":
            cand = [i for i, d in enumerate(ds) if d.cls == want]
            if not cand:
                continue
            i = r.choice(cand)
            d = ds[i]
            if kind == "modify":
                e = next((e for e in cat if e["key"] == d.key), None)
                vals = [str(v) for v in (e["values"] if e else []) if str(v) != d.value]
                if not vals:
                    continue
                ds[i] = D(d.section, d.key, r.choice(vals), d.uid, d.cls)
                touched = ds[i]
            elif kind == "delete":
                if len(ds) <= 2:
                    continue
                touched = ds.pop(i)
            else:
                if len(ds) < 3:
                    continue
                touched = ds.pop(i)
                ds.insert(r.randint(0, len(ds)), touched)
        else:
            e = r.choice([e for e in cat if e["class"] == want])
            if e["key"] not in array and any(x.key == e["key"] for x in ds):
                continue
            touched = D(e.get("section", ""), e["key"], str(r.choice(e["values"])), next_uid, e["class"])
            ds.insert(r.randint(0, len(ds)), touched)
        return Config(cfg.service, tuple(ds), cfg.cid), {"kind": kind, "keys": [[touched.section, touched.key]], "cls": want}
    return cfg, {"kind": "noop", "keys": [], "cls": want}
