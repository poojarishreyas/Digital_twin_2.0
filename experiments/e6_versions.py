"""E6: version fidelity.  The same configurations evaluated on pinned server
versions (container images on the host network): source verdicts, start
failures, and vendor-base fidelity cores per version."""
import random
from common import PROPERTIES, dump, load, load_corpus, materialize
from fidelity.config import Config, D
from fidelity.core import fidelity_core
from fidelity.harness import run_jobs
from fidelity.services.versioned import IMAGES, make

_SVC = {}


class VEv:
    """Minimal evaluator over one versioned service instance (same API as harness.Evaluator)."""
    def __init__(self, svc):
        self.svc, self.cache, self.runs = svc, {}, 0

    def raw(self, twin):
        k = twin.canonical()
        if k not in self.cache:
            out = self.svc.run(twin)
            self.runs += 1
            props = PROPERTIES[twin.service]
            if any(out.get(p) == "inconclusive" for p in props):
                out = self.svc.run(twin)
            self.cache[k] = {**{p: ("error" if out.get("_start") != "ok" else out.get(p)) for p in props},
                             "_wire": str(out.get("_wire", out.get("_detail", "")))[:200]}
        return self.cache[k]

    def verdict(self, twin, prop):
        return self.raw(twin)[prop]


def job(ev, svc, image, cfg, with_core):
    key = (svc, image, ev.slot)
    if key not in _SVC:
        _SVC[key] = VEv(make(svc, image, ev.slot))
    v = _SVC[key]
    v.cache = {}
    src = v.raw(materialize(cfg, "vendor"))
    out = {"cid": cfg.cid, "service": svc, "image": image, "verdict": {p: src[p] for p in PROPERTIES[svc]}, "wire": src["_wire"],
           "config": [(d.section, d.key, d.value) for d in cfg.directives], "cores": {}}
    if with_core:
        for p in PROPERTIES[svc]:
            if src[p] in (True, False):
                r = fidelity_core(v, cfg, "vendor", p, src[p])
                out["cores"][p] = None if r["core"] is None else [cfg.directives[i].key for i in r["core"]]
    return out


cfgs = load_corpus()
traces = load("e3-traces.json")
extra = []
rnd = random.Random(11)
for svc in IMAGES:
    pool = [(t["cid"], v) for t in traces if t["service"] == svc for v in t["versions"][1:]]
    for i, (cid, v) in enumerate(rnd.sample(pool, 60)):
        extra.append(Config(svc, tuple(D(s, k, val) for s, k, val in v["config"]), f"{cid}-d{i}"))
jobs = [(job, (c.service, img, c, True)) for c in cfgs for img in IMAGES[c.service]]
jobs += [(job, (c.service, img, c, False)) for c in extra for img in IMAGES[c.service]]
res = run_jobs(jobs, label="versions", persist=False)
dump("e6-versions.json", res)
