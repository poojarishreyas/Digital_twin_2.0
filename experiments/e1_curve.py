"""E1: fidelity curve.  Random directive subsets of size round(p*n), two base
profiles, verdict agreement with the source."""
import random
from common import PROPERTIES, dump, load, load_corpus, materialize
from fidelity.harness import run_jobs

LEVELS = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
SAMPLES = 8
truth = {(r["cid"], r["prop"]): r["verdict"] for r in load("e0-truth.json")}


def job(ev, cfg, base, keep):
    r = ev.raw(materialize(cfg.subset(keep), base))
    return {p: r[p] for p in PROPERTIES[cfg.service]}


jobs, meta = [], []
for c in load_corpus():
    rnd = random.Random(hash(c.cid) % 10**9 if False else int.from_bytes(c.cid.encode(), "big") % 10**9)
    n = len(c)
    for base in ("vendor", "platform"):
        for p in LEVELS:
            k = round(p * n)
            seen = set()
            for s in range(SAMPLES if 0 < k < n else 1):
                keep = tuple(sorted(rnd.sample(range(n), k)))
                jobs.append((job, (c, base, keep)))
                meta.append((c.cid, c.service, base, p, k, n, s))
res = run_jobs(jobs, label="curve")
rows = []
for (cid, svc, base, p, k, n, s), r in zip(meta, res):
    for prop, v in r.items():
        rows.append(dict(cid=cid, service=svc, base=base, level=p, k=k, n=n, sample=s, prop=prop, verdict=v,
                         truth=truth[(cid, prop)], agree=(v == truth[(cid, prop)])))
dump("e1-curve.json", rows)
