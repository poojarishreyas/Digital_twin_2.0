"""E11: the declarative spec engine reproduces the hand-written adapters.
Every synthetic corpus configuration plus 240 drift versions is evaluated with
specs/<service>.yaml and compared with the native-adapter verdict."""
import random
from common import PROPERTIES, dump, load, load_corpus
from fidelity.config import Config, D
from fidelity.harness import load_cache, run_jobs
from fidelity.spec import materialize
from fidelity.spec_harness import SpecEv, spec_of


def job(ev, cfg):
    sev = SpecEv(ev, cfg.service)
    r = sev.raw(materialize(spec_of(cfg.service), cfg, "vendor"))
    return {p: r[p] for p in PROPERTIES[cfg.service]}


cfgs = load_corpus()
rnd = random.Random(5)
drift = []
for t in rnd.sample(load("e3-traces.json"), 120):
    for v in rnd.sample(t["versions"][1:], 2):
        drift.append(Config(t["service"], tuple(D(s, k, val) for s, k, val in v["config"]), t["cid"] + "-d"))
allc = cfgs + drift
res = run_jobs([(job, (c,)) for c in allc], label="equiv")
cache = load_cache()
rows = []
for c, r in zip(allc, res):
    native = cache[c.canonical()]
    for p in PROPERTIES[c.service]:
        rows.append({"cid": c.cid, "service": c.service, "prop": p, "native": native[p], "spec": r[p], "agree": native[p] == r[p]})
dump("e11-equivalence.json", rows)
print(len(rows), sum(r["agree"] for r in rows))
