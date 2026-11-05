"""E7: core multiplicity.  Exhaustively test every directive subset of size
<= 2 (cores found by ddmin never exceeded 2) to obtain all *minimum* cores,
compare their size with the ddmin core, and count how many exist."""
from itertools import combinations
from common import PROPERTIES, dump, load, load_corpus, materialize
from fidelity.harness import run_jobs

truth = {(r["cid"], r["prop"]): r["verdict"] for r in load("e0-truth.json")}
ddcores = {r["cid"]: r for r in load("e2-cores.json")}


def job(ev, cfg):
    out = {}
    n = len(cfg)
    for prop in PROPERTIES[cfg.service]:
        t = truth[(cfg.cid, prop)]
        for base in ("vendor", "platform"):
            minimum = None
            for size in (0, 1, 2):
                hits = [list(c) for c in combinations(range(n), size)
                        if ev.verdict(materialize(cfg.subset(c), base), prop) == t]
                if hits:
                    minimum = hits
                    break
            dd = ddcores[cfg.cid]["cores"][f"{prop}|{base}"]["core"]
            out[f"{prop}|{base}"] = {"minimum": minimum, "ddmin": dd}
    return {"cid": cfg.cid, "service": cfg.service, "n": n, "res": out}


res = run_jobs([(job, (c,)) for c in load_corpus()], label="multiplicity")
dump("e7-multiplicity.json", res)
