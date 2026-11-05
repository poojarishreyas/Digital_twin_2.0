"""E2: fidelity cores (ddmin) under both base profiles, plus single-directive
removal sensitivity under the vendor profile."""
from common import PROPERTIES, dump, load, load_corpus, materialize
from fidelity.core import fidelity_core
from fidelity.harness import run_jobs

truth = {(r["cid"], r["prop"]): r["verdict"] for r in load("e0-truth.json")}


def job(ev, cfg):
    out = {"cid": cfg.cid, "service": cfg.service, "n": len(cfg), "cores": {}, "removal": {}}
    for prop in PROPERTIES[cfg.service]:
        t = truth[(cfg.cid, prop)]
        for base in ("vendor", "platform"):
            before = ev.runs
            r = fidelity_core(ev, cfg, base, prop, t)
            r["server_runs"] = ev.runs - before
            out["cores"][f"{prop}|{base}"] = r
        flips = []
        for i in range(len(cfg)):
            keep = [j for j in range(len(cfg)) if j != i]
            v = ev.verdict(materialize(cfg.subset(keep), "vendor"), prop)
            flips.append(v != t)
        out["removal"][prop] = flips
    out["directives"] = [(d.section, d.key, d.value, d.cls) for d in cfg.directives]
    return out


cfgs = load_corpus()
res = run_jobs([(job, (c,)) for c in cfgs], label="cores")
dump("e2-cores.json", res)
