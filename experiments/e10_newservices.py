"""E10: three services added only through specs (Mosquitto, MongoDB, MariaDB).
Same pipeline as the four hand-written families: source verdicts, cores and
pivots (bases V and P), fidelity curve, guard learning on a training half,
selective synchronization and drift with re-emulation policies."""
import random
import sys
from common import dump
from fidelity.harness import run_jobs
from fidelity.spec import materialize, properties
from fidelity.spec_harness import SpecEv, core_and_pivots, edit, generate, spec_of

SERVICES = sys.argv[1:] or ["mosquitto", "mongodb", "mariadb"]
CAND, KEEP, T, Q = 70, 40, 20, 0.3
LEVELS = [0.0, 0.25, 0.5, 0.75, 1.0]


def job_truth(ev, name, cfg):
    sev = SpecEv(ev, name)
    r = sev.raw(materialize(sev.spec, cfg, "vendor"))
    return {p: r[p] for p in properties(sev.spec)} | {"_wire": r["_wire"][:160]}


def job_full(ev, name, cfg, truth, seed):
    sev = SpecEv(ev, name)
    spec = sev.spec
    out = {"cid": cfg.cid, "n": len(cfg), "directives": [(d.section, d.key, d.value, d.cls) for d in cfg.directives],
           "props": {}}
    rnd = random.Random(seed)
    for p in properties(spec):
        cp = core_and_pivots(sev, cfg, p, truth[p])
        curve = []
        for base in ("vendor", "platform"):
            for lv in LEVELS:
                k = round(lv * len(cfg))
                for _ in range(3 if 0 < k < len(cfg) else 1):
                    keep = tuple(sorted(rnd.sample(range(len(cfg)), k)))
                    curve.append({"base": base, "level": lv,
                                  "agree": sev.verdict(materialize(spec, cfg.subset(keep), base), p) == truth[p]})
        out["props"][p] = {"truth": truth[p], "core_V": cp["vendor"], "core_P": cp["platform"], "pivots": cp["pivots"], "curve": curve}
    return out


def job_gsync(ev, name, cfg, truth, guards):
    sev = SpecEv(ev, name)
    out = {}
    for p in properties(sev.spec):
        for g, keys in guards[p].items():
            keep = [i for i, d in enumerate(cfg.directives) if d.key in keys]
            for base in ("vendor", "platform"):
                out[f"{p}|{g}|{base}"] = {"agree": sev.verdict(materialize(sev.spec, cfg.subset(keep), base), p) == truth[p],
                                          "kept": len(keep), "n": len(cfg)}
    return out


def job_drift(ev, name, cfg, seed):
    sev = SpecEv(ev, name)
    r = random.Random(seed)
    cur, uid, versions = cfg, 1000, []
    v0 = sev.raw(materialize(sev.spec, cur, "vendor"))
    versions.append({"edit": None, "verdict": {p: v0[p] for p in properties(sev.spec)}})
    for _ in range(T):
        new, rec = edit(sev.spec, cur, r, Q, uid)
        uid += 1
        o = sev.raw(materialize(sev.spec, new, "vendor"))
        verdict = {p: o[p] for p in properties(sev.spec)}
        if any(v not in (True, False) for v in verdict.values()):
            rec = {"kind": "rejected_by_server", "keys": rec["keys"], "cls": rec["cls"]}
            o = sev.raw(materialize(sev.spec, cur, "vendor"))
            verdict = {p: o[p] for p in properties(sev.spec)}
            new = cur
        versions.append({"edit": rec, "verdict": verdict})
        cur = new
    return versions


for name in SERVICES:
    spec = spec_of(name)
    cands = [generate(spec, 9000 + i, f"{name[:2]}{i:03d}") for i in range(CAND)]
    truths = run_jobs([(job_truth, (name, c)) for c in cands], label=f"{name}-truth")
    acc = [(c, t) for c, t in zip(cands, truths) if all(t[p] in (True, False) for p in properties(spec))][:KEEP]
    rejected = [{"cid": c.cid, "wire": t["_wire"]} for c, t in zip(cands, truths)
                if not all(t[p] in (True, False) for p in properties(spec))]
    full = run_jobs([(job_full, (name, c, t, 17 * i)) for i, (c, t) in enumerate(acc)], label=f"{name}-full")
    train = [f for i, f in enumerate(full) if i % 2 == 0]
    guards = {}
    for p in properties(spec):
        core_keys, piv_keys = set(), set()
        for f in train:
            ds = f["directives"]
            for b in ("core_V", "core_P"):
                core_keys |= {ds[i][1] for i in (f["props"][p][b]["core"] or [])}
            piv_keys |= {ds[i][1] for i in f["props"][p]["pivots"]}
        guards[p] = {"core": sorted(core_keys), "union": sorted(core_keys | piv_keys),
                     "expert": sorted({e["key"] for e in spec["catalog"] if e["class"] == "security"})}
    test = [(c, t) for i, (c, t) in enumerate(acc) if i % 2 == 1]
    gs = run_jobs([(job_gsync, (name, c, t, guards)) for c, t in test], label=f"{name}-gsync")
    drift = run_jobs([(job_drift, (name, c, 4242 + i)) for i, (c, _) in enumerate(test)], label=f"{name}-drift")
    dump(f"e10-{name}.json", {"candidates": len(cands), "accepted": len(acc), "rejected": rejected,
                               "truth": [{"cid": c.cid, **{p: t[p] for p in properties(spec)}} for c, t in acc],
                               "full": full, "guards": guards, "gsync": gs, "drift": drift})
