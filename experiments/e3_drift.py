"""E3: configuration drift and resynchronization policies.

For each held-out configuration we generate an edit trace, obtain the source
verdict of every version on the real server, and replay re-emulation policies
offline against those verdicts.  Guard sets are learned on the training split
only (from e2 cores / removal flips); the expert set uses the human class label.
Also measures guard-set selective synchronization: a twin that receives only
directives whose key is in G.
"""
import random
from collections import defaultdict
from common import PROPERTIES, dump, load, load_corpus, materialize, split
from fidelity.corpus import CATALOG, edit
from fidelity.harness import run_jobs

T = 40
MIXES = (0.1, 0.3, 0.5)
cfgs = load_corpus()
train, test = split(cfgs)
cores = {r["cid"]: r for r in load("e2-cores.json")}

# ---- guard sets from the training split
G = defaultdict(lambda: defaultdict(set))
for c in train:
    r = cores[c.cid]
    for prop in PROPERTIES[c.service]:
        for base in ("vendor", "platform"):
            core = r["cores"][f"{prop}|{base}"]["core"]
            for i in core or []:
                G[prop]["core"].add(c.directives[i].key)
        for i, f in enumerate(r["removal"][prop]):
            if f:
                G[prop]["removal"].add(c.directives[i].key)
for prop_list, svc in ((PROPERTIES[s], s) for s in PROPERTIES):
    for prop in prop_list:
        G[prop]["expert"] = {e.key for e in CATALOG[svc] if e.cls == "security"}
        G[prop]["all"] = {e.key for e in CATALOG[svc]}
        G[prop]["union"] = G[prop]["core"] | G[prop]["removal"]
guards = {p: {k: sorted(v) for k, v in d.items()} for p, d in G.items()}
dump("e3-guards.json", guards)


def job_trace(ev, cfg, q, seed):
    r = random.Random(seed)
    cur, uid = cfg, 1000
    versions = []
    v0 = ev.raw(materialize(cur, "vendor"))
    versions.append({"edit": None, "verdict": {p: v0[p] for p in PROPERTIES[cfg.service]}})
    for t in range(T):
        new, rec = edit(cur, r, q, uid)
        uid += 1
        out = ev.raw(materialize(new, "vendor"))
        verdict = {p: out[p] for p in PROPERTIES[cfg.service]}
        if any(v not in (True, False) for v in verdict.values()):
            # an edit the real server refuses would be rolled back by the operator
            rec = {"kind": "rejected_by_server", "keys": rec["keys"], "uids": [], "cls": rec["cls"]}
            out = ev.raw(materialize(cur, "vendor"))
            verdict = {p: out[p] for p in PROPERTIES[cfg.service]}
            new = cur
        rec["keys"] = [list(k) for k in rec["keys"]]
        versions.append({"edit": rec, "verdict": verdict,
                         "config": [(d.section, d.key, d.value) for d in new.directives]})
        cur = new
    return {"cid": cfg.cid, "service": cfg.service, "q": q, "versions": versions}


jobs = [(job_trace, (c, q, 7919 * i + int(q * 100))) for q in MIXES for i, c in enumerate(test)]
traces = run_jobs(jobs, label="drift")
dump("e3-traces.json", traces)

# ---- selective synchronization with guard sets (held-out configs + every 8th drift version)
from fidelity.config import Config, D


def job_gsync(ev, svc, directives, base, keyset, props):
    cfg = Config(svc, tuple(D(s, k, v) for s, k, v in directives))
    keep = [i for i, d in enumerate(cfg.directives) if d.key in keyset]
    r = ev.raw(materialize(cfg.subset(keep), base))
    return {"kept": len(keep), "n": len(cfg), "verdict": {p: r[p] for p in props}}


gjobs, gmeta = [], []
for tr in traces:
    if tr["q"] != 0.3:
        continue
    svc = tr["service"]
    c0 = next(c for c in test if c.cid == tr["cid"])
    samples = [(0, [(d.section, d.key, d.value) for d in c0.directives], tr["versions"][0]["verdict"])]
    samples += [(t, tr["versions"][t]["config"], tr["versions"][t]["verdict"]) for t in range(8, T + 1, 8)]
    for t, directives, truth in samples:
        for prop in PROPERTIES[svc]:
            for gname in ("core", "removal", "union", "expert"):
                for base in ("vendor", "platform"):
                    gjobs.append((job_gsync, (svc, directives, base, set(guards[prop][gname]), [prop])))
                    gmeta.append(dict(cid=tr["cid"], service=svc, t=t, prop=prop, guard=gname, base=base, truth=truth[prop]))
gres = run_jobs(gjobs, label="gsync")
rows = []
for m, r in zip(gmeta, gres):
    rows.append({**m, "kept": r["kept"], "n": r["n"], "verdict": r["verdict"][m["prop"]],
                 "agree": r["verdict"][m["prop"]] == m["truth"]})
dump("e3-gsync.json", rows)
