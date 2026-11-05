"""E13: public configurations for the spec-only services (Mosquitto, MongoDB,
MariaDB): admission, verdicts, cores and pivots, and transfer of the guard sets
learned in E10 from synthetic data.  Raw files stay outside the repository;
only normalized, redacted directives with content hashes are stored."""
import hashlib
import json
import os
import random
import re
from pathlib import Path
from common import dump, load
from fidelity import formats, redact
from fidelity.config import Config, D
from fidelity.harness import run_jobs
from fidelity.spec import materialize, properties
from fidelity.spec_harness import SpecEv, core_and_pivots, spec_of

RAW = Path(os.environ.get("RW_RAW_NEW", "/tmp/fidelity-rw-raw-new"))
TEMPLATE = re.compile(r"\{\{|\{%|<%|\$\{")
SAMPLE = 60


def collect(name):
    spec = spec_of(name)
    cand = json.loads((RAW / "candidates.json").read_text())[name]
    known = {e["key"].lower() for e in spec["catalog"]}
    seen, out, stats = set(), [], {"files": 0, "not_config": 0, "no_known_key": 0, "duplicate": 0}
    for it in cand:
        f = RAW / "blobs" / f"{it['sha']}.txt"
        if not f.exists():
            continue
        stats["files"] += 1
        text = f.read_text(errors="replace")
        if TEMPLATE.search(text):
            stats["not_config"] += 1
            continue
        ds, _, _ = formats.parse(spec, text)
        ds = redact.normalize(spec, ds)
        if not ds or not any(d[1].lower() in known for d in ds):
            stats["no_known_key"] += 1
            continue
        h = hashlib.sha256(json.dumps([name, ds]).encode()).hexdigest()[:10]
        if h in seen:
            stats["duplicate"] += 1
            continue
        seen.add(h)
        out.append(Config(name, tuple(D(s, k, v, i + 1) for i, (s, k, v) in enumerate(ds)), f"{name[:2]}-{h}"))
    stats["kept"] = len(out)
    return out, stats


def job_truth(ev, name, cfg):
    sev = SpecEv(ev, name)
    r = sev.raw(materialize(sev.spec, cfg, "vendor"))
    return {p: r[p] for p in properties(sev.spec)} | {"_wire": r["_wire"][:200]}


def job_full(ev, name, cfg, truth, guards):
    sev = SpecEv(ev, name)
    out = {"cid": cfg.cid, "n": len(cfg), "props": {}}
    for p in properties(sev.spec):
        cp = core_and_pivots(sev, cfg, p, truth[p])
        keys = [d.key for d in cfg.directives]
        gs = {}
        for g, gk in guards[p].items():
            keep = [i for i, d in enumerate(cfg.directives) if d.key in gk]
            gs[g] = {"agree": sev.verdict(materialize(sev.spec, cfg.subset(keep), "vendor"), p) == truth[p],
                     "kept": len(keep)}
        out["props"][p] = {"truth": truth[p], "core_V": cp["vendor"]["core"], "core_P": cp["platform"]["core"],
                           "core_keys": [keys[i] for i in (cp["vendor"]["core"] or [])],
                           "pivot_keys": [keys[i] for i in cp["pivots"]], "pivots": cp["pivots"], "gsync": gs}
    return out


result = {}
for name in ("mosquitto", "mongodb", "mariadb"):
    cfgs, stats = collect(name)
    truths = run_jobs([(job_truth, (name, c)) for c in cfgs], label=f"rw-{name}-truth")
    props = properties(spec_of(name))
    acc = [(c, t) for c, t in zip(cfgs, truths) if all(t[p] in (True, False) for p in props)]
    rej = [t["_wire"] for c, t in zip(cfgs, truths) if not all(t[p] in (True, False) for p in props)]
    guards = load(f"e10-{name}.json")["guards"]
    sample = random.Random(7).sample(acc, min(SAMPLE, len(acc)))
    full = run_jobs([(job_full, (name, c, t, guards)) for c, t in sample], label=f"rw-{name}-full")
    result[name] = {"stats": stats, "accepted": len(acc), "rejected": len(rej), "rejected_wire": rej,
                    "exposed": sum(1 for _, t in acc if any(t[p] is True for p in props)),
                    "n": [len(c) for c, _ in acc], "full": full,
                    "corpus": [{"cid": c.cid, "directives": [[d.section, d.key, d.value] for d in c.directives]} for c, _ in acc]}
dump("e13-realworld-new.json", result)
