"""E9: real drift.  Verdicts of every version of public configuration files
along their git histories; resynchronization policies are replayed offline."""
from common import PROPERTIES, dump, load, materialize
from fidelity.config import Config, D
from fidelity.harness import run_jobs

RW = load("rw-corpus.json")


def job(ev, svc, chain):
    out = []
    for v in chain:
        if v is None:
            out.append(None)
            continue
        cfg = Config(svc, tuple(D(s, k, val) for s, k, val in v["directives"]))
        r = ev.raw(materialize(cfg, "vendor"))
        out.append({p: r[p] for p in PROPERTIES[svc]} | {"_wire": r["_wire"][:120]})
    return out


hist = [h for h in RW["histories"] if sum(1 for v in h["versions"] if v) >= 2]
res = run_jobs([(job, (h["service"], h["versions"])) for h in hist], label="rw-hist")
dump("e9-realdrift.json", [{"file": h["file"], "service": h["service"], "versions": h["versions"], "verdicts": r}
                           for h, r in zip(hist, res)])
