"""E8: real-world validation on public configuration files (see realworld/).

1. acceptance: does the pinned server (native Redis 7.0 / PostgreSQL 16 /
   OpenSSH 9.6) start with the configuration and answer conclusively?
2. fidelity cores (both bases) and pivots on a seeded sample;
3. fidelity curve on the same sample;
4. transfer: guard sets learned on the *synthetic* training split, used for
   selective synchronization of real configurations;
5. careful static analyzer on real configurations;
(real drift along git histories is in e9_realdrift.py).
"""
import random
from common import PROPERTIES, dump, load, materialize
from fidelity.config import Config, D
from fidelity.core import fidelity_core
from fidelity.harness import run_jobs
from fidelity.static import careful

RW = load("rw-corpus.json")
SAMPLE = 150
LEVELS = [0.0, 0.25, 0.5, 0.75, 0.9, 1.0]
SSH_CANON = {k.lower(): k for k in ("PasswordAuthentication", "AuthenticationMethods", "AllowUsers", "DenyUsers",
                                    "AllowGroups", "DenyGroups", "PermitRootLogin", "PubkeyAuthentication",
                                    "PermitEmptyPasswords", "MaxAuthTries")}


def to_cfg(svc, ds, cid=""):
    return Config(svc, tuple(D(s, k, v, i + 1) for i, (s, k, v) in enumerate(ds)), cid)


def job_truth(ev, cfg):
    r = ev.raw(materialize(cfg, "vendor"))
    return {p: r[p] for p in PROPERTIES[cfg.service]} | {"_wire": r["_wire"][:200]}


def keynorm(svc, k):
    return k.lower() if svc == "openssh" else k


guards = load("e3-guards.json")


def job_full(ev, cfg, truth, seed):
    out = {"cid": cfg.cid, "service": cfg.service, "n": len(cfg), "cores": {}, "pivots": {}, "curve": [], "gsync": []}
    rnd = random.Random(seed)
    n = len(cfg)
    for p in PROPERTIES[cfg.service]:
        t = truth[p]
        for base in ("vendor", "platform"):
            r = fidelity_core(ev, cfg, base, p, t)
            out["cores"][f"{p}|{base}"] = {"core": r["core"], "tests": r["tests"],
                                          "keys": None if r["core"] is None else [cfg.directives[i].key for i in r["core"]]}
        flips = []
        for i in range(n):
            keep = [j for j in range(n) if j != i]
            flips.append(ev.verdict(materialize(cfg.subset(keep), "vendor"), p) != t)
        out["pivots"][p] = [cfg.directives[i].key for i, f in enumerate(flips) if f]
        out["pivot_idx"] = out.get("pivot_idx", {}) | {p: [i for i, f in enumerate(flips) if f]}
        for base in ("vendor", "platform"):
            for lv in LEVELS:
                k = round(lv * n)
                for s in range(4 if 0 < k < n else 1):
                    keep = tuple(sorted(rnd.sample(range(n), k)))
                    v = ev.verdict(materialize(cfg.subset(keep), base), p)
                    out["curve"].append({"prop": p, "base": base, "level": lv, "agree": v == t, "verdict": v, "truth": t})
            for g in ("core", "union", "expert"):
                gset = {keynorm(cfg.service, x) for x in guards[p][g]}
                keep = [i for i, d in enumerate(cfg.directives) if keynorm(cfg.service, d.key) in gset]
                v = ev.verdict(materialize(cfg.subset(keep), base), p)
                out["gsync"].append({"prop": p, "guard": g, "base": base, "kept": len(keep), "n": n, "agree": v == t,
                                     "verdict": v, "truth": t})
    return out


def job_hist(ev, svc, chain):
    out = []
    for v in chain:
        if v is None:
            out.append(None)
            continue
        cfg = to_cfg(svc, [tuple(x) for x in v["directives"]])
        r = ev.raw(materialize(cfg, "vendor"))
        out.append({p: r[p] for p in PROPERTIES[svc]})
    return out


corpus = [to_cfg(e["service"], [tuple(x) for x in e["directives"]], e["cid"]) for e in RW["corpus"]]
truths = run_jobs([(job_truth, (c,)) for c in corpus], label="rw-truth")
acc = [(c, t) for c, t in zip(corpus, truths) if all(t[p] in (True, False) for p in PROPERTIES[c.service])]
rej = [(c.cid, c.service, t["_wire"]) for c, t in zip(corpus, truths) if (c, t) not in acc]
rnd = random.Random(2027)
sample = []
for svc in ("redis", "postgresql", "openssh"):
    pool = [x for x in acc if x[0].service == svc]
    sample += rnd.sample(pool, min(SAMPLE, len(pool)))
full = run_jobs([(job_full, (c, t, 31 * i)) for i, (c, t) in enumerate(sample)], label="rw-full")
# careful static analyzer on every accepted configuration (key names canonicalised for sshd)
static = []
for c, t in acc:
    ds = tuple(D(d.section, SSH_CANON.get(d.key.lower(), d.key) if c.service == "openssh" else d.key, d.value) for d in c.directives)
    try:
        pred = careful(Config(c.service, ds))
    except Exception as exc:  # an analyzer crash is reported, not hidden
        pred = {p: f"analyzer_error:{type(exc).__name__}" for p in PROPERTIES[c.service]}
    for p in PROPERTIES[c.service]:
        static.append({"cid": c.cid, "service": c.service, "prop": p, "truth": t[p], "pred": pred[p]})
dump("e8-realworld.json", {
    "accepted": [{"cid": c.cid, "service": c.service, "n": len(c), "truth": {p: t[p] for p in PROPERTIES[c.service]}} for c, t in acc],
    "rejected": rej, "full": full, "static": static,
})
