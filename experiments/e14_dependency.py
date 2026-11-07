"""E14: dependency-aware selection baseline, privacy effect and adapter effort.

Dependency-aware selection (in the spirit of configuration-aware regression
test selection, e.g. Ctest/uRTS) re-runs a property only when an edit touches a
key that the property's *documented* semantics read.  We take that dependency
map from the careful static analyzer (fidelity/static.py), i.e. from
documentation, not from server runs, and compare it with learned/expert guards
on (a) synthetic drift traces, (b) real commit histories, and (c) selective
synchronization on held-out configurations (real-server verdicts)."""
import re
from collections import Counter
from pathlib import Path

import yaml
from common import PROPERTIES, dump, load, load_corpus, materialize, split
from fidelity.config import Config, D
from fidelity.harness import run_jobs

DEP = {  # keys read by fidelity/static.py careful() for each property
    "redis.unauth_admin": {"bind", "protected-mode", "requirepass", "user", "rename-command"},
    "pg.unauth_sql": {"listen_addresses", "hba"},
    "nginx.version_leak": {"server_tokens"},
    "nginx.admin_open": {"allow", "deny", "auth_basic", "satisfy", "internal"},
    "ssh.password_login": {"PasswordAuthentication", "AuthenticationMethods", "AllowUsers", "DenyUsers",
                           "AllowGroups", "DenyGroups"},
}
guards = load("e3-guards.json")
sets = {p: {"dependency": DEP[p], "union": set(guards[p]["union"]), "expert": set(guards[p]["expert"])} for p in DEP}


def replay(versions, prop, keys, norm=lambda k: k):
    vs = [v["verdict"][prop] for v in versions]
    twin, stale, resync, late = vs[0], 0, 0, 0
    for t in range(1, len(vs)):
        rec = versions[t]["edit"]
        changed = rec["kind"] not in ("rejected_by_server", "noop")
        touched = {norm(k[1]) for k in rec["keys"]}
        if changed and touched & {norm(k) for k in keys}:
            resync += 1
            twin = vs[t]
        if twin != vs[t]:
            stale += 1
            late += vs[t] != vs[t - 1]
    return resync, stale, len(vs) - 1, late


out = {"synthetic": {}, "real": {}}
traces = load("e3-traces.json")
for q in (0.1, 0.3, 0.5):
    for name in ("dependency", "union", "expert"):
        tot = [replay(t["versions"], p, sets[p][name]) for t in traces if t["q"] == q for p in PROPERTIES[t["service"]]]
        steps = sum(x[2] for x in tot)
        out["synthetic"][f"{q}|{name}"] = {"resync_per100": 100 * sum(x[0] for x in tot) / steps,
                                          "stale_pct": 100 * sum(x[1] for x in tot) / steps, "late_flips": sum(x[3] for x in tot)}
# real histories
hist = load("e9-realdrift.json")
for name in ("dependency", "union", "expert"):
    re_, late = 0, 0
    for h in hist:
        svc = h["service"]
        prop = PROPERTIES[svc][0]
        norm = (lambda k: k.lower()) if svc == "openssh" else (lambda k: k)
        G = {norm(k) for k in sets[prop][name]}
        prev = pv = twin = None
        for v, r in zip(h["versions"], h["verdicts"]):
            if v is None or r is None or r[prop] not in (True, False):
                continue
            cur = [tuple(x) for x in v["directives"]]
            if prev is None:
                prev, pv, twin = cur, r[prop], r[prop]
                continue
            a, b = Counter(prev), Counter(cur)
            touched = {norm(x[1]) for x in (a - b) + (b - a)} or ({norm(x[1]) for x in cur} if cur != prev else set())
            if cur != prev and touched & G:
                re_ += 1
                twin = r[prop]
            late += twin != r[prop] and r[prop] != pv
            prev, pv = cur, r[prop]
    out["real"][name] = {"re_emulations": re_, "late_flips": late}


# selective synchronization accuracy with the dependency set (real servers, held-out configs + drift versions)
def job(ev, svc, directives, keyset, props):
    cfg = Config(svc, tuple(D(s, k, v) for s, k, v in directives))
    keep = [i for i, d in enumerate(cfg.directives) if d.key in keyset]
    r = ev.raw(materialize(cfg.subset(keep), "vendor"))
    return {"kept": len(keep), "n": len(cfg), "verdict": {p: r[p] for p in props}}


_, test = split(load_corpus())
jobs, meta = [], []
for t in traces:
    if t["q"] != 0.3:
        continue
    c0 = next(c for c in test if c.cid == t["cid"])
    samples = [([(d.section, d.key, d.value) for d in c0.directives], t["versions"][0]["verdict"])]
    samples += [(t["versions"][i]["config"], t["versions"][i]["verdict"]) for i in range(8, 41, 8)]
    for directives, truth in samples:
        for p in PROPERTIES[t["service"]]:
            jobs.append((job, (t["service"], directives, DEP[p], [p])))
            meta.append((p, truth[p]))
res = run_jobs(jobs, label="dep-gsync")
agree = [r["verdict"][p] == tr for (p, tr), r in zip(meta, res)]
out["gsync_dependency"] = {"n": len(agree), "accuracy": sum(agree) / len(agree),
                           "exported": sum(r["kept"] / r["n"] for r in res) / len(res),
                           "errors_by_prop": dict(Counter(p for (p, _), a in zip(meta, agree) if not a))}

# privacy: what full synchronization would ship versus guard-key export, on the public corpus
rw = load("rw-corpus.json")["corpus"]
SITE = re.compile(r"(/[\w.-]+){2,}|\b\d{1,3}(\.\d{1,3}){3}\b|\{host\}|[A-Za-z0-9-]+\.[A-Za-z]{2,}\b")
prop_of = {"redis": "redis.unauth_admin", "postgresql": "pg.unauth_sql", "openssh": "ssh.password_login"}
priv = {}
for svc in ("redis", "postgresql", "openssh"):
    p = prop_of[svc]
    G = {k.lower() for k in sets[p]["union"]}
    tot = exp = site_tot = site_exp = 0
    keys_tot, keys_exp = Counter(), Counter()
    for c in rw:
        if c["service"] != svc:
            continue
        for s, k, v in c["directives"]:
            if svc == "postgresql" and s == "conf":
                continue
            tot += 1
            site = bool(SITE.search(v))
            site_tot += site
            keys_tot[k.lower()] += 1
            if k.lower() in G:
                exp += 1
                site_exp += site
                keys_exp[k.lower()] += 1
    priv[svc] = {"directives": tot, "exported": exp, "site_specific": site_tot, "site_specific_exported": site_exp,
                 "distinct_keys": len(keys_tot), "distinct_keys_exported": len(keys_exp)}
out["privacy"] = priv

# adapter development effort: spec size by part
eff = {}
for f in sorted(Path("../specs").glob("*.yaml")):
    spec = yaml.safe_load(f.read_text())
    lines = [l for l in f.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
    cat_start = next((i for i, l in enumerate(lines) if l.startswith("catalog:")), len(lines))
    cat_end = next((i for i, l in enumerate(lines) if i > cat_start and re.match(r"^[a-z_]+:", l)), len(lines))
    eff[f.stem] = {"lines": len(lines), "catalog_lines": cat_end - cat_start, "core_lines": len(lines) - (cat_end - cat_start),
                   "environment_keys": len(spec.get("parse", {}).get("environment", [])),
                   "properties": len(spec["properties"]), "catalog_entries": len(spec.get("catalog", [])),
                   "postures": len(spec.get("postures", []))}
out["effort"] = eff
dump("e14-dependency.json", out)
import json
print(json.dumps(out, indent=1))
