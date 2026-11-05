"""E12: the CI gate replayed on real public commit histories (E9 verdicts).
For every consecutive pair of versions: which keys changed, whether the gate
re-emulates (key guard), and whether the commit introduced or removed an
exposure.  Uses the verdicts already measured in E9; no new server runs."""
from collections import Counter
from common import PROPERTIES, dump, load

guards = load("e3-guards.json")
hist = load("e9-realdrift.json")
out = {"commits": 0, "parsed_changes": 0, "introduced": 0, "removed": 0, "by_service": Counter(),
       "gate": {}}
for g in ("union", "expert"):
    out["gate"][g] = {"re_emulations": 0, "blocked": 0, "missed_introductions": 0}
examples = []
for h in hist:
    svc = h["service"]
    prop = PROPERTIES[svc][0]
    norm = (lambda k: k.lower()) if svc == "openssh" else (lambda k: k)
    prev = pv = None
    for v, r in zip(h["versions"], h["verdicts"]):
        if v is None or r is None or r[prop] not in (True, False):
            continue
        cur = [tuple(x) for x in v["directives"]]
        if prev is None:
            prev, pv = cur, r[prop]
            continue
        out["commits"] += 1
        changed = cur != prev
        a, b = Counter(prev), Counter(cur)
        touched = {norm(x[1]) for x in (a - b) + (b - a)} or ({norm(x[1]) for x in cur} if changed else set())
        out["parsed_changes"] += changed
        intro = pv is False and r[prop] is True
        out["introduced"] += intro
        out["removed"] += pv is True and r[prop] is False
        if intro:
            out["by_service"][svc] += 1
            examples.append({"service": svc, "touched": sorted(touched)})
        for g in ("union", "expert"):
            G = {norm(k) for k in guards[prop][g]}
            fire = changed and bool(touched & G)
            out["gate"][g]["re_emulations"] += fire
            out["gate"][g]["blocked"] += fire and intro
            out["gate"][g]["missed_introductions"] += (not fire) and intro
        prev, pv = cur, r[prop]
out["by_service"] = dict(out["by_service"])
out["introducing_commit_keys"] = examples
dump("e12-gate.json", out)
print({k: v for k, v in out.items() if k != "introducing_commit_keys"})
print(examples)
