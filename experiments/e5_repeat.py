"""E5: determinism check.  Re-run a random sample of cached twins on fresh
server processes, bypassing the cache, and compare verdicts."""
import json
import random
import sqlite3
from common import PROPERTIES, RESULTS, dump
from fidelity.config import Config, D
from fidelity.harness import run_jobs  # noqa: E402

con = sqlite3.connect(RESULTS / "verdict-cache.sqlite")
rows = list(con.execute("SELECT k, out FROM v"))
random.Random(5).shuffle(rows)
sample = rows[:1000]


def job(ev, key):
    svc, ds = json.loads(key)
    ev.cache.pop(key, None)
    ev.cache = {}
    return ev.raw(Config(svc, tuple(D(s, k, v) for s, k, v in ds)))


res = run_jobs([(job, (k,)) for k, _ in sample], label="repeat", persist=False)
same = diff = 0
diffs = []
for (k, o), r in zip(sample, res):
    o = json.loads(o)
    svc = json.loads(k)[0]
    for p in PROPERTIES[svc]:
        if o[p] == r[p]:
            same += 1
        else:
            diff += 1
            diffs.append({"key": k[:300], "prop": p, "first": o[p], "second": r[p]})
dump("e5-repeat.json", {"twins": len(sample), "verdicts_same": same, "verdicts_diff": diff, "diffs": diffs})
print(same, diff)
