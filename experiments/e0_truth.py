"""E0: source verdicts for every candidate configuration; acceptance filter."""
from collections import Counter
from common import PROPERTIES, dump, job_truth, load_corpus
from fidelity.harness import run_jobs

cands = load_corpus(accepted_only=False)
res = run_jobs([(job_truth, (c,)) for c in cands], label="truth")
rows, accepted, rejected = [], [], []
for c, r in zip(cands, res):
    binary = all(r[p] in (True, False) for p in PROPERTIES[c.service])
    (accepted if binary else rejected).append(c.cid)
    if not binary:
        print("REJECTED", c.cid, r["_wire"][:150].replace("\n", " "))
    for p in PROPERTIES[c.service]:
        rows.append({"cid": c.cid, "service": c.service, "prop": p, "n": len(c), "verdict": r[p], "wire": r["_wire"][:160]})
dump("e0-accepted.json", accepted)
dump("e0-rejected.json", rejected)
keep = {c.cid for c in load_corpus()}
rows = [r for r in rows if r["cid"] in keep]
dump("e0-truth.json", rows)
for p in sorted({r["prop"] for r in rows}):
    sub = [r for r in rows if r["prop"] == p]
    print(p, Counter(str(r["verdict"]) for r in sub), "mean n=%.1f" % (sum(r["n"] for r in sub) / len(sub)))
print("rejected", Counter(c[:2] for c in rejected))
