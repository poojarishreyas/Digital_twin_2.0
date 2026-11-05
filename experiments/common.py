"""Shared experiment helpers."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

from fidelity.config import PROPERTIES, materialize  # noqa: E402
from fidelity.corpus import corpus  # noqa: E402

PER_SERVICE = 60      # accepted configurations per family
CANDIDATES = 90       # generated per family before the source-acceptance filter
SEED = 2026


def load_corpus(accepted_only=True):
    """Sources must be configurations the real server accepts and answers
    conclusively; e0 records which candidates pass, and the first
    PER_SERVICE accepted ones per family form the corpus."""
    cfgs = corpus(CANDIDATES, SEED)
    if not accepted_only:
        return cfgs
    ok = set(load("e0-accepted.json"))
    out, per = [], {}
    for c in cfgs:
        if c.cid in ok and per.get(c.service, 0) < PER_SERVICE:
            per[c.service] = per.get(c.service, 0) + 1
            out.append(c)
    return out


def split(cfgs):
    """Deterministic 50/50 train/test split within each family."""
    train = [c for c in cfgs if int(c.cid[2:]) % 2 == 0]
    test = [c for c in cfgs if int(c.cid[2:]) % 2 == 1]
    return train, test


def dump(name, obj):
    (RESULTS / name).write_text(json.dumps(obj, indent=1, default=str) + "\n")


def load(name):
    return json.loads((RESULTS / name).read_text())


def job_truth(ev, cfg):
    return ev.raw(materialize(cfg, "vendor"))
