"""Parallel, cached evaluation of twin configurations on real servers.

Each worker process owns one *slot* (its own ports and directories), so up to
four servers of the same family can run side by side.  Verdicts are cached by
the canonical form of the materialized twin, because the same twin recurs
across experiments (the empty subset, the full configuration, ddmin probes).
The cache lives in SQLite and is written only by the parent process.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import sqlite3
import time
from pathlib import Path

from .config import PROPERTIES, Config
from .services.impl import SERVICE_CLASSES

CACHE = Path(__file__).resolve().parent.parent / "results" / "verdict-cache.sqlite"


def _db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=60)
    con.execute("CREATE TABLE IF NOT EXISTS v (k TEXT PRIMARY KEY, out TEXT, secs REAL)")
    return con


class Evaluator:
    def __init__(self, slot: int, cache_path: Path = CACHE, readonly_cache: dict | None = None):
        self.slot = slot
        self.services: dict[str, object] = {}
        self.cache: dict[str, dict] = dict(readonly_cache or {})
        self.new: dict[str, tuple[dict, float]] = {}
        self.runs = 0

    def raw(self, twin: Config) -> dict:
        key = twin.canonical()
        if key in self.cache:
            return self.cache[key]
        svc = self.services.get(twin.service)
        if svc is None:
            svc = self.services[twin.service] = SERVICE_CLASSES[twin.service](self.slot)
        t = time.monotonic()
        out = svc.run(twin)
        secs = time.monotonic() - t
        # one retry for inconclusive probes (transient timeouts)
        if any(out.get(p) == "inconclusive" for p in PROPERTIES[twin.service]):
            out = svc.run(twin)
            secs = time.monotonic() - t
        self.runs += 1
        clean = {}
        for p in PROPERTIES[twin.service]:
            clean[p] = "error" if out.get("_start") != "ok" else out.get(p)
        clean["_wire"] = out.get("_wire", out.get("_detail", ""))
        self.cache[key] = clean
        self.new[key] = (clean, secs)
        return clean

    def verdict(self, twin: Config, prop: str):
        return self.raw(twin)[prop]


# ---------------------------------------------------------------- pool plumbing
_EV: Evaluator | None = None


def _init(slots, snapshot):
    global _EV
    _EV = Evaluator(slots.get(), readonly_cache=snapshot)


def _call(job):
    fn, args = job
    _EV.new = {}
    result = fn(_EV, *args)
    return result, _EV.new


def load_cache(path: Path = CACHE) -> dict:
    con = _db(path)
    return {k: json.loads(o) for k, o in con.execute("SELECT k, out FROM v")}


def save(entries: dict, path: Path = CACHE) -> None:
    if not entries:
        return
    con = _db(path)
    con.executemany("INSERT OR REPLACE INTO v VALUES (?,?,?)",
                    [(k, json.dumps(o), s) for k, (o, s) in entries.items()])
    con.commit()
    con.close()


def run_jobs(jobs: list, workers: int = 4, label: str = "") -> list:
    """jobs = [(fn, args)], fn(evaluator, *args) -> result.  Order preserved."""
    snapshot = load_cache()
    manager = mp.Manager()
    slots = manager.Queue()
    for i in range(workers):
        slots.put(i)
    results = [None] * len(jobs)
    t0 = time.monotonic()
    pending = {}
    with mp.get_context("fork").Pool(workers, initializer=_init, initargs=(slots, snapshot)) as pool:
        for i, res in enumerate(pool.imap(_call, jobs, chunksize=1)):
            results[i], new = res
            pending.update(new)
            if len(pending) > 200:
                save(pending)
                pending = {}
            if label and (i + 1) % max(1, len(jobs) // 20) == 0:
                print(f"[{label}] {i+1}/{len(jobs)} {time.monotonic()-t0:.0f}s", flush=True)
    save(pending)
    return results
