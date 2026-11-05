"""Collect public configuration files from GitHub code search (and their
git histories) for the real-world validation.

Raw files are untrusted data: they are written only to a scratch directory
outside the repository (RW_RAW, default /tmp/fidelity-rw-raw) and are never
executed.  Only parsed, redacted directive lists with content hashes are kept
in results/ (see parse.py); repository names are not published.

Usage:  python3 collect.py search      # code search -> candidates.json
        python3 collect.py fetch       # blobs for candidates
        python3 collect.py history     # commit histories for a sample
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

RAW = Path(os.environ.get("RW_RAW", "/tmp/fidelity-rw-raw"))
RAW.mkdir(parents=True, exist_ok=True)

QUERIES = {
    "redis": ["filename:redis.conf protected-mode", "filename:redis.conf requirepass", "filename:redis.conf bind",
              "filename:redis.conf rename-command", "filename:redis.conf maxmemory", "filename:redis.conf \"user default\""],
    "openssh": ["filename:sshd_config PasswordAuthentication", "filename:sshd_config Match", "filename:sshd_config AllowUsers",
                "filename:sshd_config PermitRootLogin", "filename:sshd_config AuthenticationMethods"],
    "postgresql": ["filename:pg_hba.conf trust", "filename:pg_hba.conf md5", "filename:pg_hba.conf scram-sha-256",
                   "filename:pg_hba.conf host all", "filename:pg_hba.conf reject"],
}


def gh(args: list[str], retries: int = 6):
    for attempt in range(retries):
        p = subprocess.run(["gh", "api", *args], capture_output=True, text=True)
        if p.returncode == 0:
            return json.loads(p.stdout) if p.stdout.strip() else None
        err = p.stderr
        if "rate limit" in err.lower() or "403" in err or "429" in err or "secondary" in err.lower():
            time.sleep(15 * (attempt + 1))
            continue
        if "404" in err or "409" in err or "422" in err:
            return None
        time.sleep(3)
    return None


def search():
    out = {}
    for fam, qs in QUERIES.items():
        seen = {}
        for q in qs:
            for page in range(1, 6):
                r = gh(["-X", "GET", "search/code", "-f", f"q={q}", "-f", "per_page=100", "-f", f"page={page}"])
                time.sleep(6.5)  # code search: 10 requests / minute
                if not r or not r.get("items"):
                    break
                for it in r["items"]:
                    key = f'{it["repository"]["full_name"]}:{it["path"]}'
                    seen[key] = {"repo": it["repository"]["full_name"], "path": it["path"], "sha": it["sha"]}
                print(fam, q, page, len(seen), flush=True)
                if len(r["items"]) < 100:
                    break
        out[fam] = list(seen.values())
    (RAW / "candidates.json").write_text(json.dumps(out))


def _raw(repo, path):
    url = f"https://raw.githubusercontent.com/{repo}/HEAD/{urllib.parse.quote(path)}"
    p = subprocess.run(["curl", "-sS", "-m", "20", "-f", url], capture_output=True)
    return p.stdout.decode("utf-8", errors="replace") if p.returncode == 0 else None


def fetch():
    """Current file contents via raw.githubusercontent.com (anonymous, public)."""
    cand = json.loads((RAW / "candidates.json").read_text())
    blobs = RAW / "blobs"
    blobs.mkdir(exist_ok=True)

    def one(it):
        dest = blobs / f"{it['sha']}.txt"
        if dest.exists():
            return 1
        text = _raw(it["repo"], it["path"])
        if text is None or len(text) > 400_000:
            return 0
        dest.write_text(text)
        return 1

    for fam, items in cand.items():
        items = sorted(items, key=lambda x: hashlib.sha256((x["repo"] + x["path"]).encode()).hexdigest())[:700]
        with ThreadPoolExecutor(16) as ex:
            n = sum(ex.map(one, items))
        print(fam, "fetched", n, flush=True)


def history(per_family: int = 150, depth: int = 400):
    """Every version of a file along its git history, from a blob-less clone."""
    cand = json.loads((RAW / "candidates.json").read_text())
    hp = RAW / "history.json"
    hist = json.loads(hp.read_text()) if hp.exists() else {}
    blobs = RAW / "blobs"
    clones = RAW / "clones"
    clones.mkdir(exist_ok=True)

    def one(fam, it):
        key = f"{fam}|{it['repo']}|{it['path']}"
        d = clones / hashlib.sha256(it["repo"].encode()).hexdigest()[:16]
        if not d.exists():
            r = subprocess.run(["git", "clone", "-q", f"--depth={depth}", "--filter=blob:none", "--no-checkout",
                                f"https://github.com/{it['repo']}", str(d)], capture_output=True, timeout=300)
            if r.returncode:
                return key, None
        log = subprocess.run(["git", "-C", str(d), "log", "--format=%H %cI", "--", it["path"]], capture_output=True, text=True)
        versions = []
        for line in reversed(log.stdout.split("\n")):
            if not line.strip():
                continue
            sha, date = line.split()
            show = subprocess.run(["git", "-C", str(d), "show", f"{sha}:{it['path']}"], capture_output=True, timeout=120)
            if show.returncode:
                versions.append({"commit": sha, "blob": None, "date": date})
                continue
            bid = hashlib.sha1(show.stdout).hexdigest()
            (blobs / f"h{bid}.txt").write_bytes(show.stdout)
            versions.append({"commit": sha, "blob": f"h{bid}", "date": date})
        return key, versions

    for fam, items in cand.items():
        by_repo = {}
        for it in sorted(items, key=lambda x: hashlib.sha256((x["repo"] + x["path"]).encode()).hexdigest()):
            by_repo.setdefault(it["repo"], it)
        sample = [it for it in list(by_repo.values())[:per_family] if f"{fam}|{it['repo']}|{it['path']}" not in hist]
        with ThreadPoolExecutor(8) as ex:
            for key, versions in ex.map(lambda it: _safe(one, fam, it), sample):
                if versions is not None:
                    hist[key] = versions
        hp.write_text(json.dumps(hist))
        print(fam, "histories", sum(1 for k in hist if k.startswith(fam + "|")), flush=True)


def _safe(fn, fam, it):
    try:
        return fn(fam, it)
    except Exception:
        return f"{fam}|{it['repo']}|{it['path']}", None


if __name__ == "__main__":
    if sys.argv[1] == "history" and len(sys.argv) > 2:
        history(int(sys.argv[2]))
    else:
        {"search": search, "fetch": fetch, "history": history}[sys.argv[1]]()
