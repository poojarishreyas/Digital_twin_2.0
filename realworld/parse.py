"""Parse public configuration files into the directive model, with redaction.

Rules (applied identically to every file and documented in the paper):
* comments and blank lines are ignored; directive order is preserved;
* environment-bound directives (ports, listen sockets, file paths, includes,
  modules, PID/log files, TLS material, replication peers) are dropped and
  counted, because a twin must supply them from its own scaffolding;
* concrete bind addresses other than loopback/wildcards are remapped to the
  twin's host address 10.77.0.1;
* every secret (Redis passwords and ACL hashes, LDAP bind passwords) is
  replaced by the synthetic lab password before anything is stored;
* PostgreSQL is studied through pg_hba.conf only, with the server listening on
  all addresses (the study isolates client-authentication semantics).

The output contains no repository names: configurations are identified by a
hash of their normalized directives.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
import sys
from pathlib import Path

PW = "lab-only-password"
CRED_URL = re.compile(r"([a-z][a-z0-9+.-]*://)[^\s:@/]+:[^\s@/]+@\S*", re.I)
TOKEN = re.compile(r"(?<![A-Za-z0-9/.])(?=(?:[A-Za-z+_=-]*[0-9]){8})[A-Za-z0-9+_=-]{32,}(?![A-Za-z0-9/])")


def scrub(directives):
    """Generic redaction applied to every parsed value: credential-bearing URLs
    and long token-like strings are replaced, whatever directive holds them."""
    out = []
    for sec, key, val in directives:
        val = CRED_URL.sub(r"\1REDACTED", val)
        val = TOKEN.sub("REDACTED", val)
        out.append((sec, key, val))
    return out

REDIS_ENV = {"port", "daemonize", "supervised", "pidfile", "logfile", "dir", "dbfilename", "unixsocket", "unixsocketperm",
             "include", "loadmodule", "aclfile", "cluster-config-file", "appendfilename", "appenddirname", "syslog-enabled",
             "syslog-ident", "syslog-facility", "save", "appendonly", "replicaof", "slaveof", "masterauth", "masteruser",
             "tls-port", "tls-cert-file", "tls-key-file", "tls-ca-cert-file", "tls-ca-cert-dir", "tls-dh-params-file",
             "tls-client-cert-file", "tls-client-key-file", "tls-key-file-pass", "tls-client-key-file-pass",
             "cluster-enabled", "always-show-logo", "set-proc-title", "proc-title-template", "cluster-announce-ip",
             "replica-announce-ip", "slave-announce-ip", "sentinel"}
SSH_ENV = {"port", "listenaddress", "hostkey", "pidfile", "include", "usepam", "hostcertificate", "hostkeyagent",
           "addressfamily"}


def _addr(a: str) -> str:
    bare = a.lstrip("-")
    if bare in ("*", "0.0.0.0", "::", "127.0.0.1", "::1", "localhost"):
        return a if bare not in ("::", "::1") else "-" + bare
    try:
        ipaddress.ip_address(bare)
        return "10.77.0.1"
    except ValueError:
        return "10.77.0.1"


def parse_redis(text: str):
    out, dropped = [], {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        key = parts[0].lower()
        val = parts[1].strip() if len(parts) > 1 else ""
        if key in REDIS_ENV or key.startswith("tls-"):
            dropped[key] = dropped.get(key, 0) + 1
            continue
        if key == "bind":
            addrs = []
            for a in val.split():
                m = _addr(a)
                if m not in addrs:
                    addrs.append(m)
            val = " ".join(addrs)
        elif key == "requirepass":
            val = PW
        elif key == "user":
            toks = []
            for t in val.split():
                if t.startswith(">") or t.startswith("#"):
                    t = ">" + PW
                elif t.startswith("<") or t.startswith("!"):
                    continue
                toks.append(t)
            val = " ".join(toks)
        out.append(("", key, val))
    return out, dropped


def parse_sshd(text: str):
    out, dropped, section = [], {}, ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip() if not raw.strip().startswith("#") else ""
        if not line:
            continue
        m = re.match(r"(\S+)\s*(?:=\s*|\s+)(.*)", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2).strip()
        if key.lower() == "match":
            section = "" if val.lower() == "all" else f"Match {val}"
            continue
        if key.lower() in SSH_ENV:
            dropped[key.lower()] = dropped.get(key.lower(), 0) + 1
            continue
        out.append((section, key, val))
    return out, dropped


def parse_hba(text: str):
    out, dropped = [], {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        toks = line.split()
        if toks[0].startswith("include"):
            dropped["include"] = dropped.get("include", 0) + 1
            continue
        if toks[0] not in ("local", "host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"):
            dropped["malformed"] = dropped.get("malformed", 0) + 1
            continue
        toks = [re.sub(r"^(ldapbindpasswd|radiussecrets?)=.*", rf"\1={PW}", t) for t in toks]
        out.append(("hba", "hba", " ".join(toks)))
    conf = [("conf", "listen_addresses", "'*'")]
    return conf + out, dropped


HERE = Path(__file__).resolve().parent
KNOWN = {"redis": set((HERE / "redis-keywords.txt").read_text().split()),
         "openssh": set((HERE / "sshd-keywords.txt").read_text().split())}
TEMPLATE = re.compile(r"\{\{|\{%|<%|\$\{|^\.(Dd|Dt|Sh|It|Nm)\b", re.M)
MIN_KNOWN = {"redis": 0.8, "openssh": 0.9}


def looks_like_config(fam, text, ds):
    """Reject templates, manual pages and other non-configuration files."""
    if TEMPLATE.search(text):
        return False
    if fam in KNOWN:
        keys = [d[1].lower() for d in ds]
        if not keys:
            return False
        return sum(1 for k in keys if k in KNOWN[fam]) / len(keys) >= MIN_KNOWN[fam]
    return True


PARSERS = {"redis": parse_redis, "openssh": parse_sshd, "postgresql": parse_hba}


def cid(family, directives):
    return family[:2] + "-" + hashlib.sha256(json.dumps([family, directives]).encode()).hexdigest()[:10]


def main(raw_dir: str, out_path: str):
    raw = Path(raw_dir)
    cand = json.loads((raw / "candidates.json").read_text())
    corpus, seen, stats = [], set(), {}
    for fam, items in cand.items():
        st = stats.setdefault(fam, {"files": 0, "not_config": 0, "empty": 0, "duplicate": 0, "kept": 0, "dropped": {}, "directives": 0})
        for it in items:
            f = raw / "blobs" / f"{it['sha']}.txt"
            if not f.exists():
                continue
            st["files"] += 1
            text = f.read_text(errors="replace")
            ds, dropped = PARSERS[fam](text)
            ds = scrub(ds)
            if not looks_like_config(fam, text, ds):
                st["not_config"] = st.get("not_config", 0) + 1
                continue
            for k, v in dropped.items():
                st["dropped"][k] = st["dropped"].get(k, 0) + v
            core_ds = [d for d in ds if not (fam == "postgresql" and d[0] == "conf")]
            if not core_ds:
                st["empty"] += 1
                continue
            i = cid(fam, ds)
            if i in seen:
                st["duplicate"] += 1
                continue
            seen.add(i)
            st["kept"] += 1
            st["directives"] += len(ds)
            corpus.append({"cid": i, "service": fam, "directives": ds, "blob": hashlib.sha256(it["sha"].encode()).hexdigest()[:12]})
    # histories -> anonymized version chains of parsed configurations
    hist_out = []
    hp = raw / "history.json"
    if hp.exists():
        for key, versions in json.loads(hp.read_text()).items():
            fam = key.split("|", 1)[0]
            chain = []
            for v in versions:
                f = raw / "blobs" / f"{v['blob']}.txt" if v["blob"] else None
                if f is None or not f.exists():
                    chain.append(None)
                    continue
                text = f.read_text(errors="replace")
                ds, _ = PARSERS[fam](text)
                ds = scrub(ds)
                if not looks_like_config(fam, text, ds):
                    chain.append(None)
                    continue
                chain.append({"date": v["date"], "directives": ds})
            hist_out.append({"file": hashlib.sha256(key.encode()).hexdigest()[:12], "service": fam, "versions": chain})
    Path(out_path).write_text(json.dumps({"stats": stats, "corpus": corpus, "histories": hist_out}))
    print(json.dumps(stats, indent=1))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
