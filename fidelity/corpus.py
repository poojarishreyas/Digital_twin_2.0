"""Seeded generator of realistic service configurations and drift edits.

Each family has a *catalog* of directives (key, legal sections, plausible
values, class) and a set of *postures*: short recipes that reproduce
configuration patterns seen in hardening guides and in common
misconfiguration reports (protected mode switched off for a container, a
pg_hba trust rule for a CI subnet, an appended sshd override that never takes
effect, an nginx location that re-opens what the server block closed).

The class label ("security"/"operational") is a human annotation used only by
the key-guard baseline built from expert judgment and by the drift edit mix.
It is never consulted when cores are computed.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

from .config import ARRAY_KEYS, Config, D


@dataclass(frozen=True)
class Entry:
    key: str
    sections: tuple[str, ...]
    values: tuple[str, ...]
    cls: str


SEC, OPS = "security", "operational"

CATALOG: dict[str, list[Entry]] = {
    "redis": [
        Entry("bind", ("",), ("0.0.0.0", "127.0.0.1", "10.77.0.1", "127.0.0.1 10.77.0.1", "* -::*"), SEC),
        Entry("protected-mode", ("",), ("yes", "no"), SEC),
        Entry("requirepass", ("",), ("lab-only-password",), SEC),
        Entry("user", ("",), ("default on nopass ~* &* +@all", "default on nopass ~* &* +@all -@admin",
                              "default on nopass ~* &* +@all -@dangerous", "default off",
                              "default on >lab-only-password ~* &* +@all", "default on nopass ~* &* +@read +@write"), SEC),
        Entry("rename-command", ("",), ('CONFIG ""', "CONFIG CONFIG_b7f3", 'FLUSHALL ""', 'DEBUG ""'), SEC),
        Entry("maxmemory", ("",), ("64mb", "128mb", "256mb", "512mb"), OPS),
        Entry("maxmemory-policy", ("",), ("noeviction", "allkeys-lru", "volatile-lru", "allkeys-lfu"), OPS),
        Entry("timeout", ("",), ("0", "60", "300"), OPS),
        Entry("tcp-keepalive", ("",), ("60", "300"), OPS),
        Entry("loglevel", ("",), ("notice", "warning", "verbose"), OPS),
        Entry("databases", ("",), ("16", "4", "32"), OPS),
        Entry("maxclients", ("",), ("128", "256", "512"), OPS),
        Entry("hz", ("",), ("10", "20", "50"), OPS),
        Entry("lazyfree-lazy-eviction", ("",), ("yes", "no"), OPS),
        Entry("slowlog-log-slower-than", ("",), ("10000", "5000", "-1"), OPS),
        Entry("latency-monitor-threshold", ("",), ("0", "100"), OPS),
        Entry("tcp-backlog", ("",), ("128", "511"), OPS),
        Entry("notify-keyspace-events", ("",), ('""', "Ex", "KEA"), OPS),
        Entry("activerehashing", ("",), ("yes", "no"), OPS),
    ],
    "postgresql": [
        Entry("listen_addresses", ("conf",), ("'*'", "'localhost'", "'10.77.0.1'", "'127.0.0.1'"), SEC),
        Entry("password_encryption", ("conf",), ("scram-sha-256", "md5"), SEC),
        Entry("hba", ("hba",), (
            "host all all 0.0.0.0/0 trust", "host all all 10.77.0.0/16 trust", "host synthetic synthetic 10.77.0.1/32 trust",
            "host all +readers 10.77.0.0/16 trust", "host appdb all 0.0.0.0/0 trust", "host all admin 0.0.0.0/0 trust",
            "hostssl all all 0.0.0.0/0 trust", "host all all samenet trust", "host all all 192.168.10.0/24 trust",
            "host all all 0.0.0.0/0 scram-sha-256", "host all all 10.77.0.0/16 scram-sha-256", "host all all 127.0.0.1/32 scram-sha-256",
            "host all all 0.0.0.0/0 md5", "host appdb admin 10.77.0.0/16 scram-sha-256", "host all all 0.0.0.0/0 reject",
            "host synthetic all 10.77.0.0/16 reject", "hostnossl all all 0.0.0.0/0 reject", "host all all samenet password",
            "host replication all 10.77.0.0/16 trust", "host all synthetic 192.168.10.0/24 scram-sha-256"), SEC),
        Entry("max_connections", ("conf",), ("50", "100", "200"), OPS),
        Entry("shared_buffers", ("conf",), ("'16MB'", "'32MB'", "'64MB'"), OPS),
        Entry("work_mem", ("conf",), ("'4MB'", "'8MB'", "'16MB'"), OPS),
        Entry("log_connections", ("conf",), ("on", "off"), OPS),
        Entry("log_disconnections", ("conf",), ("on", "off"), OPS),
        Entry("statement_timeout", ("conf",), ("0", "'30s'", "'5min'"), OPS),
        Entry("authentication_timeout", ("conf",), ("'30s'", "'1min'"), OPS),
        Entry("log_min_duration_statement", ("conf",), ("-1", "250", "1000"), OPS),
        Entry("idle_in_transaction_session_timeout", ("conf",), ("0", "'60s'"), OPS),
        Entry("effective_cache_size", ("conf",), ("'128MB'", "'256MB'"), OPS),
        Entry("maintenance_work_mem", ("conf",), ("'32MB'", "'64MB'"), OPS),
        Entry("log_line_prefix", ("conf",), ("'%m [%p] '", "'%t %u@%d '"), OPS),
    ],
    "nginx": [
        Entry("server_tokens", ("http", "server", "loc:/"), ("on", "off"), SEC),
        Entry("allow", ("http", "server", "loc:/admin/"), ("10.77.0.1", "10.77.0.0/16", "192.168.0.0/16", "all"), SEC),
        Entry("deny", ("http", "server", "loc:/admin/"), ("all", "10.77.0.0/16", "192.168.0.0/16"), SEC),
        Entry("auth_basic", ("http", "server", "loc:/admin/"), ('"Restricted"', "off"), SEC),
        Entry("satisfy", ("server", "loc:/admin/"), ("any", "all"), SEC),
        Entry("internal", ("loc:/admin/",), ("",), SEC),
        Entry("client_max_body_size", ("http", "server", "loc:/"), ("1m", "8m", "64m"), OPS),
        Entry("keepalive_timeout", ("http", "server"), ("15", "65"), OPS),
        Entry("sendfile", ("http", "server"), ("on", "off"), OPS),
        Entry("gzip", ("http", "server", "loc:/"), ("on", "off"), OPS),
        Entry("add_header", ("http", "server", "loc:/", "loc:/admin/"), ("X-Frame-Options DENY", "X-Content-Type-Options nosniff",
                                                                    "Referrer-Policy no-referrer"), OPS),
        Entry("client_body_timeout", ("http", "server"), ("10s", "60s"), OPS),
        Entry("send_timeout", ("http", "server"), ("10s", "60s"), OPS),
        Entry("charset", ("http", "server", "loc:/"), ("utf-8", "off"), OPS),
        Entry("autoindex", ("loc:/", "loc:/admin/"), ("off",), OPS),
        Entry("etag", ("http", "server"), ("on", "off"), OPS),
        Entry("tcp_nodelay", ("http", "server"), ("on", "off"), OPS),
        Entry("expires", ("loc:/",), ("1h", "off"), OPS),
    ],
    "openssh": [
        Entry("PasswordAuthentication", ("", "Match User synthetic", "Match Address 10.77.0.0/16", "Match Group twinops",
                                         "Match Address 192.168.0.0/16", "Match User auditor"), ("yes", "no"), SEC),
        Entry("AuthenticationMethods", ("", "Match User synthetic", "Match Group twinops", "Match Address 10.77.0.0/16"),
              ("any", "publickey", "publickey,password", "password"), SEC),
        Entry("AllowUsers", ("",), ("synthetic", "auditor", "synthetic@10.77.0.1", "synthetic@192.168.*", "auditor synthetic", "*"), SEC),
        Entry("DenyUsers", ("",), ("synthetic", "auditor", "*@192.168.*", "synthetic@10.77.*"), SEC),
        Entry("AllowGroups", ("",), ("twinops", "wheel"), SEC),
        Entry("DenyGroups", ("",), ("twinops", "wheel"), SEC),
        Entry("PermitRootLogin", ("",), ("no", "prohibit-password", "yes"), SEC),
        Entry("PubkeyAuthentication", ("",), ("yes", "no"), SEC),
        Entry("PermitEmptyPasswords", ("",), ("no",), SEC),
        Entry("MaxAuthTries", ("",), ("3", "6"), SEC),
        Entry("X11Forwarding", ("", "Match User synthetic", "Match Group twinops"), ("yes", "no"), OPS),
        Entry("AllowTcpForwarding", ("", "Match User synthetic", "Match Address 192.168.0.0/16"), ("yes", "no"), OPS),
        Entry("ClientAliveInterval", ("",), ("0", "300"), OPS),
        Entry("ClientAliveCountMax", ("",), ("3", "2"), OPS),
        Entry("LoginGraceTime", ("",), ("30", "120"), OPS),
        Entry("LogLevel", ("",), ("INFO", "VERBOSE"), OPS),
        Entry("MaxSessions", ("",), ("10", "4"), OPS),
        Entry("TCPKeepAlive", ("",), ("yes", "no"), OPS),
        Entry("PrintMotd", ("",), ("no", "yes"), OPS),
        Entry("UseDNS", ("",), ("no",), OPS),
        Entry("PermitTunnel", ("",), ("no",), OPS),
        Entry("Banner", ("", "Match User auditor"), ("none",), OPS),
    ],
}

_CLS = {svc: {e.key: e.cls for e in entries} for svc, entries in CATALOG.items()}


def entry(service: str, key: str) -> Entry:
    return next(e for e in CATALOG[service] if e.key == key)


# --- postures -----------------------------------------------------------------
# Each posture returns a list of (section, key, value) in intended order.

def _redis_posture(r: random.Random):
    choices = [
        lambda: [("", "protected-mode", "no")],
        lambda: [("", "bind", "0.0.0.0"), ("", "protected-mode", "no")],
        lambda: [("", "protected-mode", r.choice(["yes", "no"])), ("", "requirepass", "lab-only-password")],
        lambda: [("", "user", "default off")],
        lambda: [("", "protected-mode", "no"), ("", "user", r.choice(CATALOG["redis"][3].values))],
        lambda: [("", "protected-mode", "no"), ("", "rename-command", r.choice(['CONFIG ""', "CONFIG CONFIG_b7f3", 'FLUSHALL ""']))],
        lambda: [("", "bind", r.choice(["127.0.0.1", "10.77.0.1", "127.0.0.1 10.77.0.1"])), ("", "protected-mode", "no")],
        lambda: [("", "protected-mode", "yes")],
        lambda: [],
        # appended override (last value wins in Redis)
        lambda: [("", "protected-mode", "yes"), ("", "protected-mode", "no")],
        lambda: [("", "protected-mode", "no"), ("", "protected-mode", "yes")],
        lambda: [("", "protected-mode", "no"), ("", "user", "default on >lab-only-password ~* &* +@all")],
    ]
    out = r.choice(choices)()
    if r.random() < 0.35:
        out += r.choice([lambda: [("", "rename-command", 'DEBUG ""')], lambda: [("", "requirepass", "lab-only-password")],
                         lambda: [("", "bind", r.choice(CATALOG["redis"][0].values))]])()
    return out


def _pg_posture(r: random.Random):
    conf = []
    la = r.choices(["'*'", "'localhost'", "'10.77.0.1'", "'127.0.0.1'", None], [0.5, 0.15, 0.15, 0.1, 0.1])[0]
    if la:
        conf.append(("conf", "listen_addresses", la))
    if r.random() < 0.15:  # appended override; last assignment wins in postgresql.conf
        conf.append(("conf", "listen_addresses", r.choice(["'*'", "'localhost'"])))
    if r.random() < 0.5:
        conf.append(("conf", "password_encryption", r.choice(["scram-sha-256", "md5"])))
    rules = entry("postgresql", "hba").values
    trusts = [v for v in rules if v.endswith(" trust")]
    others = [v for v in rules if not v.endswith(" trust")]
    hba = ["host all all 127.0.0.1/32 scram-sha-256"] if r.random() < 0.6 else []
    hba += r.sample(others, r.randint(1, 3))
    if r.random() < 0.75:
        pos = r.randint(0, len(hba))
        hba[pos:pos] = r.sample(trusts, r.randint(1, 2))
    if r.random() < 0.4:
        hba.append(r.choice(["host all all 0.0.0.0/0 reject", "host all all 0.0.0.0/0 scram-sha-256"]))
    seen, uniq = set(), []
    for h in hba:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return conf + [("hba", "hba", h) for h in uniq]


def _nginx_posture(r: random.Random):
    out = []
    for sec in r.sample(["http", "server", "loc:/"], r.choice([0, 1, 1, 2])):
        out.append((sec, "server_tokens", r.choice(["on", "off"])))
    access = [
        lambda: [],
        lambda: [("server", "deny", "all"), ("loc:/admin/", "allow", "10.77.0.1")],
        lambda: [("loc:/admin/", "allow", "192.168.0.0/16"), ("loc:/admin/", "deny", "all")],
        lambda: [("server", "allow", "10.77.0.0/16"), ("server", "deny", "all")],
        lambda: [("http", "deny", "all"), ("loc:/admin/", "allow", r.choice(["10.77.0.0/16", "192.168.0.0/16"])),
                 ("loc:/admin/", "deny", "all")],
        lambda: [("server", "auth_basic", '"Restricted"'), ("loc:/admin/", "auth_basic", "off")],
        lambda: [("loc:/admin/", "auth_basic", '"Restricted"')],
        lambda: [("loc:/admin/", "satisfy", r.choice(["any", "all"])), ("loc:/admin/", "allow", "10.77.0.0/16"),
                 ("loc:/admin/", "deny", "all"), ("loc:/admin/", "auth_basic", '"Restricted"')],
        lambda: [("loc:/admin/", "internal", "")],
        lambda: [("http", "auth_basic", '"Restricted"'), ("server", "satisfy", "any"), ("server", "allow", "10.77.0.1"),
                 ("server", "deny", "all")],
    ]
    out += r.choice(access)()
    return out


def _ssh_posture(r: random.Random):
    out = []
    pa = r.choices(["yes", "no", None], [0.4, 0.4, 0.2])[0]
    if pa:
        out.append(("", "PasswordAuthentication", pa))
    if pa and r.random() < 0.2:  # appended override that sshd ignores (first value wins)
        out.append(("", "PasswordAuthentication", "no" if pa == "yes" else "yes"))
    extras = [
        lambda: [("", "AllowUsers", r.choice(entry("openssh", "AllowUsers").values))],
        lambda: [("", "DenyUsers", r.choice(entry("openssh", "DenyUsers").values))],
        lambda: [("", r.choice(["AllowGroups", "DenyGroups"]), r.choice(["twinops", "wheel"]))],
        lambda: [("", "AuthenticationMethods", r.choice(["publickey", "publickey,password", "any"]))],
        lambda: [(r.choice(["Match User synthetic", "Match Address 10.77.0.0/16", "Match Group twinops",
                            "Match Address 192.168.0.0/16", "Match User auditor"]), "PasswordAuthentication", r.choice(["yes", "no"]))],
        lambda: [("Match Group twinops", "AuthenticationMethods", "publickey")],
        lambda: [],
    ]
    for f in r.sample(extras, r.choice([1, 1, 2, 3])):
        out += f()
    if r.random() < 0.6:
        out.append(("", "PermitRootLogin", r.choice(["no", "prohibit-password"])))
    if r.random() < 0.4:
        out.append(("", "PubkeyAuthentication", "yes"))
    if r.random() < 0.3:
        out.append(("", "MaxAuthTries", r.choice(["3", "6"])))
    return out


POSTURES = {"redis": _redis_posture, "postgresql": _pg_posture, "nginx": _nginx_posture, "openssh": _ssh_posture}
OPS_RANGE = {"redis": (4, 10), "postgresql": (3, 8), "nginx": (4, 10), "openssh": (4, 9)}


def _legal_add(service: str, current: list[tuple[str, str, str]], sec: str, key: str) -> bool:
    if key in ARRAY_KEYS[service]:
        return True
    return (sec, key) not in {(s, k) for s, k, _ in current}


def generate(service: str, seed: int, cid: str) -> Config:
    r = random.Random(seed)
    sec = POSTURES[service](r)
    ops = []
    lo, hi = OPS_RANGE[service]
    pool = [e for e in CATALOG[service] if e.cls == OPS]
    for e in r.sample(pool, min(len(pool), r.randint(lo, hi))):
        s = r.choice(e.sections)
        if _legal_add(service, ops + sec, s, e.key):
            ops.append((s, e.key, r.choice(e.values)))
    # interleave security directives into the operational ones, keeping their relative order
    merged = list(ops)
    pos = sorted(r.randint(0, len(ops)) for _ in sec)
    for k, (p, item) in enumerate(zip(pos, sec)):
        merged.insert(p + k, item)
    ds = tuple(D(s, k, v, i + 1, _CLS[service][k]) for i, (s, k, v) in enumerate(merged))
    return Config(service, ds, cid)


def corpus(per_service: int = 40, seed: int = 2026) -> list[Config]:
    out = []
    for si, svc in enumerate(("redis", "postgresql", "nginx", "openssh")):
        for i in range(per_service):
            out.append(generate(svc, seed * 1000 + si * 100 + i, f"{svc[:2]}{i:03d}"))
    return out


# --- drift edits -----------------------------------------------------------------

def edit(cfg: Config, r: random.Random, q_security: float, next_uid: int) -> tuple[Config, dict]:
    """Apply one plausible operator edit.  Returns the new config and an edit
    record naming the touched directive(s), as a delta stream would."""
    service = cfg.service
    ds = list(cfg.directives)
    want = SEC if r.random() < q_security else OPS
    kinds = ["modify", "modify", "modify", "add", "delete", "move"]
    for _ in range(50):
        kind = r.choice(kinds)
        if kind in ("modify", "delete", "move"):
            cand = [i for i, d in enumerate(ds) if d.cls == want]
            if not cand:
                continue
            i = r.choice(cand)
            d = ds[i]
            if kind == "modify":
                vals = [v for v in entry(service, d.key).values if v != d.value]
                if not vals:
                    continue
                ds[i] = D(d.section, d.key, r.choice(vals), d.uid, d.cls)
                touched = [ds[i]]
            elif kind == "delete":
                if len(ds) <= 2:
                    continue
                touched = [ds.pop(i)]
            else:
                if len(ds) < 3:
                    continue
                item = ds.pop(i)
                ds.insert(r.randint(0, len(ds)), item)
                touched = [item]
        else:
            pool = [e for e in CATALOG[service] if e.cls == want]
            e = r.choice(pool)
            s = r.choice(e.sections)
            cur = [(x.section, x.key, x.value) for x in ds]
            if not _legal_add(service, cur, s, e.key):
                if service == "nginx":
                    continue
                if r.random() > 0.3:  # occasionally an appended override in order-sensitive files
                    continue
            v = r.choice(e.values)
            if (s, e.key, v) in cur:
                continue
            new = D(s, e.key, v, next_uid, e.cls)
            ds.insert(r.randint(0, len(ds)), new) if service in ("postgresql", "openssh", "redis") and r.random() < 0.5 else ds.append(new)
            touched = [new]
        rec = {"kind": kind, "keys": sorted({(t.section, t.key) for t in touched}), "uids": [t.uid for t in touched],
               "cls": want}
        return Config(service, tuple(ds), cfg.cid), rec
    return cfg, {"kind": "noop", "keys": [], "uids": [], "cls": want}
