"""Two static analyzers, written from documentation and never tuned against
server output.

* ``naive`` mirrors the rule style of the platform's static baseline
  (research/benchmark.py ``static_assess``): look up the last value of a few
  security keys and ignore order, scope and inheritance.
* ``careful`` encodes the documented semantics: Redis last-wins keys, ACL
  lines and protected mode; postgresql.conf last-wins and pg_hba first-match;
  nginx per-level inheritance where any allow/deny at a level replaces the
  parent's list; sshd first-obtained-value-wins with Match overrides.

Both analyzers know the probe context (client 10.77.0.1, user ``synthetic``
in group ``twinops`` and role ``readers``), as an expert reviewer would.
"""
from __future__ import annotations

import ipaddress
from fnmatch import fnmatch

from .config import Config

CLIENT = ipaddress.ip_address("10.77.0.1")


def _last(cfg, key, section=None, default=None):
    v = default
    for d in cfg.directives:
        if d.key == key and (section is None or d.section == section):
            v = d.value
    return v


# ------------------------------------------------------------------ naive
def naive(cfg: Config) -> dict:
    s = cfg.service
    if s == "redis":
        return {"redis.unauth_admin": _last(cfg, "protected-mode", default="yes") == "no"
                and _last(cfg, "requirepass") is None}
    if s == "postgresql":
        return {"pg.unauth_sql": any(d.key == "hba" and d.value.endswith(" trust") for d in cfg.directives)
                and _last(cfg, "listen_addresses", default="'localhost'") != "'localhost'"}
    if s == "nginx":
        leak = _last(cfg, "server_tokens", default="on") == "on"
        closed = any(d.key == "deny" and d.value == "all" for d in cfg.directives) or \
            any(d.key == "auth_basic" and d.value != "off" for d in cfg.directives) or \
            any(d.key == "internal" for d in cfg.directives)
        return {"nginx.version_leak": leak, "nginx.admin_open": not closed}
    pa = _last(cfg, "PasswordAuthentication", default="yes") == "yes"
    return {"ssh.password_login": pa and _last(cfg, "DenyUsers") != "synthetic"}


# ------------------------------------------------------------------ careful
def _redis(cfg):
    bind = None
    pm = "yes"
    user_on, has_pass, can_config = True, False, True
    renamed = False
    for d in cfg.directives:
        k, v = d.key, d.value
        if k == "bind":
            bind = v
        elif k == "protected-mode":
            pm = v
        elif k == "requirepass":
            has_pass = True
        elif k == "rename-command" and v.split()[0].upper() == "CONFIG":
            renamed = True
        elif k == "user":
            toks = v.split()[1:]
            for t in toks:
                if t == "on":
                    user_on = True
                elif t == "off":
                    user_on = False
                elif t == "nopass":
                    has_pass = False
                elif t.startswith(">"):
                    has_pass = True
                elif t in ("+@all", "allcommands"):
                    can_config = True
                elif t in ("-@admin", "-@dangerous", "-config", "-@all", "nocommands"):
                    can_config = False
    if bind is not None:
        addrs = [a.lstrip("-") for a in bind.split()]
        if not any(a in ("*", "0.0.0.0", "10.77.0.1") for a in addrs):
            return False
    if not user_on or has_pass or renamed or not can_config:
        return False
    return pm == "no"


def _hba_match(rule: str) -> bool:
    typ, db, user, addr, method = rule.split()[:5]
    if typ == "hostssl":
        return False
    if db not in ("all", "synthetic"):
        return False
    if user not in ("all", "synthetic", "+readers"):
        return False
    if addr == "samenet":
        return True
    return CLIENT in ipaddress.ip_network(addr)


def _pg(cfg):
    la = _last(cfg, "listen_addresses", default="'localhost'").strip("'")
    if la not in ("*", "10.77.0.1"):
        return False
    for d in cfg.directives:
        if d.key == "hba" and _hba_match(d.value):
            return d.value.split()[-1] == "trust"
    return False


def _innermost(cfg, key, levels, default=None):
    for lvl in levels:
        v = _last(cfg, key, lvl)
        if v is not None:
            return v
    return default


def _nginx(cfg):
    leak = _innermost(cfg, "server_tokens", ("loc:/", "server", "http"), "on") == "on"
    admin_levels = ("loc:/admin/", "server", "http")
    if any(d.key == "internal" and d.section == "loc:/admin/" for d in cfg.directives):
        return {"nginx.version_leak": leak, "nginx.admin_open": False}
    rules = None
    for lvl in admin_levels:
        lst = [d for d in cfg.directives if d.section == lvl and d.key in ("allow", "deny")]
        if lst:
            rules = lst
            break
    access = None  # None = no rules
    if rules:
        access = True
        for d in rules:
            if d.value == "all" or CLIENT in ipaddress.ip_network(d.value):
                access = d.key == "allow"
                break
    auth = _innermost(cfg, "auth_basic", admin_levels, "off") != "off"
    satisfy = _innermost(cfg, "satisfy", ("loc:/admin/", "server"), "all")
    if satisfy == "all":
        ok = access is not False and not auth
    else:
        ok = access is True or (not auth and access is not False)
    return {"nginx.version_leak": leak, "nginx.admin_open": ok}


MATCHES = {"Match User synthetic": True, "Match Address 10.77.0.0/16": True, "Match Group twinops": True,
           "Match Address 192.168.0.0/16": False, "Match User auditor": False}


def _ssh(cfg):
    eff: dict[str, str] = {}
    lists: dict[str, list[str]] = {}
    for d in cfg.directives:  # global, first value wins
        if d.section:
            continue
        if d.key in ("AllowUsers", "DenyUsers", "AllowGroups", "DenyGroups"):
            lists.setdefault(d.key, []).extend(d.value.split())
        else:
            eff.setdefault(d.key, d.value)
    matched: dict[str, str] = {}
    for d in cfg.directives:  # first matching Match block value wins, overrides global
        if d.section and MATCHES.get(d.section):
            matched.setdefault(d.key, d.value)
    eff.update(matched)
    if eff.get("PasswordAuthentication", "yes") != "yes":
        return False
    am = eff.get("AuthenticationMethods", "any")
    if am not in ("any", "password"):
        return False
    user_ok = lambda pat: fnmatch("synthetic", pat.split("@")[0]) and (
        "@" not in pat or fnmatch("10.77.0.1", pat.split("@")[1]))
    if any(user_ok(p) for p in lists.get("DenyUsers", [])):
        return False
    if "AllowUsers" in lists and not any(user_ok(p) for p in lists["AllowUsers"]):
        return False
    if "twinops" in lists.get("DenyGroups", []):
        return False
    if "AllowGroups" in lists and "twinops" not in lists["AllowGroups"]:
        return False
    return True


def careful(cfg: Config) -> dict:
    s = cfg.service
    if s == "redis":
        return {"redis.unauth_admin": _redis(cfg)}
    if s == "postgresql":
        return {"pg.unauth_sql": _pg(cfg)}
    if s == "nginx":
        return _nginx(cfg)
    return {"ssh.password_login": _ssh(cfg)}
