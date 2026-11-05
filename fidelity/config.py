"""Configuration model shared by every service family.

A configuration is an ordered tuple of directives.  Order is part of the
meaning (first-match pg_hba rules, first-wins sshd keys, last-wins Redis
keys), so nothing in this package ever sorts directives by name.

A *twin* of a configuration is built from a subset S of its directives plus a
base profile B that fills in any (section, key) the subset leaves open.  The
vendor profile V is empty: unsynchronized directives simply fall back to the
server's compiled defaults.  The platform profile P mirrors the default-twin
profile used by the Digital Twin platform's benchmark (research/benchmark.py,
``default_config``).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Iterable

SERVICES = ("redis", "postgresql", "nginx", "openssh")

# Properties probed over the wire.  nginx carries two.
PROPERTIES = {
    "redis": ("redis.unauth_admin",),
    "postgresql": ("pg.unauth_sql",),
    "nginx": ("nginx.version_leak", "nginx.admin_open"),
    "openssh": ("ssh.password_login",),
}

# Keys that may legally appear several times in one section and are
# appended rather than overridden.
ARRAY_KEYS = {
    "redis": {"user", "rename-command"},
    "postgresql": {"hba"},
    "nginx": {"allow", "deny", "add_header"},
    "openssh": {"AllowUsers", "DenyUsers", "AllowGroups", "DenyGroups"},
}


@dataclass(frozen=True)
class D:
    """One directive.  ``uid`` is a stable identity used to follow a directive
    through drift edits; it never reaches a rendered file."""

    section: str
    key: str
    value: str
    uid: int = field(default=0, compare=False)
    cls: str = field(default="operational", compare=False)  # "security" | "operational"

    def slot(self) -> tuple[str, str]:
        return (self.section, self.key)


@dataclass(frozen=True)
class Config:
    service: str
    directives: tuple[D, ...]
    cid: str = ""

    def __len__(self) -> int:
        return len(self.directives)

    def subset(self, keep: Iterable[int]) -> "Config":
        keep = set(keep)
        return replace(self, directives=tuple(d for i, d in enumerate(self.directives) if i in keep))

    def canonical(self) -> str:
        return json.dumps([self.service, [(d.section, d.key, d.value) for d in self.directives]])

    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode()).hexdigest()[:16]


BASE_PROFILES: dict[str, dict[str, tuple[D, ...]]] = {
    "vendor": {s: () for s in SERVICES},
    "platform": {
        "redis": (D("", "protected-mode", "yes", -1, "security"),),
        "openssh": (D("", "PasswordAuthentication", "no", -1, "security"),),
        "postgresql": (D("conf", "listen_addresses", "'*'", -1, "security"),
                       D("hba", "hba", "host all all 0.0.0.0/0 scram-sha-256", -2, "security")),
        "nginx": (D("http", "server_tokens", "on", -1, "security"),),
    },
}


def materialize(cfg: Config, base: str) -> Config:
    """Twin configuration = synchronized directives, then base fill-ins for
    every (section, key) slot the synchronized set leaves open.  pg_hba base
    rules are always appended, so they act as the lowest-priority catch-all."""
    profile = BASE_PROFILES[base][cfg.service]
    taken = {d.slot() for d in cfg.directives}
    extra = tuple(b for b in profile if b.key == "hba" or b.slot() not in taken)
    return replace(cfg, directives=cfg.directives + extra)
