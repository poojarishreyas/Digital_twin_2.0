"""Generic normalization of real configuration values before they are analyzed
or stored: secrets are replaced by the synthetic lab password, credential URLs
and long token-like strings are removed, and concrete addresses/ports are
remapped onto the twin's scaffolding as declared by the service spec."""
from __future__ import annotations

import ipaddress
import re

CRED_URL = re.compile(r"([a-z][a-z0-9+.-]*://)[^\s:@/]+:[^\s@/]+@\S*", re.I)
TOKEN = re.compile(r"(?<![A-Za-z0-9/.])(?=(?:[A-Za-z+_=-]*[0-9]){8})[A-Za-z0-9+_=-]{32,}(?![A-Za-z0-9/])")
KEEP_ADDR = {"*", "0.0.0.0", "::", "127.0.0.1", "::1", "localhost"}


def _remap_addr(tok: str) -> str:
    bare = tok.lstrip("-")
    if bare in KEEP_ADDR or not bare:
        return tok
    try:
        ipaddress.ip_address(bare)
        return "{host}"
    except ValueError:
        return tok


def normalize(spec: dict, directives: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    p = spec.get("parse", {})
    secret = {k.lower() for k in p.get("secret_keys", [])}
    token_keys = {k.lower() for k in p.get("token_secret_keys", [])}
    addr_keys = {k.lower() for k in p.get("address_keys", [])}
    rewrites = [(re.compile(r["key"]), re.compile(r["pattern"]), r["replace"], r.get("enumerate", False))
                for r in p.get("rewrite", [])]
    seen: dict[int, int] = {}
    out = []
    for sec, key, val in directives:
        k = key.lower()
        if k in secret:
            val = "{password}"
        if k in token_keys:
            val = " ".join(">{password}" if t.startswith((">", "#")) else t for t in val.split() if not t.startswith(("<", "!")))
        if k in addr_keys:
            parts = re.split(r"([,\s]+)", val)
            val = "".join(_remap_addr(x) if i % 2 == 0 else x for i, x in enumerate(parts))
        for ri, (kre, pat, rep, enum) in enumerate(rewrites):
            if kre.fullmatch(key) and pat.search(val):
                n = seen.get(ri, 0)
                seen[ri] = n + 1
                # later occurrences (e.g. a second listener) get distinct alternate placeholders
                val = pat.sub(rep if not enum or n == 0 else rep.replace("}", f"_alt{n}}}"), val)
        val = CRED_URL.sub(r"\1REDACTED", val)
        val = TOKEN.sub("REDACTED", val)
        out.append((sec, key, val))
    return out
