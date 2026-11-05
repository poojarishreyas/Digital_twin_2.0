"""Format-generic rendering and parsing of configurations.

A service spec describes *where* each section's directives go (a placeholder in
a file template) and *how* one directive is written (a line pattern).  The
same machinery covers flat key/value files (Redis, sshd, Mosquitto), files
with dynamic block headers (sshd ``Match``), INI files (MariaDB), brace-block
files (Nginx), rule lists (pg_hba) and nested YAML (MongoDB).

Parsing is the inverse: a real configuration file is turned into the ordered
directive model ``(section, key, value)`` so that the engine can compute
verdicts, cores and pivots on it.
"""
from __future__ import annotations

import re
from typing import Any

import yaml

from .config import Config

PLACE = re.compile(r"\{\{([A-Za-z0-9_:/.-]+)\}\}")


class Yaml12Loader(yaml.SafeLoader):
    """YAML 1.2 core-schema booleans: only true/false.  PyYAML defaults to YAML
    1.1, where on/off/yes/no are booleans; servers such as mongod (yaml-cpp)
    read them as strings, so 1.1 semantics would silently change values."""


Yaml12Loader.yaml_implicit_resolvers = {k: [r for r in v if r[0] != "tag:yaml.org,2002:bool"]
                                        for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()}
Yaml12Loader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
                                   list("tTfF"))


def subst(text: str, ctx: dict[str, Any]) -> str:
    """Replace {host}, {port}, {dir} ... without touching other braces."""
    for k, v in ctx.items():
        text = text.replace("{" + k + "}", str(v))
    return text


# ----------------------------------------------------------------------- rendering
def _section_spec(spec: dict, section: str) -> dict | None:
    secs = spec["config"].get("sections", {})
    if section in secs:
        return secs[section]
    for dyn in spec["config"].get("dynamic_sections", []):
        if re.match(dyn["match"], section):
            return dyn
    return None


def _line(sec: dict, key: str, value: str) -> str:
    if value == "" and "line_flag" in sec:
        return sec["line_flag"].replace("{key}", key)
    return sec.get("line", "{key} {value}").replace("{key}", key).replace("{value}", value)


def _yaml_value(v: str):
    try:
        return yaml.load(v, Loader=Yaml12Loader)
    except yaml.YAMLError:
        return v


def _nest(dotted: dict[str, Any]) -> dict:
    out: dict = {}
    for path, val in dotted.items():
        cur = out
        parts = path.split(".")
        for p in parts[:-1]:
            cur = cur.setdefault(p, {}) if isinstance(cur.get(p, {}), dict) else cur.setdefault(p, {})
        cur[parts[-1]] = val
    return out


def _merge(a: dict, b: dict) -> dict:
    """Deep merge; values in b win."""
    out = dict(a)
    for k, v in b.items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def render(spec: dict, cfg: Config, ctx: dict[str, Any]) -> dict[str, str]:
    """Render a configuration into the files named by the spec."""
    fmt = spec["config"].get("format", "template")
    files = {f["name"]: f["template"] for f in spec["config"]["files"]}
    if fmt == "yaml":
        # every directive key is a dotted path; the scaffold is merged on top so
        # that ports and storage paths always come from the twin, never the source
        dotted: dict[str, Any] = {}
        for d in cfg.directives:
            dotted[d.key] = _yaml_value(subst(d.value, ctx))
        body = _nest(dotted)
        scaffold = yaml.safe_load(subst(spec["config"].get("yaml_scaffold", "{}"), ctx)) or {}
        name = spec["config"]["files"][0]["name"]
        return {name: yaml.safe_dump(_merge(body, scaffold), sort_keys=False)}
    chunks: dict[str, list[str]] = {}
    dyn_order: dict[str, list[str]] = {}
    for d in cfg.directives:
        sec = _section_spec(spec, d.section)
        if sec is None:
            raise ValueError(f"section {d.section!r} not declared for {spec['name']}")
        ph = sec["placeholder"]
        if "header" in sec and sec.get("dynamic", "match" in sec):
            # dynamic sections (e.g. sshd Match blocks) are grouped under one header
            blocks = dyn_order.setdefault(ph, [])
            if d.section not in blocks:
                blocks.append(d.section)
            chunks.setdefault(f"{ph}\x00{d.section}", []).append(_line(sec, d.key, subst(d.value, ctx)))
        else:
            chunks.setdefault(ph, []).append(_line(sec, d.key, subst(d.value, ctx)))
    for ph, sections in dyn_order.items():
        sec = _section_spec(spec, sections[0])
        text = []
        for s in sections:
            text.append(sec["header"].replace("{section}", s))
            text += chunks.pop(f"{ph}\x00{s}")
        chunks[ph] = text
    out = {}
    for name, tpl in files.items():
        text = subst(tpl, ctx)
        text = PLACE.sub(lambda m: "\n".join(chunks.get(m.group(1), [])), text)
        out[name] = text
    return out


# ----------------------------------------------------------------------- parsing
def parse(spec: dict, text: str):
    """Parse a real configuration file into ordered (section, key, value)
    directives.  Returns (directives, line_numbers, dropped) where dropped counts
    environment-bound keys removed because the twin supplies them itself."""
    p = spec.get("parse", {})
    kind = p.get("kind", "lines")
    env = [k.lower() for k in p.get("environment", [])]
    dropped: dict[str, int] = {}
    out: list[tuple[str, str, str]] = []
    lines: list[int] = []

    def is_env(key):
        k = key.lower()
        return any(k == e or (e.endswith("*") and k.startswith(e[:-1])) for e in env)

    def keep(section, key, value, lineno):
        if is_env(key):
            dropped[key.lower()] = dropped.get(key.lower(), 0) + 1
            return
        out.append((section, key, value))
        lines.append(lineno)

    for pre in p.get("prefix", []):
        out.append((pre.get("section", ""), pre["key"], str(pre["value"])))
        lines.append(0)
    if kind == "yaml":
        try:
            doc = yaml.load(text, Loader=Yaml12Loader) or {}
        except yaml.YAMLError:
            return [], [], {"unparseable": 1}
        if not isinstance(doc, dict):
            return [], [], {"unparseable": 1}
        keyline = {}
        for i, raw in enumerate(text.splitlines(), 1):
            m = re.match(r"\s*([A-Za-z0-9_.]+)\s*:", raw)
            if m:
                keyline.setdefault(m.group(1), i)

        def walk(node, prefix):
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, f"{prefix}.{k}" if prefix else str(k))
            else:
                val = yaml.safe_dump(node, default_flow_style=True).strip()
                val = val[:-4].strip() if val.endswith("...") else val
                keep("", prefix, val, keyline.get(prefix.split(".")[-1], 0))
        walk(doc, "")
        return out, lines, dropped
    if kind == "rules":
        types = tuple(p.get("rule_types", []))
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split(p.get("comment", "#"), 1)[0].strip()
            if not line:
                continue
            if types and not line.split()[0] in types:
                dropped["unsupported_rule"] = dropped.get("unsupported_rule", 0) + 1
                continue
            keep(p.get("section", ""), p.get("key", "rule"), " ".join(line.split()), i)
        return out, lines, dropped
    if kind == "ini":
        section = p.get("default_section", "")
        allowed = p.get("sections")
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line[0] in "#;":
                continue
            m = re.match(r"^\[([^\]]+)\]$", line)
            if m:
                section = m.group(1).strip()
                continue
            if allowed and section not in allowed:
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                keep(p.get("map_section", section), k.strip(), v.strip(), i)
            else:
                keep(p.get("map_section", section), line, "", i)
        return out, lines, dropped
    header = re.compile(p["section_header"]) if p.get("section_header") else None
    section = ""
    comment = p.get("comment", "#")
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(comment):
            continue
        if header and header.match(line):
            section = "" if re.match(p.get("section_reset", r"^\Z"), line) else " ".join(line.split())
            continue
        m = re.match(r"(\S+?)\s*(?:=\s*|\s+)(.*)$", line) if p.get("equals", False) else re.match(r"(\S+)\s*(.*)$", line)
        if m:
            keep(section, m.group(1), m.group(2).strip(), i)
    return out, lines, dropped
