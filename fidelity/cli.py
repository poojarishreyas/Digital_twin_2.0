"""fidelity: verdict-relative analysis of real service configurations.

    python3 -m fidelity.cli specs
    python3 -m fidelity.cli analyze  SERVICE FILE [--image IMG] [--json F] [--md F] [--sarif F]
    python3 -m fidelity.cli export   SERVICE FILE [--guard-file G]
    python3 -m fidelity.cli fingerprint SERVICE [--images native IMG ...]
    python3 -m fidelity.cli gate     SERVICE OLD NEW [--guard-file G] [--sarif F]

Every verdict comes from a real server (native binary or pinned image) started
in an isolated twin and probed over the wire.  Secrets are replaced by a
synthetic password before anything runs; files are never modified.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import formats, redact
from .config import Config, D
from .core import fidelity_core
from .spec import SpecService, list_specs, load_spec, materialize, properties

SLOT = 7  # ports and directories distinct from the experiment slots


class _Ev:
    """In-process evaluator with a verdict cache (same interface as the harness)."""

    def __init__(self, spec: dict, image: str | None):
        self.spec, self.svc, self.cache, self.runs = spec, SpecService(spec, SLOT, image), {}, 0

    def raw(self, twin: Config) -> dict:
        k = twin.canonical()
        if k not in self.cache:
            props = properties(self.spec)
            out = self.svc.run(twin)
            if any(out.get(p) == "inconclusive" for p in props):
                out = self.svc.run(twin)
            self.runs += 1
            self.cache[k] = {**{p: ("error" if out.get("_start") != "ok" else out.get(p)) for p in props},
                             "_wire": str(out.get("_wire", out.get("_detail", "")))[:300]}
        return self.cache[k]

    def verdict(self, twin: Config, prop: str):
        return self.raw(twin)[prop]


def load_config(spec: dict, path: str) -> tuple[Config, list[int]]:
    text = Path(path).read_text(errors="replace")
    ds, lines, dropped = formats.parse(spec, text)
    ds = redact.normalize(spec, ds)
    cfg = Config(spec["name"], tuple(D(s, k, v, i + 1, _cls(spec, k)) for i, (s, k, v) in enumerate(ds)), Path(path).name)
    return cfg, lines


def _cls(spec, key):
    for e in spec.get("catalog", []):
        if e["key"].lower() == key.lower():
            return e["class"]
    return "operational"


def expert_keys(spec: dict) -> set[str]:
    return {e["key"].lower() for e in spec.get("catalog", []) if e["class"] == "security"}


def guard_keys(spec: dict, guard_file: str | None) -> dict[str, set[str]]:
    base = expert_keys(spec)
    learned = json.loads(Path(guard_file).read_text()) if guard_file else {}
    return {p: base | {k.lower() for k in learned.get(p, [])} for p in properties(spec)}


# ----------------------------------------------------------------------- analyze
def analyze(spec: dict, path: str, image: str | None) -> dict:
    cfg, lines = load_config(spec, path)
    ev = _Ev(spec, image)
    mat = lambda c, b: materialize(spec, c, b)  # noqa: E731
    src = ev.raw(mat(cfg, "vendor"))
    report = {"service": spec["name"], "file": path, "build": image or spec["runtime"].get("image", "native"),
              "directives": len(cfg), "properties": {}}
    if any(src[p] not in (True, False) for p in properties(spec)):
        report["error"] = "the server did not start with this configuration (or no conclusive verdict)"
        report["server_output"] = src["_wire"]
        return report
    for prop in properties(spec):
        v = src[prop]
        core = fidelity_core(ev, cfg, "vendor", prop, v, mat=mat)
        piv = []
        for i in range(len(cfg)):
            keep = [j for j in range(len(cfg)) if j != i]
            if ev.verdict(mat(cfg.subset(keep), "vendor"), prop) != v:
                piv.append(i)
        def item(i):
            d = cfg.directives[i]
            return {"line": lines[i], "section": d.section, "key": d.key, "value": d.value}
        desc = next(p.get("description", p["id"]) for p in spec["properties"] if p["id"] == prop)
        sec_keys = expert_keys(spec)
        inert = [item(i) for i, d in enumerate(cfg.directives)
                 if d.key.lower() in sec_keys and i not in piv and i not in (core["core"] or [])]
        absent = sorted(k for k in sec_keys if k not in {d.key.lower() for d in cfg.directives})
        report["properties"][prop] = {
            "question": desc, "exposed": v,
            "core": [item(i) for i in (core["core"] or [])],
            "pivots": [dict(item(i), role="enables exposure: removing it removes the exposure" if v else
                            "protects: removing it would expose the service") for i in piv],
            "inert_security_directives": inert,
            "unset_guard_keys": absent,
        }
    report["server_runs"] = ev.runs
    return report


def to_markdown(r: dict) -> str:
    out = [f"# {r['service']}: `{r['file']}` ({r['build']})", ""]
    if "error" in r:
        return "\n".join(out + [f"**{r['error']}**", "", "```", r["server_output"], "```"])
    for prop, x in r["properties"].items():
        out.append(f"## {prop}: {'EXPOSED' if x['exposed'] else 'not exposed'}")
        out.append(f"*{x['question']}*\n")
        out.append("**Minimal explanation (core):** " + (", ".join(f"line {i['line']} `{i['key']} {i['value']}`" for i in x["core"])
                   or "none needed: the server default already gives this verdict"))
        out.append("")
        if x["pivots"]:
            out.append("**Pivots:**")
            out += [f"- line {i['line']} `{i['key']} {i['value']}`: {i['role']}" for i in x["pivots"]]
        else:
            out.append("**Pivots:** none (no single line decides this verdict)")
        if x["inert_security_directives"]:
            out.append("\n**Security-labelled lines with no effect on this verdict:** " +
                       ", ".join(f"line {i['line']} `{i['key']}`" for i in x["inert_security_directives"]))
        if x["unset_guard_keys"]:
            out.append("\n**Relies on server defaults for:** " + ", ".join(f"`{k}`" for k in x["unset_guard_keys"]))
        out.append("")
    out.append(f"_{r.get('server_runs', 0)} twin executions._")
    return "\n".join(out)


def to_sarif(results: list[dict]) -> dict:
    """SARIF 2.1.0 for GitHub code scanning: one result per exposure, located at
    the pivot lines that enable it."""
    res = []
    for r in results:
        for prop, x in r.get("properties", {}).items():
            if not x["exposed"]:
                continue
            locs = [{"physicalLocation": {"artifactLocation": {"uri": r["file"]},
                                          "region": {"startLine": max(1, p["line"])}}} for p in x["pivots"]] or \
                   [{"physicalLocation": {"artifactLocation": {"uri": r["file"]}, "region": {"startLine": 1}}}]
            res.append({"ruleId": prop, "level": "error",
                        "message": {"text": f"{x['question']} (verified on a real {r['service']} twin, build {r['build']}). "
                                            "Removing or changing a highlighted line removes the exposure."},
                        "locations": locs})
    rules = sorted({x["ruleId"] for x in res})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "fidelity", "informationUri": "https://github.com/poojarishreyas/Digital_twin_2.0",
                                          "rules": [{"id": i, "shortDescription": {"text": i}} for i in rules]}},
                      "results": res}]}


# ----------------------------------------------------------------------- export
def export(spec: dict, path: str, guard_file: str | None) -> dict:
    cfg, lines = load_config(spec, path)
    keys = set().union(*guard_keys(spec, guard_file).values())
    kept = [d for d in cfg.directives if d.key.lower() in keys]
    present = {d.key.lower() for d in kept}
    return {"service": spec["name"], "exported": [[d.section, d.key, d.value] for d in kept],
            "unset": sorted(keys - present), "exported_share": round(len(kept) / max(1, len(cfg)), 3),
            "note": "values are normalized and redacted; 'unset' keys must fall back to the server default in the twin"}


# ----------------------------------------------------------------------- fingerprint
def fingerprint(spec: dict, images: list[str]) -> dict:
    """Default security behavior of each build: the verdicts of the empty
    configuration and of every single catalog security directive."""
    probes = [("(empty configuration)", Config(spec["name"], ()))]
    for e in spec.get("catalog", []):
        if e["class"] == "security":
            for v in e["values"]:
                probes.append((f"{e['key']} {v}".strip(), Config(spec["name"], (D(e.get("section", ""), e["key"], str(v)),))))
    table = {}
    for img in images:
        ev = _Ev(spec, None if img == "native" else img)
        table[img] = {label: {p: ev.verdict(materialize(spec, c, "vendor"), p) for p in properties(spec)} for label, c in probes}
    diffs = []
    if len(images) > 1:
        for label, _ in probes:
            vals = {img: table[img][label] for img in images}
            if len({json.dumps(v, sort_keys=True) for v in vals.values()}) > 1:
                diffs.append({"probe": label, "verdicts": vals})
    return {"service": spec["name"], "builds": images, "table": table, "differences": diffs}


# ----------------------------------------------------------------------- gate
def gate(spec: dict, old: str, new: str, guard_file: str | None, image: str | None) -> tuple[dict, int]:
    """Decide whether a change needs re-emulation (key guard) and, if so,
    whether it introduces an exposure.  Exit code 1 = exposure introduced."""
    a, _ = load_config(spec, old)
    b, lines_b = load_config(spec, new)
    ta = Counter((d.section, d.key, d.value) for d in a.directives)
    tb = Counter((d.section, d.key, d.value) for d in b.directives)
    touched = {k for _, k, _ in (ta - tb) + (tb - ta)}
    if not touched and [(d.section, d.key, d.value) for d in a.directives] != [(d.section, d.key, d.value) for d in b.directives]:
        touched = {d.key for d in b.directives}  # pure reordering
    guards = guard_keys(spec, guard_file)
    out = {"service": spec["name"], "old": old, "new": new, "touched_keys": sorted(touched), "properties": {}}
    hit = {p: sorted(k for k in touched if k.lower() in g) for p, g in guards.items()}
    if not any(hit.values()):
        out["decision"] = "skip: no guarded key changed, the previous verdict stands"
        return out, 0
    ev = _Ev(spec, image)
    va, vb = ev.raw(materialize(spec, a, "vendor")), ev.raw(materialize(spec, b, "vendor"))
    worst = 0
    for p in properties(spec):
        before, after = va[p], vb[p]
        status = "unchanged"
        if after is True and before is not True:
            status, worst = "EXPOSURE INTRODUCED", 1
        elif before is True and after is False:
            status = "exposure removed"
        elif after not in (True, False):
            status, worst = "server rejects the new configuration", max(worst, 1)
        out["properties"][p] = {"before": before, "after": after, "status": status, "guarded_keys_changed": hit[p]}
    out["decision"] = "re-emulated"
    out["server_runs"] = ev.runs
    return out, worst


def main(argv=None):
    ap = argparse.ArgumentParser(prog="fidelity", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("specs", help="list declared services and their properties")
    a = sub.add_parser("analyze", help="verdicts, core, pivots for a real configuration file")
    a.add_argument("service"); a.add_argument("file"); a.add_argument("--image")
    a.add_argument("--json"); a.add_argument("--md"); a.add_argument("--sarif")
    e = sub.add_parser("export", help="minimal guard-key export with unset markers")
    e.add_argument("service"); e.add_argument("file"); e.add_argument("--guard-file")
    f = sub.add_parser("fingerprint", help="compare default security behavior of builds")
    f.add_argument("service"); f.add_argument("--images", nargs="+", default=["native"])
    g = sub.add_parser("gate", help="CI gate for a configuration change")
    g.add_argument("service"); g.add_argument("old"); g.add_argument("new")
    g.add_argument("--guard-file"); g.add_argument("--image"); g.add_argument("--sarif")
    args = ap.parse_args(argv)
    if args.cmd == "specs":
        for name in list_specs():
            s = load_spec(name)
            print(f"{name:12s} {', '.join(p['id'] for p in s['properties'])}  "
                  f"[{s['runtime'].get('image', 'native')}; parser: {s.get('parse', {}).get('kind', 'none')}]")
        return 0
    spec = load_spec(args.service)
    if args.cmd == "analyze":
        r = analyze(spec, args.file, args.image)
        if args.json:
            Path(args.json).write_text(json.dumps(r, indent=2, default=str))
        if args.sarif:
            Path(args.sarif).write_text(json.dumps(to_sarif([r]), indent=2))
        md = to_markdown(r)
        if args.md:
            Path(args.md).write_text(md)
        print(md)
        return 2 if "error" in r else (1 if any(x["exposed"] for x in r["properties"].values()) else 0)
    if args.cmd == "export":
        print(json.dumps(export(spec, args.file, args.guard_file), indent=2))
        return 0
    if args.cmd == "fingerprint":
        r = fingerprint(spec, args.images)
        print(json.dumps(r, indent=2, default=str))
        return 0
    r, code = gate(spec, args.old, args.new, args.guard_file, args.image)
    if args.sarif and code:
        b = analyze(spec, args.new, args.image)
        Path(args.sarif).write_text(json.dumps(to_sarif([b]), indent=2))
    print(json.dumps(r, indent=2, default=str))
    return code


if __name__ == "__main__":
    sys.exit(main())
