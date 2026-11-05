"""Declarative service adapters.

A service is described by a YAML spec in ``specs/`` instead of Python code:
file templates and line formats (rendering), parse rules (for real files),
runtime (native binary or pinned container image on the host network),
readiness, one-time preparation steps, wire probes with verdict regexes, a
directive catalog (for corpus generation and the expert guard) and base
profiles.  ``SpecService`` executes any such spec with the same lifecycle as
the hand-written adapters, so every analysis in this package (cores, pivots,
fidelity curves, guards, drift) applies to any spec'd service unchanged.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import yaml

from . import formats
from .config import Config, D
from .services.base import HOST, PASSWORD, ROOT, Service, StartFailure, sh

SPECS = Path(__file__).resolve().parent.parent / "specs"


def load_spec(name_or_path: str) -> dict:
    p = Path(name_or_path)
    if not p.exists():
        p = SPECS / f"{name_or_path}.yaml"
    spec = yaml.safe_load(p.read_text())
    spec.setdefault("base_profiles", {})
    return spec


def list_specs() -> list[str]:
    return sorted(p.stem for p in SPECS.glob("*.yaml"))


class SpecService(Service):
    """Run any declaratively specified service."""

    def __init__(self, spec: dict, slot: int, image: str | None = None):
        self.spec = spec
        rt = spec["runtime"]
        self.image = image or rt.get("image")
        self.name = spec["name"] + ("-" + self.image.replace(":", "-").replace("/", "_") if self.image else "")
        self.port_base = rt["port_base"]
        r = rt.get("ready", {"type": "tcp"})
        self.ready_marker = r.get("marker") if r["type"] == "log" else None
        self.start_timeout = float(rt.get("start_timeout", 15))
        super().__init__(slot)
        self.dir = ROOT / f"spec-{self.name}-{slot}"
        self.dir.mkdir(parents=True, exist_ok=True)

    # context used to fill {placeholders} in templates, values, commands and probes
    def ctx(self) -> dict:
        c = {"host": HOST, "port": self.port, "dir": self.dir, "password": PASSWORD, "slot": self.slot}
        c.update({f"port_alt{i}": self.port + 1000 * i for i in range(1, 6)})
        return c

    def cname(self) -> str:
        return f"fids-{self.name}-{self.slot}"[:63]

    def _docker(self, args: list[str], entry: str | None = None, user: str | None = None, name: str | None = None) -> list[str]:
        cmd = ["docker", "run", "--rm", "--network", "host", "-v", f"{self.dir}:{self.dir}", "-w", str(self.dir)]
        if name:
            cmd += ["--name", name]
        if entry:
            cmd += ["--entrypoint", entry]
        if user:
            cmd += ["--user", user]
        return cmd + [self.image] + args

    def _cmd(self, step: dict | list) -> list[str]:
        if isinstance(step, list):
            step = {"cmd": step}
        args = [formats.subst(a, self.ctx()) for a in step["cmd"]]
        if self.image and not step.get("native", False):
            return self._docker(args[1:], entry=args[0], user=step.get("user"))
        return args

    def prepare(self):
        marker = self.dir / ".prepared"
        if marker.exists():
            return
        for f in self.spec.get("prepare", {}).get("files", []):
            (self.dir / f["name"]).write_text(formats.subst(f["content"], self.ctx()))
            if "mode" in f:
                os.chmod(self.dir / f["name"], int(str(f["mode"]), 8))
        for step in self.spec.get("prepare", {}).get("steps", []):
            r = subprocess.run(self._cmd(step), capture_output=True, text=True, timeout=600)
            if r.returncode and not step.get("ignore_errors"):
                raise RuntimeError(f"prepare step failed: {step}: {r.stdout[-400:]} {r.stderr[-400:]}")
        marker.write_text("ok")

    def render(self, cfg: Config) -> dict[str, str]:
        return formats.render(self.spec, cfg, self.ctx())

    def command(self) -> list[str]:
        rt = self.spec["runtime"]
        for p in rt.get("cleanup", []):
            Path(formats.subst(p, self.ctx())).unlink(missing_ok=True)
        args = [formats.subst(a, self.ctx()) for a in rt["command"]]
        if self.image:
            return self._docker(args[1:], entry=args[0], user=rt.get("user"), name=self.cname())
        return args

    def user(self):
        return None if self.image else self.spec["runtime"].get("native_user")

    def _wait_port(self, proc, deadline):
        r = self.spec["runtime"].get("ready", {"type": "tcp"})
        import time
        if r["type"] == "unix":
            import socket
            path = formats.subst(r["path"], self.ctx())
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise StartFailure("exited")
                try:
                    with socket.socket(socket.AF_UNIX) as so:
                        so.settimeout(0.2)
                        so.connect(path)
                        return
                except OSError:
                    time.sleep(0.02)
            raise StartFailure("timeout")
        if r["type"] == "sleep":
            time.sleep(float(r.get("seconds", 1)))
            if proc.poll() is not None:
                raise StartFailure("exited")
            return
        return super()._wait_port(proc, deadline)

    def run(self, cfg: Config):
        if self.image:
            subprocess.run(["docker", "rm", "-f", self.cname()], capture_output=True)
        try:
            return super().run(cfg)
        finally:
            if self.image:
                subprocess.run(["docker", "rm", "-f", self.cname()], capture_output=True)

    def probe(self) -> dict:
        out = {}
        wires = []
        for prop in self.spec["properties"]:
            pr = prop["probe"]
            args = [formats.subst(a, self.ctx()) for a in pr["cmd"]]
            if pr.get("client_image"):
                img = pr["client_image"] if pr["client_image"] is not True else self.image
                args = ["docker", "run", "--rm", "--network", "host", "--entrypoint", args[0], img] + args[1:]
            code, text = sh(args, timeout=float(pr.get("timeout", 8)), env=pr.get("env"))
            text = text.strip()
            exposed = re.search(prop["exposed_if"], text, re.M) and (code == 0 or not prop.get("require_exit_zero", True))
            if exposed:
                v = True
            elif re.search(prop["safe_if"], text, re.M):
                v = False
            else:
                v = "inconclusive"
            out[prop["id"]] = v
            wires.append(text[:120])
        out["_wire"] = " | ".join(wires)
        return out


def properties(spec: dict) -> tuple[str, ...]:
    return tuple(p["id"] for p in spec["properties"])


def base_profile(spec: dict, base: str) -> tuple[D, ...]:
    return tuple(D(e.get("section", ""), e["key"], str(e["value"]), -1 - i, "security")
                 for i, e in enumerate(spec["base_profiles"].get(base, [])))


def materialize(spec: dict, cfg: Config, base: str) -> Config:
    """Spec-aware twin construction (same semantics as config.materialize)."""
    from dataclasses import replace
    array = set(spec.get("array_keys", []))
    profile = base_profile(spec, base)
    taken = {d.slot() for d in cfg.directives}
    extra = tuple(b for b in profile if b.key in array or b.slot() not in taken)
    return replace(cfg, directives=cfg.directives + extra)
