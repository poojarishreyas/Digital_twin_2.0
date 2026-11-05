"""Common lifecycle for a real service instance used as a twin.

Every evaluation starts a fresh server process from rendered files, waits for
it to become ready, runs independent wire probes from a non-loopback client
address, and stops the process.  Nothing is simulated: if the real server
refuses the configuration, the verdict is ``"error"``.
"""
from __future__ import annotations

import os
import select
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

from ..config import Config

HOST = os.environ.get("FIDELITY_HOST", "10.77.0.1")  # non-loopback client/server address
ROOT = Path(os.environ.get("FIDELITY_RUNDIR", "/tmp/fidelity-run"))
PASSWORD = "lab-only-password"  # synthetic lab credential, never a real secret


class StartFailure(Exception):
    pass


class Service:
    name = ""
    port_base = 0
    ready_marker: str | None = None  # log line that signals readiness
    start_timeout = 8.0

    def __init__(self, slot: int):
        self.slot = slot
        self.port = self.port_base + slot
        self.dir = ROOT / f"{self.name}-{slot}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.prepared = False

    # --- to override -----------------------------------------------------
    def prepare(self) -> None:
        """One-time per-slot setup (data directories, keys)."""

    def render(self, cfg: Config) -> dict[str, str]:
        raise NotImplementedError

    def command(self) -> list[str]:
        raise NotImplementedError

    def probe(self) -> dict[str, object]:
        raise NotImplementedError

    def user(self) -> str | None:
        return None

    # --- lifecycle -------------------------------------------------------
    def write(self, files: dict[str, str]) -> None:
        for name, text in files.items():
            path = self.dir / name
            path.write_text(text)
            if self.user():
                shutil.chown(path, self.user())

    def _wait_port(self, proc: subprocess.Popen, deadline: float) -> None:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise StartFailure("exited")
            try:
                with socket.create_connection((HOST, self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.01)
        raise StartFailure("timeout")

    def _wait_marker(self, proc: subprocess.Popen, deadline: float) -> str:
        buf = ""
        fd = proc.stdout.fileno()
        while time.monotonic() < deadline:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                chunk = os.read(fd, 65536).decode(errors="replace")
                if not chunk:
                    raise StartFailure("exited:" + buf[-400:])
                buf += chunk
                if self.ready_marker in buf:
                    return buf
            elif proc.poll() is not None:
                raise StartFailure("exited:" + buf[-400:])
        raise StartFailure("timeout:" + buf[-400:])

    def run(self, cfg: Config) -> dict[str, object]:
        if not self.prepared:
            self.prepare()
            self.prepared = True
        self.write(self.render(cfg))
        cmd = self.command()
        if self.user():
            cmd = ["runuser", "-u", self.user(), "--"] + cmd
        log = open(self.dir / "server.log", "wb") if not self.ready_marker else None
        proc = subprocess.Popen(cmd, stdout=log or subprocess.PIPE, stderr=subprocess.STDOUT,
                                cwd=self.dir, start_new_session=True)
        if log:
            log.close()
        try:
            deadline = time.monotonic() + self.start_timeout
            try:
                if self.ready_marker:
                    self._wait_marker(proc, deadline)
                else:
                    self._wait_port(proc, deadline)
            except StartFailure as exc:
                detail = str(exc)
                if not self.ready_marker:
                    detail += ":" + (self.dir / "server.log").read_text(errors="replace")[-300:]
                return {"_start": "failed", "_detail": detail[:400]}
            out = self.probe()
            out["_start"] = "ok"
            return out
        finally:
            self.stop(proc)

    def stop(self, proc: subprocess.Popen) -> None:
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGINT if self.name == "postgresql" else signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        if proc.stdout:
            proc.stdout.close()


def sh(cmd: list[str], timeout: float = 6.0, env: dict | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, **(env or {})})
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
