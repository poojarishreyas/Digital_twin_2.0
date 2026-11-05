"""Version-pinned twins: the same renderers and wire probes as impl.py, but the
server binary comes from a pinned container image.

Containers use the host network namespace, so the server binds exactly the
addresses a native server would (10.77.0.1:<slot port>) and the probe client
on the host is seen with the same source address.  The slot directory is
bind-mounted at the same path, so rendered absolute paths stay valid.
"""
from __future__ import annotations

import os
import subprocess
import time

from .base import PASSWORD, StartFailure
from .impl import Nginx, OpenSSH, Postgres, Redis

IMAGES = {
    "redis": ["redis:6.0", "redis:6.2", "redis:7.0", "redis:7.2", "redis:7.4"],
    "postgresql": ["postgres:12", "postgres:14", "postgres:16", "postgres:17"],
    "nginx": ["nginx:1.20", "nginx:1.24", "nginx:1.27"],
    "openssh": ["fidelity-sshd:8.8_p1-r1", "fidelity-sshd:9.3_p2-r1", "fidelity-sshd:9.7_p1-r4", "fidelity-sshd:10.0_p1-r10"],
}


class DockerMixin:
    image = ""
    entry = ""
    run_user: str | None = None

    def cname(self):
        return f"fid-{self.name}-{self.slot}"

    def user(self):  # files are read by the container user; no runuser wrapping
        return None

    def docker(self, args: list[str]) -> list[str]:
        cmd = ["docker", "run", "--rm", "--name", self.cname(), "--network", "host",
               "-v", f"{self.dir}:{self.dir}", "-w", str(self.dir), "--entrypoint", self.entry]
        if self.run_user:
            cmd += ["--user", self.run_user]
        return cmd + [self.image] + args

    def run(self, cfg):
        subprocess.run(["docker", "rm", "-f", self.cname()], capture_output=True)
        try:
            return super().run(cfg)
        finally:
            subprocess.run(["docker", "rm", "-f", self.cname()], capture_output=True)


class VRedis(DockerMixin, Redis):
    entry = "redis-server"
    start_timeout = 15.0

    def command(self):
        (self.dir / "ready.sock").unlink(missing_ok=True)
        return self.docker([str(self.dir / "redis.conf")])


class VNginx(DockerMixin, Nginx):
    entry = "nginx"
    start_timeout = 15.0

    def command(self):
        return self.docker(["-p", str(self.dir), "-c", str(self.dir / "nginx.conf")])


class VOpenSSH(DockerMixin, OpenSSH):
    entry = "/usr/sbin/sshd.pam"
    start_timeout = 15.0

    def render(self, cfg):
        files = super().render(cfg)
        # KbdInteractiveAuthentication is spelled ChallengeResponseAuthentication before 8.7;
        # with UsePAM no neither can authenticate, so the scaffold line is dropped.
        files["sshd_config"] = files["sshd_config"].replace("KbdInteractiveAuthentication no\n", "")
        return files

    def command(self):
        return self.docker(["-D", "-e", "-f", str(self.dir / "sshd_config")])


class VPostgres(DockerMixin, Postgres):
    entry = "postgres"
    run_user = "999:999"
    start_timeout = 30.0

    @property
    def datadir(self):
        return self.dir / f"data-{self.image.replace(':', '-')}"

    def prepare(self):
        os.makedirs(self.datadir, exist_ok=True)
        os.chown(self.dir, 999, 999)
        os.chown(self.datadir, 999, 999)
        if (self.datadir / "PG_VERSION").exists():
            return
        subprocess.run(["docker", "run", "--rm", "--network", "host", "-v", f"{self.dir}:{self.dir}", "--user", "999:999",
                        "--entrypoint", "initdb", self.image, "-D", str(self.datadir), "--auth=trust", "-U", "postgres"],
                       check=True, capture_output=True)
        boot = subprocess.Popen(["docker", "run", "--rm", "--name", self.cname(), "--network", "host", "-v",
                                 f"{self.dir}:{self.dir}", "--user", "999:999", "--entrypoint", "postgres", self.image,
                                 "-D", str(self.datadir), "-c", f"port={self.port}", "-c", "listen_addresses=",
                                 "-c", f"unix_socket_directories={self.dir}"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            self._wait_marker(boot, time.monotonic() + 60)
            sql = (f"CREATE ROLE readers NOLOGIN; CREATE ROLE synthetic LOGIN PASSWORD '{PASSWORD}' IN ROLE readers;"
                   f"CREATE ROLE admin LOGIN PASSWORD '{PASSWORD}'; CREATE DATABASE synthetic OWNER synthetic;"
                   "CREATE DATABASE appdb OWNER admin;")
            for stmt in sql.split(";"):
                if stmt.strip():
                    subprocess.run(["psql", "-h", str(self.dir), "-p", str(self.port), "-U", "postgres", "-d", "postgres",
                                    "-c", stmt], check=True, capture_output=True)
        finally:
            subprocess.run(["docker", "rm", "-f", self.cname()], capture_output=True)
            boot.wait()
            boot.stdout.close()

    def command(self):
        return self.docker(["-D", str(self.datadir), "-c", f"config_file={self.dir}/postgresql.conf"])

    def stop(self, proc):
        subprocess.run(["docker", "stop", "-t", "5", self.cname()], capture_output=True)
        super().stop(proc)


CLASSES = {"redis": VRedis, "postgresql": VPostgres, "nginx": VNginx, "openssh": VOpenSSH}


def make(service: str, image: str, slot: int):
    cls = CLASSES[service]
    obj = cls.__new__(cls)
    obj.image = image
    tag = image.split(":")[-1].replace(".", "")
    obj.name = f"{service}-{tag}"
    obj.slot = slot
    obj.port = cls.port_base + slot
    obj.dir = (__import__("pathlib").Path(os.environ.get("FIDELITY_RUNDIR", "/tmp/fidelity-run")) / f"v-{obj.name}-{slot}")
    obj.dir.mkdir(parents=True, exist_ok=True)
    obj.prepared = False
    return obj
