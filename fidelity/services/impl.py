"""Renderers and wire probes for Redis, PostgreSQL, Nginx and OpenSSH.

Scaffolding (ports, pid files, data directories, host keys, the static
document tree) is fixed per slot and is never part of a configuration, so it
cannot become a fidelity variable.  Probes use the stock clients (redis-cli,
psql, curl, ssh) and share no code with the renderers or the static analyzers.
"""
from __future__ import annotations

import os
import re
import subprocess

from ..config import Config
from .base import HOST, PASSWORD, Service, sh

PG_BIN = "/usr/lib/postgresql/16/bin"


class Redis(Service):
    name = "redis"
    port_base = 16380
    ready_marker = None  # loglevel is a config variable, so readiness uses a scaffold Unix socket

    def render(self, cfg: Config) -> dict[str, str]:
        lines = [f"port {self.port}", "daemonize no", 'save ""', "appendonly no",
                 f"dir {self.dir}", 'logfile ""', f"unixsocket {self.dir}/ready.sock"]
        lines += [f"{d.key} {d.value}" for d in cfg.directives]
        return {"redis.conf": "\n".join(lines) + "\n"}

    def command(self):
        (self.dir / "ready.sock").unlink(missing_ok=True)
        return ["redis-server", str(self.dir / "redis.conf")]

    def _wait_port(self, proc, deadline):
        import socket as _s, time as _t
        from .base import StartFailure
        path = str(self.dir / "ready.sock")
        while _t.monotonic() < deadline:
            if proc.poll() is not None:
                raise StartFailure("exited")
            try:
                with _s.socket(_s.AF_UNIX) as so:
                    so.settimeout(0.2)
                    so.connect(path)
                    return
            except OSError:
                _t.sleep(0.01)
        raise StartFailure("timeout")

    def probe(self):
        code, out = sh(["redis-cli", "--no-auth-warning", "-h", HOST, "-p", str(self.port),
                        "CONFIG", "GET", "maxmemory"], timeout=4)
        out = out.strip()
        if code == 0 and out.startswith("maxmemory"):
            verdict = True
        elif any(m in out for m in ("NOAUTH", "DENIED", "NOPERM", "unknown command", "Connection refused",
                                    "WRONGPASS", "AUTH failed")):
            verdict = False
        else:
            verdict = "inconclusive"
        return {"redis.unauth_admin": verdict, "_wire": out[:200]}


class Postgres(Service):
    name = "postgresql"
    port_base = 15440
    ready_marker = "database system is ready to accept connections"
    start_timeout = 15.0

    def user(self):
        return "postgres"

    def prepare(self):
        data = self.dir / "data"
        os.system(f"chown -R postgres:postgres {self.dir}")
        if not (data / "PG_VERSION").exists():
            subprocess.run(["runuser", "-u", "postgres", "--", f"{PG_BIN}/initdb", "-D", str(data),
                            "--auth=trust", "-U", "postgres", "--no-sync"], check=True, capture_output=True)
            sock = self.dir
            # bootstrap roles and databases over the Unix socket only
            boot = subprocess.Popen(["runuser", "-u", "postgres", "--", f"{PG_BIN}/postgres", "-D", str(data),
                                     "-c", f"port={self.port}", "-c", "listen_addresses=",
                                     "-c", f"unix_socket_directories={sock}"],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                self._wait_marker(boot, __import__("time").monotonic() + 20)
                sql = (f"CREATE ROLE readers NOLOGIN; CREATE ROLE synthetic LOGIN PASSWORD '{PASSWORD}' IN ROLE readers;"
                       f"CREATE ROLE admin LOGIN PASSWORD '{PASSWORD}'; CREATE DATABASE synthetic OWNER synthetic;"
                       "CREATE DATABASE appdb OWNER admin;")
                for stmt in sql.split(";"):
                    if stmt.strip():
                        subprocess.run(["runuser", "-u", "postgres", "--", "psql", "-h", str(sock), "-p", str(self.port),
                                        "-U", "postgres", "-d", "postgres", "-c", stmt], check=True, capture_output=True)
            finally:
                self.stop(boot)

    def render(self, cfg: Config):
        conf = [f"port = {self.port}", f"unix_socket_directories = '{self.dir}'", "fsync = off",
                "synchronous_commit = off", f"hba_file = '{self.dir}/pg_hba.conf'",
                f"ident_file = '{self.dir}/data/pg_ident.conf'", "logging_collector = off"]
        # Local bootstrap rule: never on the network probe path.
        hba = ["local all postgres trust"]
        for d in cfg.directives:
            if d.key == "hba":
                hba.append(d.value)
            else:
                conf.append(f"{d.key} = {d.value}")
        return {"postgresql.conf": "\n".join(conf) + "\n", "pg_hba.conf": "\n".join(hba) + "\n"}

    def command(self):
        return [f"{PG_BIN}/postgres", "-D", str(self.dir / "data"), "-c", f"config_file={self.dir}/postgresql.conf"]

    def probe(self):
        env = {"PGPASSWORD": "", "PGCONNECT_TIMEOUT": "3", "PGSSLMODE": "prefer", "PGPASSFILE": "/nonexistent/pgpass"}
        code, out = sh(["psql", "-w", "-h", HOST, "-p", str(self.port), "-U", "synthetic", "-d", "synthetic",
                        "-At", "-c", "SELECT 1"], timeout=6, env=env)
        out = out.strip()
        if code == 0 and out == "1":
            verdict = True
        elif any(m in out for m in ("no password supplied", "rejects connection", "no pg_hba.conf entry",
                                    "Connection refused", "password authentication failed", "authentication failed")):
            verdict = False
        else:
            verdict = "inconclusive"
        return {"pg.unauth_sql": verdict, "_wire": out[:200]}


class Nginx(Service):
    name = "nginx"
    port_base = 18080

    def prepare(self):
        www = self.dir / "www"
        (www / "admin").mkdir(parents=True, exist_ok=True)
        (www / "index.html").write_text("public\n")
        (www / "admin" / "index.html").write_text("admin-console\n")
        code, hashed = sh(["openssl", "passwd", "-apr1", PASSWORD])
        (self.dir / "htpasswd").write_text(f"auditor:{hashed.strip()}\n")
        for t in ("body", "proxy", "fastcgi", "uwsgi", "scgi"):
            (self.dir / f"tmp-{t}").mkdir(exist_ok=True)

    def render(self, cfg: Config):
        sec = {"http": [], "server": [], "loc:/": [], "loc:/admin/": []}
        for d in cfg.directives:
            sec[d.section].append(f"{d.key} {d.value};" if d.value else f"{d.key};")
        temps = "".join(f"  {k}_temp_path {self.dir}/tmp-{v};\n" for k, v in
                        (("client_body", "body"), ("proxy", "proxy"), ("fastcgi", "fastcgi"), ("uwsgi", "uwsgi"), ("scgi", "scgi")))
        ind = lambda xs, n: "".join(" " * n + x + "\n" for x in xs)
        text = (f"daemon off;\nmaster_process off;\npid {self.dir}/nginx.pid;\nerror_log {self.dir}/error.log;\n"
                "events { worker_connections 64; }\nhttp {\n  access_log off;\n" + temps +
                f"  auth_basic_user_file {self.dir}/htpasswd;\n" + ind(sec["http"], 2) +
                f"  server {{\n    listen {HOST}:{self.port};\n    root {self.dir}/www;\n" + ind(sec["server"], 4) +
                "    location / {\n" + ind(sec["loc:/"], 6) + "    }\n"
                "    location /admin/ {\n" + ind(sec["loc:/admin/"], 6) + "    }\n  }\n}\n")
        return {"nginx.conf": text}

    def command(self):
        return ["/usr/sbin/nginx", "-p", str(self.dir), "-c", str(self.dir / "nginx.conf")]

    def probe(self):
        base = f"http://{HOST}:{self.port}"
        c1, head = sh(["curl", "--noproxy", "*", "-sS", "-o", "/dev/null", "-D", "-", "--max-time", "3", base + "/"])
        c2, code = sh(["curl", "--noproxy", "*", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "3", base + "/admin/"])
        leak = bool(re.search(r"(?im)^Server:\s*nginx/\d", head)) if c1 == 0 else "inconclusive"
        admin = (code.strip() == "200") if c2 == 0 and code.strip().isdigit() else "inconclusive"
        return {"nginx.version_leak": leak, "nginx.admin_open": admin, "_wire": f"{head[:120]}|{code.strip()}"}


class OpenSSH(Service):
    name = "openssh"
    port_base = 12220
    ready_marker = "Server listening on"

    def prepare(self):
        key = self.dir / "hostkey"
        if not key.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
        os.makedirs("/run/sshd", exist_ok=True)

    def render(self, cfg: Config):
        lines = [f"Port {self.port}", f"ListenAddress {HOST}", f"HostKey {self.dir}/hostkey", "UsePAM no",
                 f"PidFile {self.dir}/sshd.pid", "StrictModes no", "KbdInteractiveAuthentication no"]
        blocks: dict[str, list[str]] = {}
        for d in cfg.directives:
            if d.section:
                blocks.setdefault(d.section, []).append(f"  {d.key} {d.value}")
            else:
                lines.append(f"{d.key} {d.value}")
        for head, body in blocks.items():
            lines.append(head)
            lines += body
        return {"sshd_config": "\n".join(lines) + "\n"}

    def command(self):
        return ["/usr/sbin/sshd", "-D", "-e", "-f", str(self.dir / "sshd_config")]

    def probe(self):
        code, out = sh(["sshpass", "-p", PASSWORD, "ssh", "-F", "/dev/null", "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=3", "-o", "BatchMode=no",
                        "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                        "-o", "NumberOfPasswordPrompts=1", "-o", "LogLevel=ERROR", "-p", str(self.port),
                        f"synthetic@{HOST}", "echo oracle-ok"], timeout=8)
        if code == 0 and "oracle-ok" in out:
            verdict = True
        elif "Permission denied" in out or "Connection closed" in out or "Received disconnect" in out:
            verdict = False
        else:
            verdict = "inconclusive"
        return {"ssh.password_login": verdict, "_wire": out.strip()[:200]}


SERVICE_CLASSES = {"redis": Redis, "postgresql": Postgres, "nginx": Nginx, "openssh": OpenSSH}
