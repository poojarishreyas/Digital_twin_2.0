import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fidelity import formats, redact
from fidelity.config import Config, D
from fidelity.spec import list_specs, load_spec, materialize

CTX = {"host": "10.77.0.1", "port": 1234, "dir": "/tmp/x", "password": "pw", "slot": 0}


def test_all_specs_load_and_declare_properties():
    names = list_specs()
    assert {"redis", "postgresql", "nginx", "openssh", "mosquitto", "mongodb", "mariadb"} <= set(names)
    for n in names:
        s = load_spec(n)
        assert s["properties"] and all("exposed_if" in p and "safe_if" in p for p in s["properties"])


def test_lines_render_with_dynamic_match_blocks():
    s = load_spec("openssh")
    cfg = Config("openssh", (D("", "PasswordAuthentication", "no"), D("Match User synthetic", "PasswordAuthentication", "yes"),
                             D("", "X11Forwarding", "no")))
    text = formats.render(s, cfg, CTX)["sshd_config"]
    assert text.index("X11Forwarding no") < text.index("Match User synthetic")  # globals before Match blocks
    assert "  PasswordAuthentication yes" in text


def test_ini_flags_and_yaml_nesting():
    m = formats.render(load_spec("mariadb"), Config("mariadb", (D("mysqld", "skip-grant-tables", ""), D("mysqld", "bind-address", "{host}"))), CTX)["my.cnf"]
    assert "\nskip-grant-tables\n" in m and "bind-address = 10.77.0.1" in m
    y = formats.render(load_spec("mongodb"), Config("mongodb", (D("", "security.authorization", "enabled"), D("", "net.bindIp", "0.0.0.0"))), CTX)["mongod.conf"]
    assert "authorization: enabled" in y and "port: 1234" in y and "bindIp: 0.0.0.0" in y


def test_nginx_blocks_and_pg_rules():
    n = formats.render(load_spec("nginx"), Config("nginx", (D("loc:/admin/", "internal", ""), D("http", "server_tokens", "off"))), CTX)["nginx.conf"]
    assert "internal;" in n and "server_tokens off;" in n
    pg = load_spec("postgresql")
    ds, lines, _ = formats.parse(pg, "# c\nhost all all 10.0.0.0/8 trust\nlocal all all peer\n")
    assert ds[0] == ("conf", "listen_addresses", "'*'") and ds[1][2] == "host all all 10.0.0.0/8 trust" and lines[1] == 2


def test_parse_drops_environment_and_redacts():
    r = load_spec("redis")
    ds, lines, dropped = formats.parse(r, "port 6379\nbind 192.168.1.5 127.0.0.1\nrequirepass hunter2\nuser default on >x ~* +@all\n")
    assert dropped == {"port": 1}
    norm = redact.normalize(r, ds)
    assert ("", "bind", "{host} 127.0.0.1") in norm and ("", "requirepass", "{password}") in norm
    assert "hunter2" not in str(norm) and ">x" not in str(norm)
    assert redact.normalize(r, [("", "x", "postgres://u:secretpw@db/x")])[0][2] == "postgres://REDACTED"


def test_mosquitto_listeners_get_distinct_ports():
    m = load_spec("mosquitto")
    ds = redact.normalize(m, formats.parse(m, "listener 1883\nlistener 8883 10.1.2.3\n")[0])
    assert ds == [("", "listener", "{port}"), ("", "listener", "{port_alt1} {host}")]


def test_spec_materialize_fills_only_open_slots():
    s = load_spec("mosquitto")
    assert [d.value for d in materialize(s, Config("mosquitto", ()), "platform").directives] == ["false"]
    assert [d.value for d in materialize(s, Config("mosquitto", (D("", "allow_anonymous", "true"),)), "platform").directives] == ["true"]
