import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fidelity.config import Config, D, materialize
from fidelity.core import ddmin, fidelity_core


class FakeEv:
    """Verdict = exposed iff directive 'a' present and 'b' absent (a shadowing interaction)."""
    def __init__(self):
        self.runs = 0

    def verdict(self, twin, prop):
        self.runs += 1
        keys = {d.key for d in twin.directives}
        return "a" in keys and "b" not in keys


def cfg(*keys):
    return Config("redis", tuple(D("", k, "x", i) for i, k in enumerate(keys)))


def test_ddmin_finds_single_cause():
    assert ddmin(lambda s: 3 in s, list(range(8))) == [3]


def test_ddmin_pair():
    assert sorted(ddmin(lambda s: 1 in s and 6 in s, list(range(8)))) == [1, 6]


def test_core_exposed_needs_a_only():
    c = cfg("m", "a", "n", "o")
    r = fidelity_core(FakeEv(), c, "vendor", "p", True)
    assert [c.directives[i].key for i in r["core"]] == ["a"]


def test_core_empty_when_base_alone_agrees():
    c = cfg("a", "b", "n")  # not exposed; empty twin is also not exposed
    assert fidelity_core(FakeEv(), c, "vendor", "p", False)["core"] == []


def test_platform_fill_only_open_slots():
    c = Config("redis", (D("", "protected-mode", "no"),))
    assert [d.value for d in materialize(c, "platform").directives] == ["no"]
    assert [d.value for d in materialize(Config("redis", ()), "platform").directives] == ["yes"]


def test_pg_base_rule_appended():
    c = Config("postgresql", (D("hba", "hba", "host all all 0.0.0.0/0 trust"),))
    assert materialize(c, "platform").directives[-1].value.endswith("scram-sha-256")
