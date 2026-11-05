"""Analysis for the generality and tooling experiments: E10 (spec-only
services), E11 (spec engine equivalence), E12 (CI gate on real histories) and
E13 (public files for the spec-only services).  Writes results/summary3.json
and fig-newservices-curve.png; existing summaries and figures are untouched."""
import statistics as st
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from common import RESULTS, dump, load  # noqa: E402

NEW = ["mosquitto", "mongodb", "mariadb"]
PROP = {"mosquitto": "mqtt.anonymous_publish", "mongodb": "mongo.unauth_list", "mariadb": "mariadb.unauth_root"}
LABEL = {"mosquitto": "Mosquitto: anonymous publish", "mongodb": "MongoDB: unauth. listDatabases",
         "mariadb": "MariaDB: passwordless root"}
S = {}


def exists(n):
    return (RESULTS / n).exists()


def reject_cause(wire):
    w = wire.lower()
    for pat, label in (("invalid", "invalid value"), ("unknown", "unknown option"), ("error", "start error"),
                       ("timeout", "not ready"), ("exited", "exited")):
        if pat in w:
            return label
    return "other"


if exists("e11-equivalence.json"):
    rows = load("e11-equivalence.json")
    S["e11"] = {"verdicts": len(rows), "agree": sum(r["agree"] for r in rows),
                "by_service": {s: [sum(r["agree"] for r in rows if r["service"] == s), sum(1 for r in rows if r["service"] == s)]
                               for s in sorted({r["service"] for r in rows})}}

if exists("e12-gate.json"):
    S["e12"] = {k: v for k, v in load("e12-gate.json").items() if k != "introducing_commit_keys"}


def replay(trace, prop, keys, policy):
    vs = [v["verdict"][prop] for v in trace]
    twin, stale, resync, late = vs[0], 0, 0, 0
    for t in range(1, len(vs)):
        rec = trace[t]["edit"]
        changed = rec["kind"] not in ("rejected_by_server", "noop")
        touched = {k[1] for k in rec["keys"]}
        do = {"hash": changed, "oracle": vs[t] != twin}.get(policy, changed and bool(touched & keys))
        if do:
            resync += 1
            twin = vs[t]
        if twin != vs[t]:
            stale += 1
            if vs[t] != vs[t - 1]:
                late += 1
    return resync, stale, len(vs) - 1, late


E10 = {}
curves = {}
for name in NEW:
    if not exists(f"e10-{name}.json"):
        continue
    d = load(f"e10-{name}.json")
    p = PROP[name]
    full = d["full"]
    x = {"candidates": d["candidates"], "accepted": d["accepted"], "rejected": len(d["rejected"]),
         "reject_causes": dict(Counter(reject_cause(r["wire"]) for r in d["rejected"])),
         "reject_examples": [r["wire"][:140] for r in d["rejected"][:4]],
         "exposed": sum(1 for t in d["truth"] if t[p] is True), "n_mean": st.mean(f["n"] for f in full)}
    for b, key in (("V", "core_V"), ("P", "core_P")):
        cs = [f["props"][p][key]["core"] for f in full]
        ok = [c for c in cs if c is not None]
        x[f"core_{b}"] = {"max": max(len(c) for c in ok), "mean": st.mean(len(c) for c in ok),
                          "hist": dict(Counter(len(c) for c in ok)), "conflict": len(cs) - len(ok),
                          "tests_mean": st.mean(f["props"][p][key]["tests"] for f in full if f["props"][p][key]["core"] is not None)}
    piv = sum(len(f["props"][p]["pivots"]) for f in full)
    inc = sum(1 for f in full for i in f["props"][p]["pivots"] if i in (f["props"][p]["core_V"]["core"] or []))
    x["pivots"] = {"total": piv, "in_core": inc,
                   "keys": Counter(f["directives"][i][1] for f in full for i in f["props"][p]["pivots"]).most_common(6)}
    cur = defaultdict(list)
    for f in full:
        for c in f["props"][p]["curve"]:
            cur[(c["base"], c["level"])].append(0.0 if c["agree"] else 1.0)
    x["curve"] = {f"{b}|{lv}": st.mean(v) for (b, lv), v in sorted(cur.items())}
    curves[name] = x["curve"]
    x["guards"] = d["guards"][p]
    gs = defaultdict(list)
    kept = defaultdict(list)
    for r in d["gsync"]:
        for k, v in r.items():
            _, g, base = k.split("|")
            gs[(g, base)].append(1.0 if v["agree"] else 0.0)
            kept[(g, base)].append(v["kept"] / v["n"])
    x["gsync"] = {f"{g}|{b}": {"acc": st.mean(v), "kept": st.mean(kept[(g, b)]), "n": len(v)} for (g, b), v in gs.items()}
    pol = {}
    for name_p, keys in (("hash", None), ("union", set(d["guards"][p]["union"])), ("expert", set(d["guards"][p]["expert"])),
                         ("oracle", None)):
        tot = [replay(tr, p, keys or set(), name_p) for tr in d["drift"]]
        steps = sum(t[2] for t in tot)
        pol[name_p] = {"resync_per100": 100 * sum(t[0] for t in tot) / steps, "stale_pct": 100 * sum(t[1] for t in tot) / steps,
                       "late_flips": sum(t[3] for t in tot)}
    flips = sum(1 for tr in d["drift"] for t in range(1, len(tr)) if tr[t]["verdict"][p] != tr[t - 1]["verdict"][p])
    x["drift"] = {"traces": len(d["drift"]), "edits": sum(len(tr) - 1 for tr in d["drift"]), "flips": flips, "policies": pol}
    E10[name] = x
S["e10"] = E10

if exists("e13-realworld-new.json"):
    d = load("e13-realworld-new.json")
    E13 = {}
    for name, r in d.items():
        p = PROP[name]
        full = r["full"]
        x = {"stats": r["stats"], "accepted": r["accepted"], "rejected": r["rejected"],
             "reject_examples": Counter(w[:90] for w in r["rejected_wire"]).most_common(4),
             "exposed": r["exposed"], "n_mean": st.mean(r["n"]) if r["n"] else 0, "sample": len(full)}
        if full:
            okV = [f["props"][p]["core_V"] for f in full if f["props"][p]["core_V"] is not None]
            x["core_V"] = {"max": max(len(c) for c in okV), "mean": st.mean(len(c) for c in okV), "hist": dict(Counter(len(c) for c in okV))}
            x["conflict_P"] = sum(1 for f in full if f["props"][p]["core_P"] is None)
            x["pivots"] = {"total": sum(len(f["props"][p]["pivots"]) for f in full),
                           "in_core": sum(1 for f in full for i in f["props"][p]["pivots"] if i in (f["props"][p]["core_V"] or [])),
                           "keys": Counter(k for f in full for k in f["props"][p]["pivot_keys"]).most_common(6)}
            x["gsync"] = {g: {"acc": st.mean(1.0 if f["props"][p]["gsync"][g]["agree"] else 0.0 for f in full),
                              "kept": st.mean(f["props"][p]["gsync"][g]["kept"] / f["n"] for f in full)}
                          for g in ("core", "union", "expert")}
        E13[name] = x
    S["e13"] = E13

if curves:
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.2), sharey=True)
    cols = {"mosquitto": "#1baf7a", "mongodb": "#eda100", "mariadb": "#e34948"}
    mk = {"mosquitto": "o", "mongodb": "s", "mariadb": "^"}
    for ax, base, title in zip(axes, ("vendor", "platform"), ("(a) Base V: vendor defaults", "(b) Base P: platform profile")):
        for name, cur in curves.items():
            lv = sorted({float(k.split("|")[1]) for k in cur})
            ax.plot([100 * l for l in lv], [100 * cur[f"{base}|{l}"] for l in lv], color=cols[name], marker=mk[name],
                    ms=3.2, lw=1.2, label=LABEL[name])
        ax.set_title(title, fontsize=8)
        ax.set_xlabel("Directives synchronized at random (%)")
        ax.set_xlim(0, 100)
        ax.set_ylim(bottom=0)
        ax.grid(True, color="#e6e5e0", lw=0.5)
    axes[0].set_ylabel("Verdict error (%)")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=3, fontsize=7, bbox_to_anchor=(0.5, -0.01))
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    fig.savefig(RESULTS / "fig-newservices-curve.png", dpi=300)
    fig2, axes2 = plt.subplots(2, 1, figsize=(3.5, 4.2), sharex=True)
    for ax, base, title in zip(axes2, ("vendor", "platform"), ("(a) Base V: vendor defaults", "(b) Base P: platform profile")):
        for name, cur in curves.items():
            lv = sorted({float(k.split("|")[1]) for k in cur})
            ax.plot([100 * l for l in lv], [100 * cur[f"{base}|{l}"] for l in lv], color=cols[name], marker=mk[name],
                    ms=3, lw=1.1, label=LABEL[name])
        ax.set_title(title, fontsize=8)
        ax.set_ylabel("Verdict error (%)")
        ax.set_ylim(bottom=0)
        ax.grid(True, color="#e6e5e0", lw=0.5)
    axes2[1].set_xlabel("Directives synchronized at random (%)")
    h, l = axes2[0].get_legend_handles_labels()
    fig2.legend(h, l, loc="lower center", ncol=1, fontsize=6.5, bbox_to_anchor=(0.5, 0.0))
    fig2.tight_layout(rect=(0, 0.13, 1, 1))
    fig2.savefig(RESULTS / "fig-newservices-curve-stacked.png", dpi=300)

dump("summary3.json", S)
import json  # noqa: E402
print(json.dumps(S, indent=1, default=str)[:7000])
