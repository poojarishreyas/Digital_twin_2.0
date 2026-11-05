"""Summaries, tables and figures for the paper.  Reads results/*.json only."""
import json
import random
import sqlite3
import statistics as st
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from common import PROPERTIES, RESULTS, dump, load, load_corpus, split  # noqa: E402
from fidelity.config import Config, D  # noqa: E402
from fidelity.static import careful, naive  # noqa: E402

PROPS = ["redis.unauth_admin", "pg.unauth_sql", "nginx.version_leak", "nginx.admin_open", "ssh.password_login"]
LABEL = {"redis.unauth_admin": "Redis: unauth. admin cmd", "pg.unauth_sql": "PostgreSQL: passwordless SQL",
         "nginx.version_leak": "Nginx: version disclosure", "nginx.admin_open": "Nginx: /admin/ reachable",
         "ssh.password_login": "OpenSSH: password login"}
COLORS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#6250d6"]
MARKERS = ["o", "s", "^", "D", "v"]
STYLES = ["-", "--", "-.", ":", (0, (5, 1, 1, 1))]
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.linewidth": 0.6, "axes.edgecolor": "#52514e",
                     "xtick.color": "#52514e", "ytick.color": "#52514e", "axes.labelcolor": "#0b0b0b",
                     "legend.frameon": False, "savefig.dpi": 300, "axes.grid": True, "grid.color": "#e6e5e0",
                     "grid.linewidth": 0.5, "axes.spines.top": False, "axes.spines.right": False})
S = {}


def boot_ci(groups, B=2000, seed=1):
    """Cluster bootstrap over configurations: groups = list of per-config means."""
    r = random.Random(seed)
    n = len(groups)
    ms = sorted(st.mean(r.choice(groups) for _ in range(n)) for _ in range(B))
    return ms[int(0.025 * B)], ms[int(0.975 * B)]


# ----------------------------------------------------------------- E0
truth_rows = load("e0-truth.json")
S["corpus"] = {p: {"configs": sum(1 for r in truth_rows if r["prop"] == p),
                   "exposed": sum(1 for r in truth_rows if r["prop"] == p and r["verdict"] is True),
                   "mean_n": st.mean(r["n"] for r in truth_rows if r["prop"] == p),
                   "min_n": min(r["n"] for r in truth_rows if r["prop"] == p),
                   "max_n": max(r["n"] for r in truth_rows if r["prop"] == p)} for p in PROPS}
S["rejected_sources"] = load("e0-rejected.json")
con = sqlite3.connect(RESULTS / "verdict-cache.sqlite")
secs = defaultdict(list)
for k, s in con.execute("SELECT k, secs FROM v"):
    secs[json.loads(k)[0]].append(s)
S["server_runs"] = {svc: {"runs": len(v), "median_s": st.median(v), "p95_s": sorted(v)[int(0.95 * len(v))]}
                    for svc, v in secs.items()}
S["server_runs_total"] = sum(len(v) for v in secs.values())

# ----------------------------------------------------------------- E1
curve = load("e1-curve.json")
levels = sorted({r["level"] for r in curve})
E1 = {}
for base in ("vendor", "platform"):
    for p in PROPS + ["all"]:
        for lv in levels:
            rows = [r for r in curve if r["base"] == base and r["level"] == lv and (p == "all" or r["prop"] == p)]
            per = defaultdict(list)
            for r in rows:
                per[(r["cid"], r["prop"])].append(0.0 if r["agree"] else 1.0)
            g = [st.mean(v) for v in per.values()]
            lo, hi = boot_ci(g)
            fs = sum(1 for r in rows if r["truth"] is True and r["verdict"] is False)
            fa = sum(1 for r in rows if r["truth"] is False and r["verdict"] is True)
            er = sum(1 for r in rows if r["verdict"] not in (True, False))
            E1[f"{base}|{p}|{lv}"] = {"error": st.mean(g), "ci": [lo, hi], "runs": len(rows),
                                     "false_safe": fs / len(rows), "false_alarm": fa / len(rows), "start_error": er / len(rows)}
S["e1"] = E1

fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.35), sharey=True)
for ax, base, title in zip(axes, ("vendor", "platform"), ("(a) Base profile V: vendor defaults", "(b) Base profile P: platform default twin")):
    for i, p in enumerate(PROPS):
        ys = [100 * E1[f"{base}|{p}|{lv}"]["error"] for lv in levels]
        ax.plot([100 * l for l in levels], ys, color=COLORS[i], marker=MARKERS[i], ms=3.2, lw=1.2, ls=STYLES[i], label=LABEL[p])
    ys = [100 * E1[f"{base}|all|{lv}"]["error"] for lv in levels]
    lo = [100 * E1[f"{base}|all|{lv}"]["ci"][0] for lv in levels]
    hi = [100 * E1[f"{base}|all|{lv}"]["ci"][1] for lv in levels]
    ax.fill_between([100 * l for l in levels], lo, hi, color="#0b0b0b", alpha=0.10, lw=0)
    ax.plot([100 * l for l in levels], ys, color="#0b0b0b", lw=1.8, label="All properties (95% CI)")
    ax.set_title(title, fontsize=8)
    ax.set_xlabel("Directives synchronized at random (%)")
    ax.set_xlim(0, 100)
axes[0].set_ylabel("Verdict error (%)")
axes[0].set_ylim(bottom=0)
h, l = axes[0].get_legend_handles_labels()
fig.legend(h, l, loc="lower center", ncol=3, fontsize=7, bbox_to_anchor=(0.5, -0.02))
fig.tight_layout(rect=(0, 0.17, 1, 1))
fig.savefig(RESULTS / "fig-fidelity-curve.png")
plt.close(fig)

# single-column stacked variant (used by the Word build)
fig, axes = plt.subplots(2, 1, figsize=(3.5, 4.6), sharex=True)
for ax, base, title in zip(axes, ("vendor", "platform"), ("(a) Base profile V: vendor defaults", "(b) Base profile P: platform default twin")):
    for i, p in enumerate(PROPS):
        ys = [100 * E1[f"{base}|{p}|{lv}"]["error"] for lv in levels]
        ax.plot([100 * l for l in levels], ys, color=COLORS[i], marker=MARKERS[i], ms=3, lw=1.1, ls=STYLES[i], label=LABEL[p])
    ys = [100 * E1[f"{base}|all|{lv}"]["error"] for lv in levels]
    lo = [100 * E1[f"{base}|all|{lv}"]["ci"][0] for lv in levels]
    hi = [100 * E1[f"{base}|all|{lv}"]["ci"][1] for lv in levels]
    ax.fill_between([100 * l for l in levels], lo, hi, color="#0b0b0b", alpha=0.10, lw=0)
    ax.plot([100 * l for l in levels], ys, color="#0b0b0b", lw=1.7, label="All properties (95% CI)")
    ax.set_title(title, fontsize=8)
    ax.set_ylabel("Verdict error (%)")
    ax.set_xlim(0, 100)
    ax.set_ylim(bottom=0)
axes[1].set_xlabel("Directives synchronized at random (%)")
h, l = axes[0].get_legend_handles_labels()
fig.legend(h, l, loc="lower center", ncol=2, fontsize=6.5, bbox_to_anchor=(0.5, 0.0))
fig.tight_layout(rect=(0, 0.13, 1, 1))
fig.savefig(RESULTS / "fig-fidelity-curve-stacked.png")
plt.close(fig)

# ----------------------------------------------------------------- E2
cores = load("e2-cores.json")
cfgs = {c.cid: c for c in load_corpus()}
E2 = {}
keyfreq = defaultdict(Counter)
for p in PROPS:
    for base in ("vendor", "platform"):
        sizes, fracs, tests, runs, empty, conflict, shadow = [], [], [], [], 0, 0, []
        for r in cores:
            k = f"{p}|{base}"
            if k not in r["cores"]:
                continue
            c = r["cores"][k]
            if c["core"] is None:
                conflict += 1
                continue
            sizes.append(len(c["core"]))
            fracs.append(len(c["core"]) / r["n"])
            tests.append(c["tests"])
            runs.append(c["server_runs"])
            empty += (len(c["core"]) == 0)
            for i in c["core"]:
                keyfreq[f"{p}|{base}"][r["directives"][i][1]] += 1
            # security-labelled directives that are NOT in the core ("inert security directives")
            sec = [i for i, d in enumerate(r["directives"]) if d[3] == "security"]
            if sec:
                shadow.append(sum(1 for i in sec if i not in c["core"]) / len(sec))
        E2[f"{p}|{base}"] = {"configs": len(sizes) + conflict, "base_conflict": conflict, "mean_core": st.mean(sizes),
                             "median_core": st.median(sizes), "max_core": max(sizes), "mean_frac": st.mean(fracs),
                             "empty_core": empty, "size_hist": dict(Counter(sizes)), "mean_tests": st.mean(tests),
                             "max_tests": max(tests), "inert_security_share": st.mean(shadow) if shadow else None,
                             "top_keys": keyfreq[f"{p}|{base}"].most_common(6)}
# removal sensitivity vs core
rem = {}
for p in PROPS:
    crit, crit_in_core, ncrit, ndir = 0, 0, [], 0
    for r in cores:
        if p not in r["removal"]:
            continue
        flips = r["removal"][p]
        core = r["cores"][f"{p}|vendor"]["core"] or []
        ncrit.append(sum(flips))
        ndir += len(flips)
        crit += sum(flips)
        crit_in_core += sum(1 for i, f in enumerate(flips) if f and i in core)
    rem[p] = {"critical_directives": crit, "critical_in_core": crit_in_core, "mean_critical_per_config": st.mean(ncrit),
              "share_critical": crit / ndir, "configs_with_no_critical": sum(1 for x in ncrit if x == 0)}
E2["_removal"] = rem
all_v = [len(r["cores"][f"{p}|vendor"]["core"]) for r in cores for p in PROPERTIES[r["service"]]
         if r["cores"][f"{p}|vendor"]["core"] is not None]
all_f = [len(r["cores"][f"{p}|vendor"]["core"]) / r["n"] for r in cores for p in PROPERTIES[r["service"]]
         if r["cores"][f"{p}|vendor"]["core"] is not None]
E2["_overall_vendor"] = {"mean_core": st.mean(all_v), "median": st.median(all_v), "mean_frac": st.mean(all_f),
                         "le2": sum(1 for x in all_v if x <= 2) / len(all_v), "pairs": len(all_v),
                         "mean_n": st.mean(r["n"] for r in cores)}
all_p = [len(r["cores"][f"{p}|platform"]["core"]) for r in cores for p in PROPERTIES[r["service"]]
         if r["cores"][f"{p}|platform"]["core"] is not None]
E2["_overall_platform"] = {"mean_core": st.mean(all_p), "median": st.median(all_p),
                           "le2": sum(1 for x in all_p if x <= 2) / len(all_p), "pairs": len(all_p)}
S["e2"] = E2

fig, ax = plt.subplots(figsize=(3.5, 2.5))
rows_lbl, ypos = [], []
SIZE_COL = {0: "#c9c8c2", 1: "#2a78d6", 2: "#eb6834", "x": "#52514e"}
y = 0
for p in PROPS:
    for base, tag in (("vendor", "V"), ("platform", "P")):
        e = E2[f"{p}|{base}"]
        h = {int(k): v for k, v in e["size_hist"].items()}
        tot = e["configs"]
        left = 0
        for k in (0, 1, 2):
            w = 100 * h.get(k, 0) / tot
            ax.barh(y, w, left=left, color=SIZE_COL[k], edgecolor="white", lw=0.8, height=0.78,
                    label={0: "|K| = 0 (base agrees)", 1: "|K| = 1", 2: "|K| = 2"}[k] if y == 0 else None)
            if w >= 9:
                ax.text(left + w / 2, y, f"{w:.0f}", ha="center", va="center", fontsize=6,
                        color="#0b0b0b" if k == 0 else "white")
            left += w
        if e["base_conflict"]:
            w = 100 * e["base_conflict"] / tot
            ax.barh(y, w, left=left, color=SIZE_COL["x"], edgecolor="white", lw=0.8, height=0.78,
                    label="no core (base conflict)")
        rows_lbl.append(f"{LABEL[p]} [{tag}]")
        ypos.append(y)
        y += 1
    y += 0.4
ax.set_yticks(ypos)
ax.set_yticklabels(rows_lbl, fontsize=6)
ax.invert_yaxis()
ax.set_xlim(0, 100)
ax.set_xlabel("Share of configurations (%)")
ax.grid(axis="y", visible=False)
fig.legend(fontsize=6, loc="upper center", ncol=4, columnspacing=0.8, handlelength=1.2)
fig.tight_layout(rect=(0, 0, 1, 0.93))
fig.savefig(RESULTS / "fig-core-size.png")
plt.close(fig)

# ----------------------------------------------------------------- E3 policy replay
traces = load("e3-traces.json")
guards = load("e3-guards.json")


ONLINE = {}  # online guard: per (mix, property), shared across traces in order


def replay(tr, prop, policy):
    vs = [v["verdict"][prop] for v in tr["versions"]]
    twin = vs[0]
    stale = resync = 0
    twins = []
    since = set()  # keys edited since the last re-emulation
    live = ONLINE.setdefault((tr["q"], prop), set(guards[prop]["union"]))
    for t in range(1, len(vs)):
        rec = tr["versions"][t]["edit"]
        keys = {k[1] for k in rec["keys"]}
        changed = rec["kind"] not in ("rejected_by_server", "noop")
        since |= keys
        if policy == "union+per8":
            do = (changed and bool(keys & set(guards[prop]["union"]))) or t % 8 == 0
        elif policy == "online":
            audit = t % 8 == 0
            do = (changed and bool(keys & live)) or audit
            if audit and not (changed and bool(keys & live)) and vs[t] != twin:
                live |= since  # the audit exposed a stale verdict: learn the keys touched since last sync
        elif policy == "hash":
            do = changed
        elif policy.startswith("per"):
            do = t % int(policy[3:]) == 0
        elif policy == "oracle":
            do = vs[t] != twin
        else:
            do = changed and bool(keys & set(guards[prop][policy]))
        if do:
            resync += 1
            twin = vs[t]
            since = set()
        twins.append(twin)
        stale += twin != vs[t]
    # lag of each true flip = consecutive stale steps starting at the flip (0 = caught at once;
    # censored at the trace end)
    lags = []
    for t in range(1, len(vs)):
        if vs[t] != vs[t - 1]:
            lag = 0
            while t + lag < len(vs) and twins[t + lag - 1] != vs[t + lag]:
                lag += 1
            lags.append(lag)
    flips = len(lags)
    return {"stale": stale, "resync": resync, "steps": len(vs) - 1, "flips": flips, "lags": lags}


POL = ["hash", "per2", "per4", "per8", "core", "removal", "union", "expert", "union+per8", "online", "oracle"]
E3 = {}
for q in sorted({t["q"] for t in traces}):
    for pol in POL:
        ONLINE.clear()
        agg = defaultdict(list)
        for tr in traces:
            if tr["q"] != q:
                continue
            for prop in PROPERTIES[tr["service"]]:
                r = replay(tr, prop, pol)
                agg["stale"].append(r["stale"] / r["steps"])
                agg["resync"].append(r["resync"] / r["steps"])
                agg["flips"].append(r["flips"])
                agg["lags"] += r["lags"]
                agg["missed"].append(sum(1 for l in r["lags"] if l > 0))
                agg[f"stale|{prop}"].append(r["stale"] / r["steps"])
                agg[f"resync|{prop}"].append(r["resync"] / r["steps"])
        E3[f"{q}|{pol}"] = {"stale_pct": 100 * st.mean(agg["stale"]), "stale_ci": [100 * x for x in boot_ci(agg["stale"])],
                            "resync_per100": 100 * st.mean(agg["resync"]), "flips_total": sum(agg["flips"]),
                            "late_flips": sum(agg["missed"]), "mean_lag": st.mean(agg["lags"]) if agg["lags"] else 0.0,
                            "by_prop": {p: {"stale_pct": 100 * st.mean(agg[f"stale|{p}"]), "resync_per100": 100 * st.mean(agg[f"resync|{p}"])}
                                        for p in PROPS if agg[f"stale|{p}"]}}
S["e3"] = E3
S["e3_guards"] = guards
kinds = Counter(v["edit"]["kind"] for t in traces for v in t["versions"][1:])
S["e3_edit_kinds"] = dict(kinds)
S["e3_traces"] = {"traces": len(traces), "edits": sum(len(t["versions"]) - 1 for t in traces)}

fig, ax = plt.subplots(figsize=(3.5, 2.4))
names = {"hash": "Hash-triggered", "per2": "Periodic k=2", "per4": "Periodic k=4", "per8": "Periodic k=8",
         "core": "G_core", "removal": "G_pivot", "union": "G_core∪pivot", "expert": "G_expert",
         "oracle": "Oracle", "online": "Online guard"}
mk = {"hash": ("#52514e", "o"), "per2": ("#eb6834", "s"), "per4": ("#eb6834", "s"), "per8": ("#eb6834", "s"),
      "core": ("#2a78d6", "^"), "removal": ("#1baf7a", "D"), "union": ("#6250d6", "v"), "expert": ("#eda100", "P"),
      "oracle": ("#0b0b0b", "*"), "online": ("#008300", "h")}
off = {"hash": (-14, 6), "per2": (5, 2), "per4": (5, 2), "per8": (5, -3), "core": (-6, 7), "removal": (5, 4),
       "union": (-62, -5), "expert": (-2, 8), "oracle": (-4, 8), "online": (5, -2)}
for pol in names:
    e = E3[f"0.3|{pol}"]
    c, m = mk[pol]
    ax.scatter(e["resync_per100"], e["stale_pct"], color=c, marker=m, s=28, zorder=3, edgecolor="white", lw=0.5)
    ax.annotate(names[pol], (e["resync_per100"], e["stale_pct"]), fontsize=6, xytext=off[pol],
                textcoords="offset points", color="#0b0b0b")
xs = [E3[f"0.3|per{k}"]["resync_per100"] for k in (2, 4, 8)]
ys = [E3[f"0.3|per{k}"]["stale_pct"] for k in (2, 4, 8)]
ax.plot(xs, ys, color="#eb6834", lw=0.8, ls="--", zorder=2)
ax.set_xscale("log")
ax.set_xticks([3, 5, 10, 20, 50, 100])
ax.set_xticklabels(["3", "5", "10", "20", "50", "100"])
ax.set_xlabel("Re-emulations per 100 edits (log scale)")
ax.set_ylabel("Stale-verdict steps (%)")
ax.set_xlim(3, 140)
ax.set_ylim(-0.8, 14.5)
fig.tight_layout()
fig.savefig(RESULTS / "fig-resync.png")
plt.close(fig)

# guard-set selective sync
gs = load("e3-gsync.json")
G = {}
for g in ("core", "removal", "union", "expert"):
    for base in ("vendor", "platform"):
        rows = [r for r in gs if r["guard"] == g and r["base"] == base]
        per = defaultdict(list)
        for r in rows:
            per[(r["cid"], r["prop"])].append(1.0 if r["agree"] else 0.0)
        acc = [st.mean(v) for v in per.values()]
        G[f"{g}|{base}"] = {"accuracy": st.mean(acc), "ci": boot_ci(acc), "kept_frac": st.mean(r["kept"] / r["n"] for r in rows),
                            "n": len(rows), "errors": sum(1 for r in rows if not r["agree"]),
                            "false_safe": sum(1 for r in rows if r["truth"] is True and r["verdict"] is False),
                            "by_prop": {p: st.mean(1.0 if r["agree"] else 0.0 for r in rows if r["prop"] == p) for p in PROPS}}
S["e3_gsync"] = G

# ----------------------------------------------------------------- E4 static analyzers vs real servers
seen = {}
for r in truth_rows:
    c = cfgs[r["cid"]]
    seen.setdefault(c.canonical(), (c, {}))[1][r["prop"]] = r["verdict"]
for tr in traces:
    for v in tr["versions"][1:]:
        c = Config(tr["service"], tuple(D(s, k, val) for s, k, val in v["config"]))
        seen.setdefault(c.canonical(), (c, v["verdict"]))
E4 = {}
disagree = defaultdict(list)
for name, fn in (("naive", naive), ("careful", careful)):
    for p in PROPS:
        tp = fp = tn = fn_ = 0
        for c, truth in seen.values():
            if p not in truth:
                continue
            pred = fn(c)[p]
            t = truth[p]
            tp += pred and t
            fp += pred and not t
            tn += (not pred) and (not t)
            fn_ += (not pred) and t
            if pred != t and len(disagree[(name, p)]) < 4:
                disagree[(name, p)].append({"truth": t, "pred": pred, "config": [(d.section, d.key, d.value) for d in c.directives
                                                                                  if d.key not in ()]})
        n = tp + fp + tn + fn_
        E4[f"{name}|{p}"] = {"n": n, "acc": (tp + tn) / n, "tp": tp, "fp": fp, "tn": tn, "fn": fn_}
S["e4"] = E4
S["e4_unique_configs"] = len(seen)
dump("e4-disagreements.json", {f"{a}|{b}": v for (a, b), v in disagree.items()})
dump("summary.json", S)
print(json.dumps({k: S[k] for k in ("corpus", "server_runs", "server_runs_total")}, indent=1))
