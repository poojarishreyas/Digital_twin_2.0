"""Analysis for E6 (versions), E7 (core multiplicity) and E8 (real-world corpus).
Writes results/summary2.json and figures.  Sections run only if inputs exist."""
import json
import statistics as st
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

from common import PROPERTIES, RESULTS, dump, load  # noqa: E402

S = {}
NATIVE = {"redis": "native 7.0.15", "postgresql": "native 16.15", "nginx": "native 1.24.0", "openssh": "native 9.6p1"}
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.linewidth": 0.6, "axes.edgecolor": "#52514e",
                     "xtick.color": "#52514e", "ytick.color": "#52514e", "legend.frameon": False, "savefig.dpi": 300,
                     "axes.spines.top": False, "axes.spines.right": False})


def exists(name):
    return (RESULTS / name).exists()


# ------------------------------------------------------------------ E6 versions
if exists("e6-versions.json"):
    rows = load("e6-versions.json")
    truth0 = {(r["cid"], r["prop"]): r["verdict"] for r in load("e0-truth.json")}
    # native verdicts for drift samples come from the trace files
    native = {}
    by = defaultdict(dict)  # (cid) -> image -> verdict dict
    cfgkey = {}
    for r in rows:
        by[r["cid"]][r["image"]] = r["verdict"]
        cfgkey[r["cid"]] = (r["service"], r["config"])
    # native verdicts: corpus from e0; drift samples from the verdict cache
    import sqlite3
    con = sqlite3.connect(RESULTS / "verdict-cache.sqlite")
    cache = {k: json.loads(o) for k, o in con.execute("SELECT k, out FROM v")}
    for cid, (svc, cfg) in cfgkey.items():
        key = json.dumps([svc, [list(x) for x in cfg]])
        key2 = json.dumps([svc, cfg])
        o = cache.get(key) or cache.get(key2)
        if o is None:
            o = {p: truth0.get((cid, p)) for p in PROPERTIES[svc]}
        by[cid]["native"] = {p: o.get(p) for p in PROPERTIES[svc]}
    E6 = {}
    flips_examples = defaultdict(list)
    for svc in ("redis", "postgresql", "nginx", "openssh"):
        imgs = sorted({r["image"] for r in rows if r["service"] == svc}, key=lambda x: [int(y) if y.isdigit() else y for y in x.replace("_", ".").replace("-", ".").replace(":", ".").split(".") if y])
        cids = [c for c in by if cfgkey[c][0] == svc]
        for p in PROPERTIES[svc]:
            res = {}
            for img in imgs + ["native"]:
                vs = [by[c].get(img, {}).get(p) for c in cids]
                res[img] = {"n": len(vs), "error": sum(1 for v in vs if v not in (True, False)),
                            "exposed": sum(1 for v in vs if v is True)}
                if img != "native":
                    dis = [c for c in cids if by[c].get(img, {}).get(p) != by[c]["native"][p]]
                    res[img]["disagree_native"] = len(dis)
                    res[img]["disagree_binary"] = sum(1 for c in dis if by[c][img][p] in (True, False) and by[c]["native"][p] in (True, False))
                    for c in dis[:50]:
                        flips_examples[f"{p}|{img}"].append({"cid": c, "native": by[c]["native"][p], "version": by[c][img][p],
                                                             "wire": next((r["wire"] for r in rows if r["cid"] == c and r["image"] == img), "")[:160]})
            anyflip = [c for c in cids if len({str(by[c].get(i, {}).get(p)) for i in imgs + ["native"]}) > 1]
            res["_configs_with_any_difference"] = len(anyflip)
            res["_configs"] = len(cids)
            res["_images"] = imgs
            E6[p] = res
    # core stability across versions (corpus configs only, where all versions binary)
    cores = defaultdict(dict)
    for r in rows:
        for p, keys in r["cores"].items():
            cores[(r["cid"], p)][r["image"]] = None if keys is None else tuple(sorted(keys))
    stab = {}
    for p in [p for ps in PROPERTIES.values() for p in ps]:
        ks = [v for (c, pp), v in cores.items() if pp == p]
        comparable = [v for v in ks if len(v) >= 2]
        same = sum(1 for v in comparable if len(set(v.values())) == 1)
        stab[p] = {"configs": len(comparable), "same_core_keys_all_versions": same}
    S["e6"] = E6
    S["e6_core_stability"] = stab
    dump("e6-flip-examples.json", flips_examples)

# ------------------------------------------------------------------ E7 multiplicity
if exists("e7-multiplicity.json"):
    rows = load("e7-multiplicity.json")
    E7 = {}
    for base in ("vendor", "platform"):
        tot = same = mult = 0
        counts = []
        larger = 0
        for r in rows:
            for k, v in r["res"].items():
                if not k.endswith(base) or v["ddmin"] is None:
                    continue
                tot += 1
                mins = v["minimum"]
                if mins is None:
                    larger += 1
                    continue
                if len(mins[0]) == len(v["ddmin"]):
                    same += 1
                counts.append(len(mins))
                mult += len(mins) > 1
        E7[base] = {"pairs": tot, "ddmin_is_minimum": same, "unique_minimum": sum(1 for c in counts if c == 1),
                    "multiple_minimum": mult, "max_minimum_cores": max(counts), "mean_minimum_cores": st.mean(counts),
                    "none_le2": larger, "count_hist": dict(Counter(counts))}
    S["e7"] = E7


# ------------------------------------------------------------------ E8 real-world corpus
FAMS = ("redis", "postgresql", "openssh")
PROPS3 = ["redis.unauth_admin", "pg.unauth_sql", "ssh.password_login"]


def reject_cause(svc, wire):
    w = wire.lower()
    if svc == "redis":
        if "bad directive" in w or "wrong number of arguments" in w or "argument" in w:
            return "unknown or malformed directive"
        if "fatal config" in w:
            return "invalid value"
        return "other"
    if svc == "openssh":
        if "bad configuration option" in w or "unsupported option" in w or "deprecated" in w:
            return "unknown option"
        if "no such file" in w or "could not" in w or "load" in w:
            return "missing file"
        return "invalid value or combination"
    if "pg_hba" in w or "invalid" in w or "authentication option" in w:
        return "invalid pg_hba rule"
    return "other"


if exists("e8-realworld.json"):
    d = load("e8-realworld.json")
    stats = load("rw-corpus.json")["stats"]
    E8 = {"parse": stats}
    for svc in FAMS:
        acc = [a for a in d["accepted"] if a["service"] == svc]
        rej = [r for r in d["rejected"] if r[1] == svc]
        prop = PROPERTIES[svc][0]
        E8[svc] = {"configs": len(acc) + len(rej), "accepted": len(acc), "rejected": len(rej),
                   "reject_causes": dict(Counter(reject_cause(svc, r[2]) for r in rej)),
                   "exposed": sum(1 for a in acc if a["truth"][prop] is True),
                   "n_median": st.median(a["n"] for a in acc), "n_mean": st.mean(a["n"] for a in acc),
                   "n_max": max(a["n"] for a in acc)}
    for svc in FAMS:
        prop = PROPERTIES[svc][0]
        rows = [r for r in d["full"] if r["service"] == svc]
        out = {"sample": len(rows), "n_mean": st.mean(r["n"] for r in rows)}
        for base in ("vendor", "platform"):
            cs = [r["cores"][f"{prop}|{base}"] for r in rows]
            ok = [c for c in cs if c["core"] is not None]
            sizes = [len(c["core"]) for c in ok]
            out[base] = {"conflict": len(cs) - len(ok), "max": max(sizes), "median": st.median(sizes),
                         "mean": st.mean(sizes), "le2": sum(1 for x in sizes if x <= 2) / len(sizes),
                         "hist": dict(Counter(sizes)), "mean_frac": st.mean(len(c["core"]) / r["n"] for c, r in zip(cs, rows) if c["core"] is not None),
                         "mean_tests": st.mean(c["tests"] for c in ok), "max_tests": max(c["tests"] for c in ok),
                         "keys": Counter(k for c in ok for k in (c["keys"] or [])).most_common(6)}
        piv_total = sum(len(r["pivot_idx"][prop]) for r in rows)
        piv_in = sum(1 for r in rows for i in r["pivot_idx"][prop] if i in (r["cores"][f"{prop}|vendor"]["core"] or []))
        out["pivots"] = {"total": piv_total, "in_core": piv_in, "keys": Counter(k for r in rows for k in r["pivots"][prop]).most_common(8),
                         "configs_with_pivot": sum(1 for r in rows if r["pivot_idx"][prop])}
        curve = defaultdict(list)
        for r in rows:
            for c in r["curve"]:
                curve[(c["base"], c["level"])].append(0.0 if c["agree"] else 1.0)
        out["curve"] = {f"{b}|{l}": st.mean(v) for (b, l), v in sorted(curve.items())}
        gs = defaultdict(list)
        kept = defaultdict(list)
        for r in rows:
            for g in r["gsync"]:
                gs[(g["guard"], g["base"])].append(1.0 if g["agree"] else 0.0)
                kept[(g["guard"], g["base"])].append(g["kept"] / g["n"])
        out["gsync"] = {f"{g}|{b}": {"acc": st.mean(v), "kept": st.mean(kept[(g, b)]), "n": len(v)} for (g, b), v in gs.items()}
        E8[svc + "_full"] = out
    # pooled curve and gsync across families
    pooled = defaultdict(list)
    for r in d["full"]:
        for c in r["curve"]:
            pooled[(c["base"], c["level"])].append(0.0 if c["agree"] else 1.0)
    E8["curve_pooled"] = {f"{b}|{l}": st.mean(v) for (b, l), v in sorted(pooled.items())}
    pg = defaultdict(list)
    pk = defaultdict(list)
    for r in d["full"]:
        for g in r["gsync"]:
            pg[(g["guard"], g["base"])].append(1.0 if g["agree"] else 0.0)
            pk[(g["guard"], g["base"])].append(g["kept"] / g["n"])
    E8["gsync_pooled"] = {f"{g}|{b}": {"acc": st.mean(v), "kept": st.mean(pk[(g, b)]), "n": len(v),
                                       "errors": sum(1 for x in v if x == 0)} for (g, b), v in pg.items()}
    stc = defaultdict(lambda: [0, 0])
    for x in d["static"]:
        stc[x["prop"]][0] += x["pred"] == x["truth"]
        stc[x["prop"]][1] += 1
    E8["static_careful"] = {p: {"acc": a / n, "n": n, "errors": n - a} for p, (a, n) in stc.items()}

    # figure: fidelity curves on public configurations vs the synthetic corpus
    syn = load("summary.json")["e1"]
    fig, axes = plt.subplots(1, 2, figsize=(7.16, 2.2), sharey=True)
    cols = {"redis": "#2a78d6", "postgresql": "#eb6834", "openssh": "#6250d6"}
    mk = {"redis": "o", "postgresql": "s", "openssh": "v"}
    lab = {"redis": "Redis (public)", "postgresql": "PostgreSQL (public)", "openssh": "OpenSSH (public)"}
    for ax, base, title in zip(axes, ("vendor", "platform"), ("(a) Base V: vendor defaults", "(b) Base P: platform default twin")):
        for svc in FAMS:
            cur = E8[svc + "_full"]["curve"]
            lv = sorted({float(k.split("|")[1]) for k in cur})
            ax.plot([100 * l for l in lv], [100 * cur[f"{base}|{l}"] for l in lv], color=cols[svc], marker=mk[svc], ms=3.2, lw=1.2, label=lab[svc])
        lv = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        ax.plot([100 * l for l in lv], [100 * syn[f"{base}|all|{l}"]["error"] for l in lv], color="#0b0b0b", lw=1.6, ls="--", label="Synthetic, all properties")
        ax.set_title(title, fontsize=8)
        ax.set_xlabel("Directives synchronized at random (%)")
        ax.set_xlim(0, 100)
        ax.set_ylim(bottom=0)
        ax.grid(True, color="#e6e5e0", lw=0.5)
    axes[0].set_ylabel("Verdict error (%)")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=4, fontsize=7, bbox_to_anchor=(0.5, -0.01))
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    fig.savefig(RESULTS / "fig-rw-curve.png")
    plt.close(fig)

    fig, axes = plt.subplots(2, 1, figsize=(3.5, 4.4), sharex=True)
    for ax, base, title in zip(axes, ("vendor", "platform"), ("(a) Base V: vendor defaults", "(b) Base P: platform default twin")):
        for svc in FAMS:
            cur = E8[svc + "_full"]["curve"]
            lv = sorted({float(k.split("|")[1]) for k in cur})
            ax.plot([100 * l for l in lv], [100 * cur[f"{base}|{l}"] for l in lv], color=cols[svc], marker=mk[svc], ms=3, lw=1.1, label=lab[svc])
        lv = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        ax.plot([100 * l for l in lv], [100 * syn[f"{base}|all|{l}"]["error"] for l in lv], color="#0b0b0b", lw=1.5, ls="--", label="Synthetic, all properties")
        ax.set_title(title, fontsize=8)
        ax.set_ylabel("Verdict error (%)")
        ax.set_xlim(0, 100)
        ax.set_ylim(bottom=0)
        ax.grid(True, color="#e6e5e0", lw=0.5)
    axes[1].set_xlabel("Directives synchronized at random (%)")
    h, l = axes[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=2, fontsize=6.5, bbox_to_anchor=(0.5, 0.0))
    fig.tight_layout(rect=(0, 0.1, 1, 1))
    fig.savefig(RESULTS / "fig-rw-curve-stacked.png")
    plt.close(fig)
    S["e8"] = E8

# ------------------------------------------------------------------ E9 real drift
if exists("e9-realdrift.json"):
    hs = load("e9-realdrift.json")
    guards = load("e3-guards.json")
    pol = defaultdict(lambda: defaultdict(int))
    per = {"commits": 0, "parsed_changes": 0, "flips": 0, "files": len(hs)}
    for h in hs:
        svc = h["service"]
        prop = PROPERTIES[svc][0]
        norm = (lambda k: k.lower()) if svc == "openssh" else (lambda k: k)
        G = {g: {norm(k) for k in guards[prop][g]} for g in ("union", "expert", "core")}
        prev = None
        twin = {g: None for g in ("hash", "union", "expert", "core", "commit")}
        for v, r in zip(h["versions"], h["verdicts"]):
            if v is None or r is None or r[prop] not in (True, False):
                continue
            cur = [tuple(x) for x in v["directives"]]
            if prev is None:
                prev, pv = cur, r[prop]
                for g in twin:
                    twin[g] = pv
                continue
            per["commits"] += 1
            changed = cur != prev
            a, b = Counter(prev), Counter(cur)
            touched = {norm(x[1]) for x in (a - b) + (b - a)}
            if changed and not touched:
                touched = {norm(x[1]) for x in cur}  # pure reordering
            flip = r[prop] != pv
            per["parsed_changes"] += changed
            per["flips"] += flip
            for g in twin:
                do = {"commit": True, "hash": changed}.get(g, changed and bool(touched & G.get(g, set())))
                if do:
                    pol[g]["resync"] += 1
                    twin[g] = r[prop]
                pol[g]["stale"] += twin[g] != r[prop]
            prev, pv = cur, r[prop]
    per["by_service"] = {svc: sum(1 for h in hs if h["service"] == svc) for svc in FAMS}
    S["e9"] = {"overall": per, "policies": {k: dict(v) for k, v in pol.items()}}

dump("summary2.json", S)
print(json.dumps(S, indent=1, default=str)[:6000])
