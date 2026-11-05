# Fidelity Cores — experiments for verdict-relevant security twins

This repository holds the measurement harness, raw results and manuscript for
the paper *"Fidelity Cores: Measuring How Much Configuration a Security Service
Twin Actually Needs"*. It extends the Digital Twin platform
([poojarishreyas/Digital_twin](https://github.com/poojarishreyas/Digital_twin)), whose
configuration-synchronized service twins showed that twins built from defaults
give wrong security verdicts. This work asks the next question: **which part of a
configuration decides the verdict, how fast accuracy degrades when only part of
it is mirrored, and when a drifting configuration actually needs re-emulation.**

Everything is measured on real servers — Redis 7.0, PostgreSQL 16, Nginx 1.24
and OpenSSH 9.6 — started from rendered files and probed over the wire from a
non-loopback client with the stock clients (`redis-cli`, `psql`, `curl`,
`ssh`). Nothing is simulated.

## Layout

| Path | Contents |
|---|---|
| `fidelity/config.py` | ordered directive model, base profiles V (vendor) and P (platform default twin), twin materialization |
| `fidelity/services/` | per-family renderers, real-server lifecycle and wire probes |
| `fidelity/corpus.py` | seeded configuration generator (catalog + postures) and drift edit model |
| `fidelity/core.py` | fidelity cores via delta debugging (ddmin) |
| `fidelity/static.py` | naive and careful static analyzers (documentation-based, never tuned to server output) |
| `fidelity/harness.py` | 4-slot parallel evaluator with a verdict cache |
| `experiments/e0_truth.py` | source verdicts and acceptance filter |
| `experiments/e1_curve.py` | fidelity curve: random partial synchronization |
| `experiments/e2_cores.py` | fidelity cores under both base profiles, removal sensitivity |
| `experiments/e3_drift.py` | drift traces, guard sets, selective synchronization |
| `experiments/e5_repeat.py` | determinism check: 1,000 cached twins re-run on fresh processes |
| `experiments/analyze.py` | statistics, figures, static-analyzer comparison (E4) |
| `results/` | raw JSON for every run, `summary.json`, figures, verdict cache |
| `paper/` | manuscript: `fidelity-cores.tex` (IEEEtran), `.pdf`, `.docx` (built by `build_docx.py`) |

## Reproduce

Requirements (Ubuntu 24.04): `redis-server`, `postgresql-16`, `nginx`,
`openssh-server`, `sshpass`, `curl`, Python 3.11+ with `matplotlib`.
Run as root inside a disposable VM or container; the harness adds a
non-loopback address and two synthetic lab users.

```bash
ip addr add 10.77.0.1/32 dev lo
useradd -m synthetic && echo 'synthetic:lab-only-password' | chpasswd
groupadd twinops && usermod -aG twinops synthetic
useradd -m auditor && echo 'auditor:lab-only-password' | chpasswd
mkdir -p /run/sshd
cd experiments
python3 e0_truth.py && python3 e1_curve.py && python3 e2_cores.py && python3 e3_drift.py && python3 analyze.py
python3 -m pytest -q ../tests
```

To re-run only the analysis from the shipped results, first restore the verdict cache:
`gunzip -k results/verdict-cache.sqlite.gz`, then `cd experiments && python3 analyze.py`.

## Headline results

| Finding | Value |
|---|---|
| Largest fidelity core (300 configuration–property pairs, vendor base) | 2 directives (median 0, mean 5.1% of a file) |
| Verdict error with 90% of directives mirrored at random | 6.6% (95% CI 5.5–7.8) |
| Pivots lying outside the core | 76 of 194 (39%) |
| Selective sync with learned core∪pivot keys | 24% of directives exported, 99.3% agreement |
| Key-guarded vs hash-triggered re-emulation (q = 0.3) | 19.9 vs 99.8 per 100 edits, 0.28% stale steps |
| Careful static analyzer vs real servers | 17,018 / 17,032 verdicts agree; 14 semantic corner cases |

The credentials are synthetic lab values; no real system, account or secret is involved.
