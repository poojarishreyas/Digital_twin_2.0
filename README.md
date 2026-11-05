# Fidelity Cores — experiments for verdict-relevant security twins

This repository holds the measurement harness, raw results and manuscript for
the paper *"Fidelity Cores and Pivots: Verdict-Preserving Configuration Minimization for Security Service Twins"*. It extends the Digital Twin platform
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
| `experiments/e6_versions.py` | 16 pinned builds (Redis 6.0–7.4, PostgreSQL 12–17, Nginx 1.20–1.27, OpenSSH 8.8–10.0) |
| `experiments/e7_multiplicity.py` | exhaustive minimum cores (size ≤ 2) vs ddmin |
| `experiments/e8_realworld.py` | public configurations: acceptance, cores, pivots, curves, guard transfer, static analyzer |
| `experiments/e9_realdrift.py` | real git histories replayed against re-emulation policies |
| `experiments/analyze2.py` | statistics and figures for E6–E9 |
| `fidelity/services/versioned.py` | pinned-build twins (containers on the host network) |
| `versions/Dockerfile.sshd` | OpenSSH images at pinned versions with synthetic users |
| `realworld/collect.py`, `realworld/parse.py` | public-file collection (code search, raw reads, blob-less clones) and redacting parser |
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
| Public corpus | 1,092 distinct files (420 Redis, 339 pg_hba, 333 sshd); cores still ≤ 2 directives |
| Guard transfer synthetic → public | 450/450 verdicts, exporting 23.8% (Redis) / 12.3% (sshd) of directives |
| Real histories | 426 commits, 19 verdict flips; guard needs 137 re-emulations vs 426 per commit, none stale |
| Build defaults | official Redis images default `protected-mode no`; Ubuntu 7.0.15 defaults `yes` (11/120 verdicts differ) |
| Platform base profile on public sshd files | 22% wrong even at full synchronization (absence not reported) |

### Real-world data handling
Public files are fetched into a scratch directory outside the repository and never committed. `results/rw-corpus.json`
holds only parsed directives after redaction (every secret replaced by the synthetic lab password) and identifies
configurations by content hash; no repository names are stored. The pinned-build experiment needs Docker; the OpenSSH
images are built from `versions/Dockerfile.sshd`.

The credentials are synthetic lab values; no real system, account or secret is involved.
