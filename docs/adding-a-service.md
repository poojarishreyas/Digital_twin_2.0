# Adding a service without writing code

Every analysis in this repository (verdicts, fidelity cores, pivots, fidelity
curves, guard learning, drift policies, the `fidelity` CLI) runs on any service
described by a YAML spec in `specs/`. Mosquitto, MongoDB and MariaDB were added
this way, with no Python changes.

A spec has six parts.

```yaml
name: mosquitto

config:                     # 1. how a configuration is rendered
  files:
    - name: mosquitto.conf
      template: |           # scaffolding the twin owns; {{main}} receives the directives
        user root
        log_dest stdout
        {{main}}
  sections:
    "": {placeholder: main, line: "{key} {value}"}
  # other formats: INI headers + flag lines (mariadb.yaml), nested YAML via
  # dotted keys (mongodb.yaml), brace blocks (nginx.yaml), rule files and
  # several files at once (postgresql.yaml), dynamic Match blocks (openssh.yaml)

parse:                      # 2. how a real file is read (for analyze/export/gate)
  kind: lines               # lines | ini | yaml | rules
  environment: [pid_file, cafile, certfile, keyfile]   # supplied by the twin, dropped
  rewrite:                  # map host-specific values onto the twin
    - {key: listener, pattern: '^\d+', replace: '{port}', enumerate: true}
  # also: secret_keys, token_secret_keys, address_keys

runtime:                    # 3. how the server runs (native binary or pinned image)
  image: eclipse-mosquitto:2.0
  port_base: 18830
  command: [mosquitto, -c, "{dir}/mosquitto.conf"]
  ready: {type: log, marker: " running"}      # log | tcp | unix | sleep

prepare:                    # 4. one-time per-slot setup (synthetic users, keys, data dirs)
  steps:
    - {cmd: [mosquitto_passwd, -b, -c, "{dir}/passwd", synthetic, "{password}"]}

properties:                 # 5. security questions answered over the wire
  - id: mqtt.anonymous_publish
    probe: {cmd: [mosquitto_pub, -h, "{host}", -p, "{port}", -t, t, -m, x], client_image: true}
    exposed_if: '^'                         # regex on client output (exit code 0 required)
    safe_if: 'not authori[sz]ed|Connection refused'

catalog:                    # 6. optional: directive values for corpus generation,
  - {key: allow_anonymous, values: ["true", "false"], class: security}   # the expert guard
array_keys: [listener]      #    and build fingerprinting
base_profiles:
  platform: [{key: allow_anonymous, value: "false"}]
```

Placeholders available everywhere: `{host}`, `{port}`, `{port_alt1..5}`, `{dir}`, `{password}`.

Checklist for a new spec:

1. `python3 -m fidelity.cli specs` lists it.
2. Run a few hand-written configurations with known answers (see `tests/test_spec.py`
   and the smoke script in the paper's artifact) and confirm both an exposed and a
   safe verdict are produced.
3. `python3 -m fidelity.cli fingerprint <name> --images native <image>` shows the
   default security behaviour of each build you intend to use.
4. Optionally run `experiments/e10_newservices.py <name>` to obtain cores, pivots,
   fidelity curves and learned guard sets for the new service.

Limits: a spec can only express what a wire probe can observe, and anything the
twin cannot provide (PAM stacks, TLS material, cluster peers, site-specific
includes) has to be declared as environment-bound. Such directives are reported,
not silently emulated.
