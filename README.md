# urirun-connector-sentinel — Optimistic Autonomy + Adaptive Containment

The system does **not** start "everything blocked until a human unlocks". It starts broad and
self-directed (grant-pack `optimistic-autonomy`), then **automatically narrows** the instant it
observes an anomaly — and only on the affected dimension, never the whole fleet. A human/twin is
asked only for the genuinely dangerous classes.

```
GREEN  → broad autonomy
YELLOW → suspicion → soft-narrow (no mutations on the affected scope)
ORANGE → repeated failure → hard-narrow (only reconcile/test/diagnose)
RED    → critical (secret exfil, policy change) → deny + escalate ticket
```

## Three schemes

### `containment://` — dimensioned narrowing
Narrow a **single dimension** (`ticket` / `worker` / `connector` / `node` / `repo` / `lane` /
`domain`), never global first. Modes: `soft_narrow` (block mutations, allow read/test),
`hard_narrow` (only an allow-list of action classes), `quarantine` (read-only).

| URI | |
|-----|--|
| `containment://host/scope/command/apply` | narrow a scope |
| `containment://host/scope/command/release` | lift it |
| `containment://host/scope/query/active` | active containments |
| `containment://host/action/query/check` | is this action allowed under active containments? |

### `trust://` — per-subject trust
`trust://host/subject/query/score` → `{trust, allowed_mode}` (0.8+ green, 0.6+ yellow, 0.4+
orange, else quarantine). `subject/command/update` moves it on each outcome (secret violation
is a hard drop).

### `sentinel://` — observe → score → contain
`sentinel://host/action/command/observe` takes `{dims, signals, outcome}`, scores anomaly
severity, updates trust, and **auto-applies the narrowest containment** on threshold.
`anomaly/query/score` returns severity + response.

## Hard invariant

`NEVER_AUTO` (secret export, `disable_policy`, `disable_audit`, `wipe_disk`, `change_never_auto`,
…) is denied regardless of grant or containment state — the system can never widen itself into
those, so no planner error / prompt-injection / bad connector can turn them on.

## Example (dimensioned, not global)

`worker-3` shows a secret-exfiltration pattern → `worker-3` is quarantined + a `SECURITY-REVIEW`
ticket is created; **the rest of the fleet keeps running**. `lenovo` registry drift →
`node:lenovo` hard-narrowed to `fleet.reconcile`/`smoke`; `host` and other nodes untouched.

## Composition

`grant-pack (optimistic-autonomy)` = broad start; `sentinel://` = adaptive narrowing;
`containment://` consulted by `work://` `runnable_gate` alongside policy∧grant∧proxy∧lock;
`trust://` weights how freely a subject runs. `repo://` merge-gate + postconditions close the
loop on mutations.

## Tests

```bash
python -m pytest tests/ -q   # 11 passed
```
