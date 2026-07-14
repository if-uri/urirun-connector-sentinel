# Author: Tom Sapletta · Part of the ifURI solution.
"""urirun-connector-sentinel — Optimistic Autonomy + Adaptive Containment.

The system does NOT start "everything blocked until a human unlocks". It starts broad and
self-directed, then **automatically narrows** the moment it observes an anomaly — and only on
the affected dimension (this ticket / worker / connector / node / repo / lane / domain), never
the whole fleet. Escalation to a human/twin happens only for the genuinely dangerous classes.

Three schemes:
  * ``containment://`` — dimensioned narrowing: apply/release/active + ``check`` (is an action
    allowed given the active containments?). Modes: soft_narrow (no mutations), hard_narrow
    (only an allow-list of action classes), quarantine (read-only).
  * ``trust://`` — per-subject (worker/connector) trust score → allowed mode
    (green/yellow/orange/quarantine); updated on each outcome.
  * ``sentinel://`` — observe an action's outcome + anomaly signals, score severity, update
    trust, and auto-apply the *narrowest* containment on threshold (GREEN→YELLOW→ORANGE→RED).

Hard invariant: a fixed ``never-auto`` set (secret export, disable policy/audit, wipe, etc.)
is denied regardless of grant/containment state — the system can never widen itself into those.
"""
from __future__ import annotations

import fnmatch
import json
import os
import time
from pathlib import Path
from typing import Any

import urirun

containment_conn = urirun.connector("containment", scheme="containment")
trust_conn = urirun.connector("trust", scheme="trust")
sentinel_conn = urirun.connector("sentinel", scheme="sentinel")

_CONT = Path(os.environ.get("URIRUN_CONTAINMENTS") or "~/.urirun/host-dashboard/containments.json").expanduser()
_TRUST = Path(os.environ.get("URIRUN_TRUST") or "~/.urirun/host-dashboard/trust.json").expanduser()

# Denied no matter what — the system can never grant itself these (change_never_auto included).
NEVER_AUTO = ("credential.export", "secret.read_plaintext", "exfiltrate_secrets", "bypass_auth",
              "disable_policy", "disable_audit", "destructive_without_backup", "wipe_disk",
              "change_never_auto")
# Narrowest → widest: containment is applied to the FIRST dimension present, never global first.
_SCOPE_ORDER = ("ticket", "worker", "connector", "node", "repo", "lane", "domain")
_READONLY = ("query", "read", "test", "smoke", "diagnose")

_SEVERITY = {
    "secret_exfiltration": "critical", "credential_access": "critical", "policy_change": "critical",
    "disable_audit": "critical", "provenance_mismatch": "high", "unknown_domain_large_payload": "high",
    "repeated_failure": "medium", "postcondition_fail": "medium", "ok_no_effect": "medium",
    "registry_drift": "medium", "unknown_domain": "low", "slow": "low",
}
_SEV_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RESPONSE = {"low": "log", "medium": "narrow_scope", "high": "quarantine_scope", "critical": "deny_and_escalate"}


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text()) if path.is_file() else None
    except Exception:  # noqa: BLE001
        return None


def _save(path: Path, data: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


# ── containment ───────────────────────────────────────────────────────────────

def active_containments(now: float | None = None) -> list[dict]:
    now = time.time() if now is None else now
    data = _load(_CONT) or []
    return [c for c in data if not c.get("released") and (not c.get("expires_at") or c["expires_at"] > now)]


def containment_apply(scope: dict, mode: str, *, reason: str = "", restrict_to: list[str] | None = None,
                      deny: list[str] | None = None, ttl_minutes: int = 0, now: float | None = None) -> dict:
    """Narrow a single dimension. mode ∈ soft_narrow | hard_narrow | quarantine."""
    now = time.time() if now is None else now
    if mode not in ("soft_narrow", "hard_narrow", "quarantine"):
        return {"ok": False, "error": f"bad mode {mode!r}"}
    cid = "cont:" + "-".join(f"{k}={v}" for k, v in sorted(scope.items())) + f":{mode}"
    data = [c for c in (_load(_CONT) or []) if c.get("id") != cid]
    entry = {"id": cid, "scope": scope, "mode": mode, "reason": reason,
             "restrict_to": restrict_to or [], "deny": deny or [], "applied_at": now,
             "expires_at": (now + ttl_minutes * 60) if ttl_minutes else 0}
    data.append(entry)
    _save(_CONT, data)
    return {"ok": True, "containment": entry}


def containment_release(containment_id: str) -> dict:
    data = _load(_CONT) or []
    hit = False
    for c in data:
        if c.get("id") == containment_id:
            c["released"] = True
            hit = True
    _save(_CONT, data)
    return {"ok": hit, "released": containment_id if hit else None}


def _scope_matches(scope: dict, dims: dict) -> bool:
    return all(dims.get(k) == v for k, v in scope.items())


def _one_denies(c: dict, dims: dict, action_class: str, uri: str) -> dict | None:
    if uri and any(fnmatch.fnmatch(uri, p) for p in c.get("deny", [])):
        return {"allowed": False, "mode": c["mode"], "reason": f"denied by {c['id']}: {c['reason']}", "containment": c["id"]}
    mode = c["mode"]
    if mode == "quarantine" and action_class not in _READONLY:
        return {"allowed": False, "mode": mode, "reason": f"quarantine (read-only): {c['reason']}", "containment": c["id"]}
    if mode == "hard_narrow":
        allowed = c.get("restrict_to") or []
        if allowed and action_class not in allowed:
            return {"allowed": False, "mode": mode, "reason": f"hard-narrow, only {allowed}: {c['reason']}", "containment": c["id"]}
    if mode == "soft_narrow" and action_class in ("command", "external", "mutation"):
        return {"allowed": False, "mode": mode, "reason": f"soft-narrow (no mutations): {c['reason']}", "containment": c["id"]}
    return None


def containment_check(dims: dict, action_class: str = "command", uri: str = "", now: float | None = None) -> dict:
    """Is an action (with its dims + class) allowed under the active containments?"""
    action = uri.split("://", 1)[0] + "." + action_class if uri else action_class
    if any(action_class == n or (uri and n in uri) for n in NEVER_AUTO) or action_class in NEVER_AUTO:
        return {"allowed": False, "mode": "red", "reason": f"never-auto: {action_class}"}
    for c in active_containments(now):
        if not _scope_matches(c["scope"], dims):
            continue
        verdict = _one_denies(c, dims, action_class, uri)
        if verdict:
            return verdict
    return {"allowed": True, "mode": "green"}


# ── trust ─────────────────────────────────────────────────────────────────────

_BANDS = ((0.8, "green"), (0.6, "yellow"), (0.4, "orange"), (0.0, "quarantine"))
_DELTA = {"success": 0.02, "failure": -0.1, "postcondition_fail": -0.15, "secret_violation": -0.6}


def allowed_mode(trust: float) -> str:
    for thr, mode in _BANDS:
        if trust >= thr:
            return mode
    return "quarantine"


def trust_score(subject: str) -> dict:
    d = (_load(_TRUST) or {}).get(subject, {})
    t = d.get("trust", 1.0)
    return {"subject": subject, "trust": round(t, 3), "recent_failures": d.get("recent_failures", 0),
            "secret_violations": d.get("secret_violations", 0),
            "postcondition_failures": d.get("postcondition_failures", 0), "allowed_mode": allowed_mode(t)}


def trust_update(subject: str, outcome: str) -> dict:
    data = _load(_TRUST) or {}
    d = data.setdefault(subject, {"trust": 1.0})
    d["trust"] = max(0.0, min(1.0, d.get("trust", 1.0) + _DELTA.get(outcome, 0.0)))
    if outcome == "success":
        d["recent_failures"] = 0
    if outcome == "failure":
        d["recent_failures"] = d.get("recent_failures", 0) + 1
    if outcome == "postcondition_fail":
        d["postcondition_failures"] = d.get("postcondition_failures", 0) + 1
    if outcome == "secret_violation":
        d["secret_violations"] = d.get("secret_violations", 0) + 1
    _save(_TRUST, data)
    return trust_score(subject)


# ── sentinel: observe → score → contain ───────────────────────────────────────

def anomaly_score(signals: list[str]) -> str:
    return max((_SEVERITY.get(s, "low") for s in signals), key=lambda s: _SEV_RANK[s], default="none")


def _minimal_scope(dims: dict) -> dict:
    for dim in _SCOPE_ORDER:
        if dims.get(dim):
            return {dim: dims[dim]}
    return {"lane": dims.get("lane", "global")}


def observe(dims: dict, signals: list[str] | None = None, outcome: str = "success") -> dict:
    """Observe an action outcome. Update trust, and on an anomaly auto-apply the NARROWEST
    containment (never global first). Returns severity + response + containment + escalation."""
    signals = signals or []
    subject = dims.get("worker") or dims.get("connector") or "system"
    if signals or outcome != "success":
        trust_update(subject, "secret_violation" if anomaly_score(signals) == "critical"
                     else (outcome if outcome != "success" else "failure"))
    if not signals:
        return {"severity": "none", "response": "log", "trust": trust_score(subject)}
    sev = anomaly_score(signals)
    resp = _RESPONSE[sev]
    result: dict[str, Any] = {"severity": sev, "response": resp, "signals": signals, "subject": subject}
    if resp == "log":
        return result
    scope = _minimal_scope(dims)
    mode = {"narrow_scope": "soft_narrow", "quarantine_scope": "quarantine", "deny_and_escalate": "quarantine"}[resp]
    deny = ["*://**"] if resp == "deny_and_escalate" else []
    c = containment_apply(scope, mode, reason=f"anomaly:{','.join(signals)}", deny=deny)
    result["containment"] = c["containment"]["id"]
    if resp == "deny_and_escalate":
        result["ticket"] = "SECURITY-REVIEW"
        result["escalate"] = "human://operator/decision/security"
    return result


# ── handlers ──────────────────────────────────────────────────────────────────

def _ok(scheme: str, **kw: Any) -> dict[str, Any]:
    return urirun.ok(connector=scheme, **kw)


@containment_conn.handler("scope/command/apply", isolated=True,
                          meta={"label": "Zawęź jeden wymiar (soft/hard/quarantine) — nie globalnie"})
def containment_scope_command_apply(scope: Any = None, mode: str = "soft_narrow", reason: str = "",
                                    restrict_to: Any = None, deny: Any = None, ttl_minutes: int = 0) -> dict[str, Any]:
    sc = scope if isinstance(scope, dict) else {}
    rt = list(restrict_to) if isinstance(restrict_to, (list, tuple)) else None
    dn = list(deny) if isinstance(deny, (list, tuple)) else None
    res = containment_apply(sc, mode, reason=reason, restrict_to=rt, deny=dn, ttl_minutes=int(ttl_minutes))
    return _ok("containment", action="containment-apply", **res) if res.get("ok") \
        else urirun.fail(res.get("error", "apply failed"), connector="containment", action="containment-apply")


@containment_conn.handler("scope/command/release", isolated=True, meta={"label": "Zdejmij containment"})
def containment_scope_command_release(containment_id: str = "") -> dict[str, Any]:
    return _ok("containment", action="containment-release", **containment_release(containment_id))


@containment_conn.handler("scope/query/active", isolated=False, meta={"label": "Aktywne containmenty"})
def containment_scope_query_active() -> dict[str, Any]:
    cs = active_containments()
    return _ok("containment", action="containment-active", count=len(cs), containments=cs)


@containment_conn.handler("action/query/check", isolated=False,
                          meta={"label": "Czy akcja dozwolona pod aktywnymi containmentami"})
def containment_action_query_check(dims: Any = None, action_class: str = "command", uri: str = "") -> dict[str, Any]:
    return _ok("containment", action="containment-check", **containment_check(dims if isinstance(dims, dict) else {}, action_class, uri))


@trust_conn.handler("subject/query/score", isolated=False, meta={"label": "Trust score subjecta → allowed_mode"})
def trust_subject_query_score(subject: str = "") -> dict[str, Any]:
    return _ok("trust", action="trust-score", **trust_score(subject))


@trust_conn.handler("subject/command/update", isolated=True, meta={"label": "Zaktualizuj trust po wyniku akcji"})
def trust_subject_command_update(subject: str = "", outcome: str = "success") -> dict[str, Any]:
    return _ok("trust", action="trust-update", **trust_update(subject, outcome))


@sentinel_conn.handler("action/command/observe", isolated=True,
                       meta={"label": "Obserwuj wynik+sygnały anomalii → score, trust, auto-containment"})
def sentinel_action_command_observe(dims: Any = None, signals: Any = None, outcome: str = "success") -> dict[str, Any]:
    sig = list(signals) if isinstance(signals, (list, tuple)) else ([signals] if signals else [])
    return _ok("sentinel", action="observe", **observe(dims if isinstance(dims, dict) else {}, sig, outcome))


@sentinel_conn.handler("anomaly/query/score", isolated=False, meta={"label": "Severity dla sygnałów anomalii"})
def sentinel_anomaly_query_score(signals: Any = None) -> dict[str, Any]:
    sig = list(signals) if isinstance(signals, (list, tuple)) else ([signals] if signals else [])
    return _ok("sentinel", action="anomaly-score", severity=anomaly_score(sig), response=_RESPONSE.get(anomaly_score(sig), "log"))


def urirun_bindings() -> dict[str, Any]:
    return containment_conn.bindings()


def trust_bindings() -> dict[str, Any]:
    return trust_conn.bindings()


def sentinel_bindings() -> dict[str, Any]:
    return sentinel_conn.bindings()


def main(argv: list[str] | None = None) -> int:
    return containment_conn.cli(argv, manifest_prose=None)


if __name__ == "__main__":
    raise SystemExit(main())
