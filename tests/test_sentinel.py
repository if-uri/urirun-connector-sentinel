"""Optimistic autonomy + adaptive containment: containment:// / trust:// / sentinel://."""
from __future__ import annotations

import pytest

from urirun_connector_sentinel import core


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "_CONT", tmp_path / "cont.json")
    monkeypatch.setattr(core, "_TRUST", tmp_path / "trust.json")


# ── 1. no anomaly → broad autonomy (green) ────────────────────────────────────

def test_1_no_containment_allows_broadly():
    for act in ("command", "test", "connector.generate"):
        assert core.containment_check({"worker": "w1"}, action_class=act)["allowed"] is True


# ── 6. never-auto denied regardless ───────────────────────────────────────────

def test_6_never_auto_denied_even_with_no_containment():
    for act in ("exfiltrate_secrets", "disable_policy", "wipe_disk", "change_never_auto"):
        d = core.containment_check({"worker": "w1"}, action_class=act)
        assert d["allowed"] is False and d["mode"] == "red"


# ── 4. node stale → narrow only that node ─────────────────────────────────────

def test_4_containment_is_dimensioned_not_global():
    core.containment_apply({"node": "lenovo"}, "hard_narrow", reason="node stale",
                           restrict_to=["query", "smoke", "fleet.reconcile"])
    # lenovo mutations blocked, but its allow-list + OTHER nodes still run
    assert core.containment_check({"node": "lenovo"}, "command")["allowed"] is False
    assert core.containment_check({"node": "lenovo"}, "smoke")["allowed"] is True
    assert core.containment_check({"node": "host"}, "command")["allowed"] is True  # fleet not frozen


def test_soft_narrow_allows_read_blocks_mutation():
    core.containment_apply({"worker": "w2"}, "soft_narrow", reason="suspect")
    assert core.containment_check({"worker": "w2"}, "query")["allowed"] is True
    assert core.containment_check({"worker": "w2"}, "command")["allowed"] is False


def test_quarantine_is_read_only():
    core.containment_apply({"worker": "w3"}, "quarantine", reason="critical")
    assert core.containment_check({"worker": "w3"}, "query")["allowed"] is True
    assert core.containment_check({"worker": "w3"}, "test")["allowed"] is True
    assert core.containment_check({"worker": "w3"}, "connector.generate")["allowed"] is False


# ── trust bands ───────────────────────────────────────────────────────────────

def test_trust_decays_on_failure_and_maps_to_mode():
    assert core.trust_score("w9")["allowed_mode"] == "green"  # default 1.0
    core.trust_update("w9", "secret_violation")  # -0.6 → 0.4 → orange
    s = core.trust_score("w9")
    assert s["trust"] == pytest.approx(0.4, abs=0.01) and s["allowed_mode"] == "orange"
    assert s["secret_violations"] == 1


# ── sentinel: observe → score → auto-contain (2,3,5,7) ────────────────────────

def test_anomaly_score_ranks_severity():
    assert core.anomaly_score(["unknown_domain"]) == "low"
    assert core.anomaly_score(["postcondition_fail"]) == "medium"
    assert core.anomaly_score(["provenance_mismatch"]) == "high"
    assert core.anomaly_score(["repeated_failure", "secret_exfiltration"]) == "critical"


def test_2_unknown_domain_small_only_logs():
    r = core.observe({"worker": "w4", "domain": "unknown.example"}, ["unknown_domain"])
    assert r["severity"] == "low" and r["response"] == "log"
    assert core.active_containments() == []  # nothing narrowed


def test_3_secret_exfiltration_denies_and_quarantines_worker():
    r = core.observe({"worker": "koru-worker-3", "connector": "gen"}, ["secret_exfiltration"])
    assert r["severity"] == "critical" and r["response"] == "deny_and_escalate"
    assert r["ticket"] == "SECURITY-REVIEW" and r["escalate"].startswith("human://")
    # only THAT worker is contained (narrowest dim = ticket/worker), not the fleet
    assert core.containment_check({"worker": "koru-worker-3"}, "command")["allowed"] is False
    assert core.containment_check({"worker": "koru-worker-9"}, "command")["allowed"] is True


def test_5_repeated_failure_narrows_lane_to_readonly():
    core.observe({"lane": "connector-gen"}, ["repeated_failure", "postcondition_fail"])
    assert core.containment_check({"lane": "connector-gen"}, "command")["allowed"] is False  # soft-narrow
    assert core.containment_check({"lane": "connector-gen"}, "query")["allowed"] is True


def test_7_release_lifts_containment():
    core.observe({"worker": "w5"}, ["provenance_mismatch"])
    cid = core.active_containments()[0]["id"]
    assert core.containment_check({"worker": "w5"}, "command")["allowed"] is False
    core.containment_release(cid)
    assert core.containment_check({"worker": "w5"}, "command")["allowed"] is True
