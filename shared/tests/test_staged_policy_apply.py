import json
from pathlib import Path

import pytest

from scripts.staged_policy_apply import STAGES, order_tier_moves, run_protocol


def _hooks(tmp_path: Path, fail: str = "") -> tuple[dict, Path]:
    log = tmp_path / "calls"
    hooks = {}
    for stage in STAGES:
        script = tmp_path / stage
        script.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' '{stage}' >> '{log}'\n"
            + ("exit 19\n" if stage == fail else "exit 0\n")
        )
        script.chmod(0o755)
        hooks[stage] = [str(script)]
    return hooks, log


def test_legacy_is_a_zero_diff_without_hooks(tmp_path, capsys):
    state = tmp_path / "state.json"
    assert run_protocol(mode="legacy", fingerprint="new", state_file=state, hooks={}) == 0
    assert not state.exists()
    assert "zero changes" in capsys.readouterr().out


def test_tier_moves_tighten_before_loosen():
    moves = [
        {"principal": "loosen", "before": "full", "after": "partial"},
        {"principal": "tighten", "before": "raw", "after": "full"},
        {"principal": "same", "before": "partial", "after": "partial"},
    ]
    assert [m["principal"] for m in order_tier_moves(moves)] == ["tighten", "same", "loosen"]


def test_stage_order_and_retirement_requires_later_success(tmp_path):
    hooks, log = _hooks(tmp_path)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"active_fingerprint": "old"}))
    assert run_protocol(mode="deterministic", fingerprint="new", state_file=state,
                        hooks=hooks, release_id="r1") == 0
    assert log.read_text().splitlines() == list(STAGES[:-1])
    assert json.loads(state.read_text())["retire_after_release"] == "old"

    log.write_text("")
    assert run_protocol(mode="deterministic", fingerprint="new", state_file=state,
                        hooks=hooks, release_id="r2") == 0
    assert log.read_text().splitlines() == list(STAGES)


@pytest.mark.parametrize("failed", STAGES[:-1])
def test_failure_at_each_mandatory_stage_stops_and_reports_left_state(tmp_path, failed):
    hooks, log = _hooks(tmp_path, failed)
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"active_fingerprint": "old"}))
    assert run_protocol(mode="deterministic", fingerprint="new", state_file=state,
                        hooks=hooks, release_id="r1") == 19
    called = log.read_text().splitlines()
    assert called == list(STAGES[: STAGES.index(failed) + 1])
    saved = json.loads(state.read_text())
    assert saved["status"] == "failed"
    assert saved["failed_stage"] == failed
    assert saved["old_protection"] == "old"
    assert saved["new_protection"] == "new"
    assert saved.get("active_fingerprint") == "old"


def test_retirement_failure_keeps_active_generation_and_pending_retirement(tmp_path):
    hooks, log = _hooks(tmp_path, "retire")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"active_fingerprint": "new", "retire_after_release": "old"}))
    assert run_protocol(mode="deterministic", fingerprint="new", state_file=state,
                        hooks=hooks, release_id="r2") == 19
    saved = json.loads(state.read_text())
    assert saved["active_fingerprint"] == "new"
    assert saved["retire_after_release"] == "old"
