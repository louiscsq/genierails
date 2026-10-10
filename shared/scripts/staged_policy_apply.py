#!/usr/bin/env python3
"""Fail-closed staged application of deterministic governance changes.

The controller is deliberately independent of Terraform and Databricks clients:
each stage is an argv hook.  Production hooks are supplied by the Make layer;
tests use tiny executables.  A hook failure stops immediately and the journal
records exactly which old/new protections remain.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path


STAGES = ("create", "verify-created", "switch", "verify-switched", "retire")
PROTECTION = {"raw": 0, "partial": 1, "redacted": 2, "null": 2, "full": 2}


def order_tier_moves(moves: list[dict]) -> list[dict]:
    """Return moves in tighten-before-loosen order (stable within each class)."""
    def key(move: dict) -> int:
        before, after = move.get("before"), move.get("after")
        if before not in PROTECTION or after not in PROTECTION:
            raise ValueError(f"unknown protection move: {before!r} -> {after!r}")
        return 0 if PROTECTION[after] >= PROTECTION[before] else 1
    return sorted(moves, key=key)


@dataclass
class Journal:
    release_id: str
    fingerprint: str
    completed: list[str]
    old_protection: str
    new_protection: str
    retire_after_release: str
    status: str = "running"
    failed_stage: str = ""


def _read(path: Path) -> dict:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _write(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(tmp, path)


def run_protocol(*, mode: str, fingerprint: str, state_file: Path,
                 hooks: dict[str, list[str]], release_id: str | None = None) -> int:
    if mode != "deterministic":
        print("staged policy apply: legacy governance mode; zero changes")
        return 0
    missing = [stage for stage in STAGES[:-1] if not hooks.get(stage)]
    if missing:
        raise ValueError("missing stage hooks: " + ", ".join(missing))

    previous = _read(state_file)
    rid = release_id or uuid.uuid4().hex
    old = str(previous.get("active_fingerprint", ""))
    eligible = str(previous.get("retire_after_release", ""))
    journal = Journal(
        release_id=rid, fingerprint=fingerprint, completed=[],
        old_protection=old, new_protection=fingerprint,
        retire_after_release=old if old and old != fingerprint else eligible,
    )
    _write(state_file, {**previous, **asdict(journal)})

    # Cleanup belongs to a later successful release.  Consequently it is last,
    # and only a retirement carried by an earlier release is eligible here.
    stages = list(STAGES[:-1])
    if eligible and eligible != fingerprint and hooks.get("retire"):
        stages.append("retire")
    env = os.environ | {
        "GENIERAILS_POLICY_RELEASE_ID": rid,
        "GENIERAILS_POLICY_FINGERPRINT": fingerprint,
        "GENIERAILS_OLD_POLICY_FINGERPRINT": old,
        "GENIERAILS_RETIRE_FINGERPRINT": eligible,
    }
    for stage in stages:
        print(f"=== Policy staged apply: {stage} ===", flush=True)
        result = subprocess.run(hooks[stage], env=env, check=False)
        if result.returncode:
            journal.status = "failed"
            journal.failed_stage = stage
            _write(state_file, {**previous, **asdict(journal)})
            print(
                f"policy staged apply failed at {stage} (exit {result.returncode}); "
                f"old protection={old or 'none'}, new protection={fingerprint}, "
                f"completed={','.join(journal.completed) or 'none'}",
                file=sys.stderr,
            )
            return result.returncode
        journal.completed.append(stage)
        _write(state_file, {**previous, **asdict(journal)})

    journal.status = "success"
    final = {**previous, **asdict(journal), "active_fingerprint": fingerprint,
             "successful_at": int(time.time())}
    # The old active generation becomes pending; a generation retired now is
    # removed from the pending slot.  Never retire the generation just switched.
    final["retire_after_release"] = old if old and old != fingerprint else ""
    _write(state_file, final)
    return 0


def _parse_hook(raw: str) -> tuple[str, list[str]]:
    stage, sep, path = raw.partition("=")
    if not sep or stage not in STAGES or not path:
        raise argparse.ArgumentTypeError("hook must be STAGE=EXECUTABLE")
    return stage, [path]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--state-file", type=Path, required=True)
    parser.add_argument("--release-id")
    parser.add_argument("--hook", action="append", default=[], type=_parse_hook)
    args = parser.parse_args(argv)
    try:
        return run_protocol(mode=args.mode, fingerprint=args.fingerprint,
                            state_file=args.state_file, hooks=dict(args.hook),
                            release_id=args.release_id)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"staged policy apply: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
