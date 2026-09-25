#!/usr/bin/env python3
"""Scheduled steady-state governance wrapper.

This is glue only — it invokes the EXISTING steady-state entrypoints from the
target environment directory, exactly as the `make` targets do. It contains no
classification / re-derive logic of its own:

  audit    -> scripts/audit_schema_drift.py            (== make audit-schema)
  delta    -> generate_abac.py --delta --auth-file ...  (== make generate-delta)
  coverage -> validate_abac.py generated/abac.auto.tfvars [generated/masking_functions.sql]
              (== make validate-generated)

The steady-state scripts resolve config via relative paths from the environment
directory (envs/<env>/), so this wrapper just `chdir`s there and shells out to
them using the same interpreter. It is meant to be driven by the scheduled
Databricks Job defined in roots/workspace/scheduled_governance.tf, one task per
`--step`, but also runs standalone for local testing.

Exit codes mirror the wrapped script:
  audit    — 0 = no drift, 1 = drift detected (a scheduled run going red is the
             drift signal; the delta task is wired with run_if = ALL_DONE so it
             still runs and resolves the drift).
  delta    — passthrough from generate_abac.py.
  coverage — passthrough from validate_abac.py.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
SHARED_ROOT = SCRIPTS_DIR.parent
REPO_ROOT = SHARED_ROOT.parent

STEPS = ("audit", "delta", "coverage")


def _resolve_env_dir(env_dir_arg: str) -> Path:
    """Resolve the target env directory (absolute, or repo-relative like
    'aws/envs/prod') to an absolute path."""
    p = Path(env_dir_arg)
    if not p.is_absolute():
        p = (REPO_ROOT / p).resolve()
    return p


def _run(cmd: list[str], cwd: Path) -> int:
    print(f"+ (cd {cwd} && {' '.join(cmd)})", flush=True)
    return subprocess.run(cmd, cwd=str(cwd)).returncode


def _audit(env_dir: Path) -> int:
    return _run(
        [sys.executable, str(SCRIPTS_DIR / "audit_schema_drift.py")],
        cwd=env_dir,
    )


def _delta(env_dir: Path, auth_file: str) -> int:
    return _run(
        [sys.executable, str(SHARED_ROOT / "generate_abac.py"),
         "--delta", "--auth-file", auth_file],
        cwd=env_dir,
    )


def _coverage(env_dir: Path) -> int:
    tfvars = env_dir / "generated" / "abac.auto.tfvars"
    if not tfvars.exists():
        print(f"  Coverage check: no {tfvars} to validate — nothing to check.")
        return 0
    cmd = [sys.executable, str(SHARED_ROOT / "validate_abac.py"), str(tfvars)]
    masking = env_dir / "generated" / "masking_functions.sql"
    if masking.exists():
        cmd.append(str(masking))
    return _run(cmd, cwd=env_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-dir", required=True,
                        help="Target environment directory (absolute, or repo-relative like 'aws/envs/prod').")
    parser.add_argument("--step", choices=(*STEPS, "all"), default="all",
                        help="Which steady-state step to run (default: all, in order audit -> delta -> coverage).")
    parser.add_argument("--auth-file", default="auth.auto.tfvars",
                        help="Auth tfvars filename passed to generate_abac.py --delta (default: auth.auto.tfvars).")
    args = parser.parse_args()

    env_dir = _resolve_env_dir(args.env_dir)
    if not env_dir.is_dir():
        print(f"ERROR: env directory not found: {env_dir}", file=sys.stderr)
        return 2

    steps = STEPS if args.step == "all" else (args.step,)
    rc = 0
    for step in steps:
        print("=" * 60)
        print(f"  Scheduled governance step: {step}  (env: {env_dir.name})")
        print("=" * 60)
        if step == "audit":
            step_rc = _audit(env_dir)
        elif step == "delta":
            step_rc = _delta(env_dir, args.auth_file)
        else:
            step_rc = _coverage(env_dir)
        # For a single-step invocation, mirror the wrapped script's exit code.
        # For --step all, keep going but remember the last non-zero code.
        if step_rc != 0:
            rc = step_rc
    return rc


if __name__ == "__main__":
    sys.exit(main())
