#!/usr/bin/env python3
"""Refuse masks/policies on governed columns that GenieRails does not own."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SHARED = Path(__file__).resolve().parents[1]
if str(SHARED) not in sys.path:
    sys.path.insert(0, str(SHARED))

from scripts.audit_schema_drift import _get_sdk_client, _get_warehouse_id, _load_hcl, _run_sql


def external_masks(governed_columns: set[str], configured_policies: set[str],
                   direct_rows: list[list[str]], effective_rows: list[list[str]]) -> list[str]:
    problems: set[str] = set()
    governed = {item.lower() for item in governed_columns}
    for row in direct_rows:
        if len(row) >= 5:
            column = ".".join(str(v) for v in row[:4])
            mask = str(row[4] or "")
            if column.lower() in governed and not mask.split(".")[-1].startswith("gr_mask_"):
                problems.add(f"{column}: table-attached mask {mask}")
    for row in effective_rows:
        text = " | ".join(str(value or "") for value in row)
        if any(column in text.lower() for column in governed):
            names = {name for name in configured_policies if name in text}
            if not names and "gr_mask_" not in text:
                problems.add(f"external effective policy: {text}")
    return sorted(problems)


def inventory(env_dir: Path) -> list[str]:
    cfg = _load_hcl(env_dir / "generated" / "abac.auto.tfvars")
    columns = {
        str(item.get("entity_name")) for item in cfg.get("tag_assignments") or []
        if item.get("entity_type") == "columns" and item.get("tag_key") == "gr_treatment"
    }
    if not columns:
        return []
    policies = {str(item.get("name")) for item in cfg.get("fgac_policies") or []}
    tables = sorted({".".join(column.split(".")[:3]) for column in columns})
    w = _get_sdk_client(env_dir)
    warehouse = _get_warehouse_id(env_dir, w)
    if not warehouse:
        raise RuntimeError("no SQL warehouse is available for external-mask inventory")
    quoted = ",".join("'" + value.replace("'", "''") + "'" for value in sorted(columns))
    direct = _run_sql(w, warehouse,
        "SELECT table_catalog, table_schema, table_name, column_name, mask_name "
        "FROM system.information_schema.column_masks WHERE concat(table_catalog,'.',table_schema,'.',table_name,'.',column_name) "
        f"IN ({quoted})")
    effective: list[list[str]] = []
    for table in tables:
        effective.extend(_run_sql(w, warehouse, f"SHOW EFFECTIVE POLICIES ON TABLE {table}"))
    return external_masks(columns, policies, direct, effective)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        problems = inventory(args.env_dir)
    except Exception as exc:
        print(f"ERROR: external-mask inventory failed: {exc}", file=sys.stderr)
        return 2
    if problems:
        print("ERROR: external mask or ABAC policy found on a governed column; refusing to apply:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("External-mask inventory passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
