#!/usr/bin/env python3
"""Accept an empty account plan; applying workflows may only sync tag values."""
import json
import sys

plan = json.load(sys.stdin)
changes = []
for item in plan.get("resource_changes", []):
    actions = item.get("change", {}).get("actions", [])
    if actions not in ([], ["no-op"], ["read"]):
        changes.append(f"{item.get('address')}: {','.join(actions)}")
if changes:
    print("ERROR: account plan is non-empty; rehearse/release may only add allowed treatment-tag values.", file=sys.stderr)
    for change in changes:
        print(f"  - {change}", file=sys.stderr)
    print("Run `make apply-account` in the approved operations stage.", file=sys.stderr)
    raise SystemExit(1)
