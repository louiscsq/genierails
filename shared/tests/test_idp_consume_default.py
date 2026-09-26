"""Tests for IdP-CONSUME-BY-DEFAULT (#31).

Two layers, both without any Databricks / LLM / Terraform runtime:

  1. The generate_abac.py group preflight — consume-by-default verifies that
     referenced access-tier groups already exist as IdP-synced account groups,
     failing loudly (naming the missing group) otherwise; the opt-in create
     path is a no-op.

  2. The account Terraform module/root wiring — groups are looked up by name
     (not created) by default, membership is not managed by default, and the
     opt-in create path still mints groups. Asserted structurally by parsing
     the .tf files with hcl2 (no terraform binary required).
"""
import sys
from pathlib import Path

import hcl2
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from generate_abac import (
    GroupPreflightError,
    find_missing_idp_groups,
    preflight_consume_groups,
)

SHARED = Path(__file__).parent.parent
ACCOUNT_MODULE = SHARED / "modules" / "account"
ACCOUNT_ROOT = SHARED / "roots" / "account"


# ---------------------------------------------------------------------------
# generate_abac.py — group preflight
# ---------------------------------------------------------------------------
class TestFindMissingIdpGroups:
    def test_none_missing(self):
        assert find_missing_idp_groups(["A", "B"], ["A", "B", "C"]) == []

    def test_reports_missing(self):
        assert find_missing_idp_groups(["A", "X"], ["A", "B"]) == ["X"]

    def test_preserves_order_and_dedupes(self):
        assert find_missing_idp_groups(["X", "Y", "X", "A"], ["A"]) == ["X", "Y"]

    def test_empty_referenced(self):
        assert find_missing_idp_groups([], ["A"]) == []

    def test_ignores_falsy_names(self):
        assert find_missing_idp_groups(["", "A"], ["", "B"]) == ["A"]


class TestPreflightConsumeGroups:
    def test_all_present_is_noop(self):
        # No exception when every referenced group exists.
        preflight_consume_groups(["Finance_Analyst"], ["Finance_Analyst", "Admin"])

    def test_missing_group_fails_loudly_and_names_it(self):
        with pytest.raises(GroupPreflightError) as excinfo:
            preflight_consume_groups(
                ["Finance_Analyst", "Ghost_Group"],
                ["Finance_Analyst"],
                create_groups=False,
            )
        msg = str(excinfo.value)
        # The missing group is named, the present one is not flagged.
        assert "Ghost_Group" in msg
        assert "preflight failed" in msg.lower()
        # Actionable remediation is surfaced.
        assert "AIM" in msg or "SCIM" in msg
        assert "--create-groups" in msg

    def test_create_groups_opt_in_skips_preflight(self):
        # In the demo/greenfield create path, a not-yet-existing group is fine.
        preflight_consume_groups(
            ["Brand_New_Group"], [], create_groups=True
        )


# ---------------------------------------------------------------------------
# Terraform wiring — parsed structurally with hcl2 (no terraform binary)
# ---------------------------------------------------------------------------
def _load_tf(path: Path) -> dict:
    with open(path) as f:
        return hcl2.load(f)


def _variable_default(tf: dict, name: str):
    for v in tf.get("variable", []):
        if name in v:
            return v[name].get("default")
    raise AssertionError(f"variable {name!r} not found")


def _block_for_each(tf: dict, kind: str, block_type: str, block_name: str) -> str:
    for block in tf.get(kind, []):
        named = block.get(block_type)
        if named and block_name in named:
            return named[block_name].get("for_each", "")
    raise AssertionError(f"{kind} {block_type}.{block_name} not found")


class TestAccountModuleConsumeByDefault:
    def test_module_manage_groups_defaults_to_false(self):
        tf = _load_tf(ACCOUNT_MODULE / "variables.tf")
        assert _variable_default(tf, "manage_groups") is False

    def test_root_manage_groups_defaults_to_false(self):
        tf = _load_tf(ACCOUNT_ROOT / "main.tf")
        assert _variable_default(tf, "manage_groups") is False

    def test_default_path_looks_up_groups_via_data_source(self):
        tf = _load_tf(ACCOUNT_MODULE / "main.tf")
        fe = _block_for_each(tf, "data", "databricks_group", "consumed")
        # Consumes var.groups when NOT managing (the default false branch).
        assert "manage_groups" in fe
        assert "var.groups" in fe
        # Empty in the manage/create branch — no lookup when we create.
        assert "{}" in fe

    def test_default_path_does_not_create_groups(self):
        tf = _load_tf(ACCOUNT_MODULE / "main.tf")
        fe = _block_for_each(tf, "resource", "databricks_group", "groups")
        # Creation is gated on manage_groups; empty map otherwise (default).
        assert "manage_groups" in fe
        assert "var.groups" in fe

    def test_membership_not_managed_by_default(self):
        tf = _load_tf(ACCOUNT_MODULE / "main.tf")
        fe = _block_for_each(tf, "resource", "databricks_group_member", "members")
        assert "manage_groups" in fe
        assert "local.group_member_map" in fe

    def test_opt_in_create_path_still_present(self):
        # The databricks_group resource (create path) must not be deleted —
        # it is demoted to opt-in, not removed.
        tf = _load_tf(ACCOUNT_MODULE / "main.tf")
        names = {
            name
            for block in tf.get("resource", [])
            for typ, named in block.items()
            if typ == "databricks_group"
            for name in named
        }
        assert "groups" in names
