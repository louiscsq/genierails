"""Unit tests for verify_effective_access.py.

These exercise the *pure* comparison and spec-derivation logic with mocked
query results — no Databricks connection, no warehouse, no service principals.
The live workspace path (EffectiveAccessVerifier / verify_effective_access_live)
is guarded behind GENIERAILS_LIVE_VERIFY and is not exercised here; only its
guard is asserted.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from verify_effective_access import (  # noqa: E402
    PASS,
    FAIL,
    SKIP,
    DEFAULT_ADMIN_TIER,
    ColumnMaskCheck,
    RowFilterCheck,
    VerificationSpec,
    CheckResult,
    EffectiveAccessReport,
    parse_tag_conditions,
    resolve_columns_for_condition,
    derive_spec_from_config,
    evaluate_column_mask_check,
    evaluate_row_filter_check,
    evaluate_effective_access,
    load_spec_from_file,
    verify_effective_access_live,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _mask_check(masked=("Junior_Analyst",), unmasked=("Compliance_Officer",)):
    return ColumnMaskCheck(
        table="fin.finance.customers",
        column="ssn",
        key_column="customer_id",
        masked_principals=tuple(masked),
        unmasked_principals=tuple(unmasked),
        policy_name="mask_pii_ssn",
    )


def _filter_check(restricted=("Junior_Analyst",), unrestricted=("Compliance_Officer",)):
    return RowFilterCheck(
        table="fin.finance.transactions",
        restricted_principals=tuple(restricted),
        unrestricted_principals=tuple(unrestricted),
        policy_name="filter_aml_clearance",
    )


# ---------------------------------------------------------------------------
# Column-mask comparison
# ---------------------------------------------------------------------------
class TestColumnMaskComparison:
    def test_masking_effective_passes(self):
        """Masked principal sees masked value, unmasked sees raw -> PASS."""
        check = _mask_check()
        values = {
            "Junior_Analyst":     {1: "XXX-XX-6789", 2: "XXX-XX-1111"},
            "Compliance_Officer": {1: "123-45-6789", 2: "987-65-1111"},
        }
        result = evaluate_column_mask_check(check, values)
        assert result.status == PASS
        assert result.evidence["compared_rows"] == 2
        assert result.evidence["masked_ok"] == 2

    def test_leak_fails(self):
        """Masked principal sees the SAME raw value -> FAIL (leak)."""
        check = _mask_check()
        values = {
            "Junior_Analyst":     {1: "123-45-6789", 2: "XXX-XX-1111"},
            "Compliance_Officer": {1: "123-45-6789", 2: "987-65-1111"},
        }
        result = evaluate_column_mask_check(check, values)
        assert result.status == FAIL
        assert result.evidence["leaks"][0]["row_key"] == 1
        assert "leaked" in result.detail

    def test_null_and_empty_raw_values_not_counted_as_leak(self):
        """NULL/empty raw values are not maskable and must not fail the check."""
        check = _mask_check()
        values = {
            "Junior_Analyst":     {1: None, 2: "", 3: "XXX-XX-3333"},
            "Compliance_Officer": {1: None, 2: "", 3: "111-22-3333"},
        }
        result = evaluate_column_mask_check(check, values)
        assert result.status == PASS
        # Only row 3 had a maskable raw value.
        assert result.evidence["masked_ok"] == 1

    def test_value_normalization_across_types(self):
        """Numeric-looking values compare after string-normalization."""
        check = ColumnMaskCheck(
            table="fin.finance.transactions", column="amount",
            key_column="txn_id",
            masked_principals=("Junior_Analyst",),
            unmasked_principals=("Compliance_Officer",),
        )
        values = {
            "Junior_Analyst":     {1: 1200.00, 2: 3400.00},   # rounded
            "Compliance_Officer": {1: 1234.56, 2: 3456.78},   # raw
        }
        result = evaluate_column_mask_check(check, values)
        assert result.status == PASS

    def test_no_unmasked_principal_skips(self):
        check = _mask_check(unmasked=("Compliance_Officer",))
        values = {"Junior_Analyst": {1: "XXX-XX-6789"}}
        result = evaluate_column_mask_check(check, values)
        assert result.status == SKIP
        assert "unmasked" in result.detail

    def test_no_masked_principal_skips(self):
        check = _mask_check()
        values = {"Compliance_Officer": {1: "123-45-6789"}}
        result = evaluate_column_mask_check(check, values)
        assert result.status == SKIP

    def test_no_overlapping_rows_skips(self):
        check = _mask_check()
        values = {
            "Junior_Analyst":     {5: "XXX-XX-0000"},
            "Compliance_Officer": {1: "123-45-6789"},
        }
        result = evaluate_column_mask_check(check, values)
        assert result.status == SKIP
        assert "overlapping" in result.detail

    def test_admin_baseline_used_as_raw(self):
        check = _mask_check(unmasked=(DEFAULT_ADMIN_TIER,))
        values = {
            "Junior_Analyst":     {1: "XXX-XX-6789"},
            DEFAULT_ADMIN_TIER:   {1: "123-45-6789"},
        }
        result = evaluate_column_mask_check(check, values)
        assert result.status == PASS

    def test_partial_leak_fails_even_if_some_rows_masked(self):
        check = _mask_check()
        values = {
            "Junior_Analyst":     {1: "XXX-XX-6789", 2: "987-65-1111"},  # row 2 leaks
            "Compliance_Officer": {1: "123-45-6789", 2: "987-65-1111"},
        }
        result = evaluate_column_mask_check(check, values)
        assert result.status == FAIL
        assert len(result.evidence["leaks"]) == 1


# ---------------------------------------------------------------------------
# Row-filter comparison
# ---------------------------------------------------------------------------
class TestRowFilterComparison:
    def test_filter_effective_passes(self):
        check = _filter_check()
        counts = {"Junior_Analyst": 8, "Compliance_Officer": 15}
        result = evaluate_row_filter_check(check, counts)
        assert result.status == PASS

    def test_no_restriction_fails(self):
        check = _filter_check()
        counts = {"Junior_Analyst": 15, "Compliance_Officer": 15}
        result = evaluate_row_filter_check(check, counts)
        assert result.status == FAIL
        assert "not effective" in result.detail

    def test_restricted_sees_more_fails(self):
        check = _filter_check()
        counts = {"Junior_Analyst": 20, "Compliance_Officer": 15}
        result = evaluate_row_filter_check(check, counts)
        assert result.status == FAIL

    def test_restricted_sees_zero_passes(self):
        check = _filter_check()
        counts = {"Junior_Analyst": 0, "Compliance_Officer": 15}
        result = evaluate_row_filter_check(check, counts)
        assert result.status == PASS

    def test_missing_unrestricted_skips(self):
        check = _filter_check()
        counts = {"Junior_Analyst": 5}
        result = evaluate_row_filter_check(check, counts)
        assert result.status == SKIP

    def test_missing_restricted_skips(self):
        check = _filter_check()
        counts = {"Compliance_Officer": 15}
        result = evaluate_row_filter_check(check, counts)
        assert result.status == SKIP

    def test_zero_baseline_skips(self):
        check = _filter_check()
        counts = {"Junior_Analyst": 0, "Compliance_Officer": 0}
        result = evaluate_row_filter_check(check, counts)
        assert result.status == SKIP
        assert "nothing to restrict" in result.detail

    def test_none_counts_ignored(self):
        """A principal that couldn't read (None) is treated as absent."""
        check = _filter_check(restricted=("Junior_Analyst", "Senior_Analyst"))
        counts = {"Junior_Analyst": None, "Senior_Analyst": 8, "Compliance_Officer": 15}
        result = evaluate_row_filter_check(check, counts)
        assert result.status == PASS


# ---------------------------------------------------------------------------
# Tag-condition parsing / column resolution
# ---------------------------------------------------------------------------
class TestTagConditionParsing:
    def test_parse_single_condition(self):
        assert parse_tag_conditions("hasTagValue('pii_level', 'masked_ssn')") == [
            ("pii_level", "masked_ssn")
        ]

    def test_parse_double_quotes(self):
        assert parse_tag_conditions('hasTagValue("pci_level", "redacted_cvv")') == [
            ("pci_level", "redacted_cvv")
        ]

    def test_parse_multiple_conditions(self):
        cond = "hasTagValue('a','1') OR hasTagValue('b','2')"
        assert parse_tag_conditions(cond) == [("a", "1"), ("b", "2")]

    def test_parse_empty(self):
        assert parse_tag_conditions("") == []
        assert parse_tag_conditions(None) == []

    def test_resolve_columns(self):
        tag_assignments = [
            {"entity_type": "columns", "entity_name": "fin.finance.customers.ssn",
             "tag_key": "pii_level", "tag_value": "masked_ssn"},
            {"entity_type": "columns", "entity_name": "fin.finance.customers.email",
             "tag_key": "pii_level", "tag_value": "masked_email"},
        ]
        cols = resolve_columns_for_condition(
            "hasTagValue('pii_level', 'masked_ssn')", tag_assignments
        )
        assert cols == [{"table": "fin.finance.customers", "column": "ssn"}]

    def test_resolve_tables(self):
        tag_assignments = [
            {"entity_type": "tables", "entity_name": "fin.finance.transactions",
             "tag_key": "compliance_scope", "tag_value": "aml_restricted"},
        ]
        tables = resolve_columns_for_condition(
            "hasTagValue('compliance_scope', 'aml_restricted')",
            tag_assignments, entity_type="tables",
        )
        assert tables == [{"table": "fin.finance.transactions", "column": ""}]

    def test_resolve_handles_hcl_list_wrapped_scalars(self):
        """hcl2 wraps scalars in single-item lists — resolution must cope."""
        tag_assignments = [
            {"entity_type": ["columns"], "entity_name": ["fin.finance.customers.ssn"],
             "tag_key": ["pii_level"], "tag_value": ["masked_ssn"]},
        ]
        cols = resolve_columns_for_condition(
            "hasTagValue('pii_level', 'masked_ssn')", tag_assignments
        )
        assert cols == [{"table": "fin.finance.customers", "column": "ssn"}]


# ---------------------------------------------------------------------------
# Spec derivation from config
# ---------------------------------------------------------------------------
class TestDeriveSpec:
    FGAC = [
        {
            "name": "mask_pii_ssn", "policy_type": "POLICY_TYPE_COLUMN_MASK",
            "to_principals": ["Junior_Analyst"],
            "match_condition": "hasTagValue('pii_level', 'masked_ssn')",
            "function_name": "mask_ssn",
        },
        {
            "name": "filter_aml", "policy_type": "POLICY_TYPE_ROW_FILTER",
            "to_principals": ["Junior_Analyst", "Senior_Analyst"],
            "when_condition": "hasTagValue('compliance_scope', 'aml_restricted')",
            "function_name": "filter_aml_clearance",
        },
    ]
    TAGS = [
        {"entity_type": "columns", "entity_name": "fin.finance.customers.ssn",
         "tag_key": "pii_level", "tag_value": "masked_ssn"},
        {"entity_type": "tables", "entity_name": "fin.finance.transactions",
         "tag_key": "compliance_scope", "tag_value": "aml_restricted"},
    ]
    GROUPS = ["Junior_Analyst", "Senior_Analyst", "Compliance_Officer"]

    def test_derives_column_mask(self):
        spec = derive_spec_from_config(
            self.FGAC, self.TAGS, self.GROUPS, key_column="customer_id",
        )
        assert len(spec.column_masks) == 1
        mc = spec.column_masks[0]
        assert mc.table == "fin.finance.customers"
        assert mc.column == "ssn"
        assert mc.key_column == "customer_id"
        assert mc.masked_principals == ("Junior_Analyst",)
        # Senior + Compliance are unmasked, plus the admin baseline.
        assert "Senior_Analyst" in mc.unmasked_principals
        assert "Compliance_Officer" in mc.unmasked_principals
        assert DEFAULT_ADMIN_TIER in mc.unmasked_principals
        assert "Junior_Analyst" not in mc.unmasked_principals

    def test_derives_row_filter(self):
        spec = derive_spec_from_config(self.FGAC, self.TAGS, self.GROUPS)
        assert len(spec.row_filters) == 1
        rf = spec.row_filters[0]
        assert rf.table == "fin.finance.transactions"
        assert set(rf.restricted_principals) == {"Junior_Analyst", "Senior_Analyst"}
        assert "Compliance_Officer" in rf.unrestricted_principals

    def test_all_users_mask_only_exceptions_are_unmasked(self):
        """A mask targeting 'account users' masks every concrete tier except the
        exceptions, and the exceptions are the only raw baseline (admin is also
        a member of 'account users' so it is NOT a baseline)."""
        fgac = [{
            "name": "mask_cvv", "policy_type": "POLICY_TYPE_COLUMN_MASK",
            "to_principals": ["account users"],
            "except_principals": ["Compliance_Officer"],
            "match_condition": "hasTagValue('pci_level', 'redacted_cvv')",
        }]
        tags = [{"entity_type": "columns",
                 "entity_name": "fin.finance.credit_cards.cvv",
                 "tag_key": "pci_level", "tag_value": "redacted_cvv"}]
        spec = derive_spec_from_config(
            fgac, tags, ["Junior_Analyst", "Senior_Analyst", "Compliance_Officer"],
        )
        mc = spec.column_masks[0]
        # 'account users' itself is never a provisionable principal.
        assert "account users" not in mc.masked_principals
        assert "account users" not in mc.unmasked_principals
        assert set(mc.masked_principals) == {"Junior_Analyst", "Senior_Analyst"}
        assert mc.unmasked_principals == ("Compliance_Officer",)
        # Admin is NOT a raw baseline for an all-users mask.
        assert DEFAULT_ADMIN_TIER not in mc.unmasked_principals

    def test_key_column_by_table_overrides_default(self):
        spec = derive_spec_from_config(
            self.FGAC, self.TAGS, self.GROUPS,
            key_column="id",
            key_column_by_table={"fin.finance.customers": "customer_id"},
        )
        assert spec.column_masks[0].key_column == "customer_id"

    def test_unmatched_condition_yields_no_check(self):
        fgac = [{
            "name": "mask_orphan", "policy_type": "POLICY_TYPE_COLUMN_MASK",
            "to_principals": ["Junior_Analyst"],
            "match_condition": "hasTagValue('nonexistent', 'value')",
        }]
        spec = derive_spec_from_config(fgac, self.TAGS, self.GROUPS)
        assert spec.column_masks == []

    def test_spec_principals_excludes_admin(self):
        spec = derive_spec_from_config(self.FGAC, self.TAGS, self.GROUPS)
        assert DEFAULT_ADMIN_TIER not in spec.principals
        assert "Junior_Analyst" in spec.principals

    def test_hcl_list_wrapped_policy_fields(self):
        """Fields parsed by hcl2 as single-item lists still derive correctly."""
        fgac = [{
            "name": ["mask_pii_ssn"], "policy_type": ["POLICY_TYPE_COLUMN_MASK"],
            "to_principals": ["Junior_Analyst"],
            "match_condition": ["hasTagValue('pii_level', 'masked_ssn')"],
        }]
        spec = derive_spec_from_config(fgac, self.TAGS, self.GROUPS, key_column="customer_id")
        assert len(spec.column_masks) == 1
        assert spec.column_masks[0].policy_name == "mask_pii_ssn"


# ---------------------------------------------------------------------------
# Report aggregation
# ---------------------------------------------------------------------------
class TestReport:
    def test_report_passed_when_all_pass(self):
        spec = VerificationSpec(column_masks=[_mask_check()], row_filters=[_filter_check()])
        column_values = {
            ("fin.finance.customers", "ssn"): {
                "Junior_Analyst":     {1: "XXX-XX-6789"},
                "Compliance_Officer": {1: "123-45-6789"},
            }
        }
        row_counts = {"fin.finance.transactions": {"Junior_Analyst": 8, "Compliance_Officer": 15}}
        report = evaluate_effective_access(spec, column_values, row_counts)
        assert report.passed
        assert report.counts()[PASS] == 2
        assert report.failures == []

    def test_report_fails_on_leak(self):
        spec = VerificationSpec(column_masks=[_mask_check()])
        column_values = {
            ("fin.finance.customers", "ssn"): {
                "Junior_Analyst":     {1: "123-45-6789"},
                "Compliance_Officer": {1: "123-45-6789"},
            }
        }
        report = evaluate_effective_access(spec, column_values, {})
        assert not report.passed
        assert len(report.failures) == 1

    def test_summary_renders_markers(self):
        report = EffectiveAccessReport()
        report.add(CheckResult("column-mask", "x", PASS, "ok"))
        report.add(CheckResult("row-filter", "y", FAIL, "leaked"))
        text = report.summary()
        assert "✓" in text and "✗" in text
        assert "1 FAILED" in text

    def test_skip_counts_as_ok(self):
        report = EffectiveAccessReport()
        report.add(CheckResult("column-mask", "x", SKIP, "no data"))
        assert report.passed
        assert report.counts()[SKIP] == 1


# ---------------------------------------------------------------------------
# Spec file loading
# ---------------------------------------------------------------------------
class TestSpecLoading:
    def test_load_spec_from_json(self, tmp_path):
        spec_file = tmp_path / "spec.json"
        spec_file.write_text("""
        {
          "column_masks": [
            {"table": "c.s.t", "column": "ssn", "key_column": "id",
             "masked_principals": ["Junior"], "unmasked_principals": ["Senior"],
             "policy_name": "m1"}
          ],
          "row_filters": [
            {"table": "c.s.t2", "restricted_principals": ["Junior"],
             "unrestricted_principals": ["Senior"], "policy_name": "f1"}
          ]
        }
        """)
        spec = load_spec_from_file(spec_file)
        assert len(spec.column_masks) == 1
        assert spec.column_masks[0].column == "ssn"
        assert len(spec.row_filters) == 1
        assert spec.row_filters[0].table == "c.s.t2"


# ---------------------------------------------------------------------------
# Live guard
# ---------------------------------------------------------------------------
class TestLiveGuard:
    def test_live_disabled_without_env(self, tmp_path, monkeypatch):
        monkeypatch.delenv("GENIERAILS_LIVE_VERIFY", raising=False)
        with pytest.raises(RuntimeError, match="Live verification is disabled"):
            verify_effective_access_live(
                VerificationSpec(column_masks=[_mask_check()]),
                tmp_path / "auth.auto.tfvars",
            )
