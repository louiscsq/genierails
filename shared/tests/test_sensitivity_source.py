"""Unit tests for the SensitivitySource abstraction (issue #30).

Covers:
  * ClassificationSource reading native UC Data Classification (class.* column
    tags and data_classification.results) with the system-table reads mocked.
  * The default classification-else-LLM selection rule (select_findings).
  * The generate_abac.autofix_untagged_pii_columns integration: native
    classification wins per column, and behaviour is unchanged when there is no
    native classification.

No Databricks, LLM, or Terraform dependency — reads are mocked.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from sensitivity_source import (
    CLASSIFICATION,
    LLM,
    ClassificationSource,
    ClassificationScan,
    Finding,
    LLMSource,
    classification_decision,
    scan_from_run_sql,
    select_findings,
    SCAN_CLASSIFIED,
    SCAN_NO_TAGS,
    SCAN_UNAVAILABLE,
    SCAN_ERROR,
    DECISION_USE_CLASSIFICATION,
    DECISION_USE_LLM,
    DECISION_FAIL_CLOSED,
)
from tests.conftest import assert_valid_hcl


# ---------------------------------------------------------------------------
# ClassificationSource — native class.* column tags (mocked rows)
# ---------------------------------------------------------------------------
class TestClassificationSourceColumnTags:
    def test_maps_class_suffix_tag_to_governed(self):
        rows = [
            ("cat", "sch", "tbl", "email", "class.email", ""),
            ("cat", "sch", "tbl", "card", "class.credit_card", ""),
        ]
        src = ClassificationSource(tag_rows=rows)
        findings = {f.entity_name: f for f in src.findings_for([
            "cat.sch.tbl.email", "cat.sch.tbl.card",
        ])}
        assert findings["cat.sch.tbl.email"].tag_key == "pii_level"
        assert findings["cat.sch.tbl.email"].tag_value == "masked_email"
        assert findings["cat.sch.tbl.card"].tag_key == "pci_level"
        assert findings["cat.sch.tbl.card"].tag_value == "masked_card_last4"
        # every finding is labelled as coming from classification
        assert all(f.source == CLASSIFICATION for f in findings.values())
        assert findings["cat.sch.tbl.email"].detail == "class.email"

    def test_semantic_carried_in_tag_value(self):
        # Some deployments store the semantic in the value, key == "class".
        rows = [("cat", "sch", "tbl", "phone", "class", "phone_number")]
        src = ClassificationSource(tag_rows=rows)
        findings = src.findings_for(["cat.sch.tbl.phone"])
        assert len(findings) == 1
        assert (findings[0].tag_key, findings[0].tag_value) == ("pii_level", "masked_phone")

    def test_filters_to_requested_columns(self):
        rows = [
            ("cat", "sch", "tbl", "email", "class.email", ""),
            ("cat", "sch", "other", "email", "class.email", ""),
        ]
        src = ClassificationSource(tag_rows=rows)
        findings = src.findings_for(["cat.sch.tbl.email"])
        assert [f.entity_name for f in findings] == ["cat.sch.tbl.email"]

    def test_unmapped_semantic_produces_no_finding_but_counts_as_classified(self):
        rows = [("cat", "sch", "tbl", "mystery", "class.some_novel_type", "")]
        src = ClassificationSource(tag_rows=rows)
        assert src.findings_for(["cat.sch.tbl.mystery"]) == []
        # still recognised as a natively-classified column (so LLM won't override)
        assert src.classified_columns() == {"cat.sch.tbl.mystery"}
        assert src.has_native_data() is True

    def test_non_class_tags_ignored(self):
        rows = [("cat", "sch", "tbl", "email", "team", "growth")]
        src = ClassificationSource(tag_rows=rows)
        assert src.findings_for(["cat.sch.tbl.email"]) == []
        assert src.classified_columns() == set()

    def test_dedup_repeated_rows(self):
        rows = [
            ("cat", "sch", "tbl", "email", "class.email", ""),
            ("cat", "sch", "tbl", "email", "class.email", ""),
        ]
        src = ClassificationSource(tag_rows=rows)
        assert len(src.findings_for(["cat.sch.tbl.email"])) == 1

    def test_empty_source_has_no_native_data(self):
        src = ClassificationSource()
        assert src.has_native_data() is False
        assert src.findings_for(["cat.sch.tbl.email"]) == []


# ---------------------------------------------------------------------------
# ClassificationSource — data_classification.results rows
# ---------------------------------------------------------------------------
class TestClassificationSourceResults:
    def test_maps_results_rows(self):
        rows = [("cat", "sch", "tbl", "ssn", "social_security_number")]
        src = ClassificationSource(classification_rows=rows)
        findings = src.findings_for(["cat.sch.tbl.ssn"])
        assert len(findings) == 1
        assert (findings[0].tag_key, findings[0].tag_value) == ("pii_level", "masked_ssn")
        assert findings[0].source == CLASSIFICATION

    def test_maps_namespaced_class_tag_value(self):
        # data_classification.results.class_tag may be namespaced (class.us_ssn).
        rows = [("cat", "sch", "tbl", "national_id", "class.us_ssn")]
        src = ClassificationSource(classification_rows=rows)
        findings = src.findings_for(["cat.sch.tbl.national_id"])
        assert [(f.tag_key, f.tag_value) for f in findings] == [("pii_level", "masked_ssn")]


# ---------------------------------------------------------------------------
# ClassificationSource.from_run_sql — mocked warehouse reads
# ---------------------------------------------------------------------------
class TestClassificationSourceFromRunSql:
    def test_queries_class_namespace_and_tolerates_missing_results_table(self):
        seen_sql = []

        def fake_run_sql(sql):
            seen_sql.append(sql)
            if "column_tags" in sql:
                return [["cat", "sch", "tbl", "email", "class.email", ""]]
            # system.data_classification.results does not exist on this workspace
            raise RuntimeError("Table or view not found: system.data_classification.results")

        src = ClassificationSource.from_run_sql(fake_run_sql, ["cat.sch.tbl"])
        findings = src.findings_for(["cat.sch.tbl.email"])
        assert [(f.tag_key, f.tag_value, f.source) for f in findings] == [
            ("pii_level", "masked_email", CLASSIFICATION)
        ]
        # The column_tags query is filtered to the class.* namespace and scoped
        # to the requested table.
        tags_sql = next(s for s in seen_sql if "column_tags" in s)
        assert "like 'class.%'" in tags_sql.lower()
        assert "'cat.sch.tbl'" in tags_sql

    def test_results_table_projection_uses_class_tag(self):
        # Regression: the results read must project `class_tag` (not the
        # non-existent `class_name`), and those rows must produce findings.
        seen_sql = []

        def fake_run_sql(sql):
            seen_sql.append(sql)
            if "data_classification.results" in sql:
                return [["cat", "sch", "tbl", "national_id", "class.us_ssn"]]
            return []  # no class.* column_tags

        src = ClassificationSource.from_run_sql(fake_run_sql, ["cat.sch.tbl"])
        results_sql = next(s for s in seen_sql if "data_classification.results" in s)
        assert "class_tag" in results_sql
        assert "class_name" not in results_sql
        findings = src.findings_for(["cat.sch.tbl.national_id"])
        assert [(f.tag_key, f.tag_value, f.source) for f in findings] == [
            ("pii_level", "masked_ssn", CLASSIFICATION)
        ]

    def test_non_absent_results_error_propagates(self):
        # from_run_sql must NOT swallow a permission/other results error as an
        # empty read — it propagates so callers can fail closed.
        def fake_run_sql(sql):
            if "column_tags" in sql:
                return [["cat", "sch", "tbl", "email", "class.email", ""]]
            raise RuntimeError("permission denied on system.data_classification.results")

        with pytest.raises(RuntimeError, match="permission denied"):
            ClassificationSource.from_run_sql(fake_run_sql, ["cat.sch.tbl"])

    def test_wildcard_refs_are_skipped(self):
        calls = []

        def fake_run_sql(sql):
            calls.append(sql)
            return []

        src = ClassificationSource.from_run_sql(fake_run_sql, ["cat.sch.*"])
        assert src.has_native_data() is False
        assert calls == []  # nothing concrete to query


# ---------------------------------------------------------------------------
# select_findings — the classification-else-LLM rule
# ---------------------------------------------------------------------------
def _llm_from(mapping):
    """Build an LLMSource whose inference returns a fixed per-column mapping."""
    def infer(columns):
        out = []
        for c in columns:
            if c in mapping:
                key, val = mapping[c]
                out.append(Finding(c, key, val, LLM))
        return out
    return LLMSource(infer)


class TestSelectFindings:
    def test_no_classification_returns_llm_findings_in_order(self):
        cols = ["t.a", "t.b", "t.c"]
        llm = _llm_from({"t.a": ("pii_level", "masked_email"),
                         "t.c": ("pii_level", "masked_phone")})
        # None classification source
        result = select_findings(cols, None, llm)
        assert [(f.entity_name, f.tag_value, f.source) for f in result] == [
            ("t.a", "masked_email", LLM),
            ("t.c", "masked_phone", LLM),
        ]
        # empty classification source behaves the same
        result2 = select_findings(cols, ClassificationSource(), llm)
        assert [f.entity_name for f in result2] == ["t.a", "t.c"]

    def test_classification_wins_for_its_columns(self):
        # LLM would tag t.x.y.a as email; classification says it is a credit card.
        classification = ClassificationSource(
            tag_rows=[("t", "x", "y", "a", "class.credit_card", "")],
        )
        cols = ["t.x.y.a", "t.x.y.b"]
        llm = _llm_from({"t.x.y.a": ("pii_level", "masked_email"),
                         "t.x.y.b": ("pii_level", "masked_phone")})
        result = {f.entity_name: f for f in select_findings(cols, classification, llm)}
        # t.x.y.a comes from classification (pci), NOT the LLM's email guess
        assert result["t.x.y.a"].source == CLASSIFICATION
        assert (result["t.x.y.a"].tag_key, result["t.x.y.a"].tag_value) == (
            "pci_level", "masked_card_last4")
        # t.x.y.b still falls back to the LLM
        assert result["t.x.y.b"].source == LLM
        assert result["t.x.y.b"].tag_value == "masked_phone"

    def test_classification_only_column_added_alongside_llm(self):
        cols = ["c.s.t.contact", "c.s.t.email"]
        classification = ClassificationSource(
            tag_rows=[("c", "s", "t", "contact", "class.email", "")],
        )
        llm = _llm_from({"c.s.t.email": ("pii_level", "masked_email")})
        result = {f.entity_name: f.source for f in select_findings(cols, classification, llm)}
        assert result == {"c.s.t.contact": CLASSIFICATION, "c.s.t.email": LLM}

    def test_unmapped_class_tag_is_authoritative_and_blocks_llm(self):
        # A class.* tag we do not map must NOT let the LLM tag that column.
        cols = ["c.s.t.mystery", "c.s.t.email"]
        classification = ClassificationSource(
            tag_rows=[("c", "s", "t", "mystery", "class.some_novel_type", "")],
        )
        llm = _llm_from({"c.s.t.mystery": ("pii_level", "masked_email"),
                         "c.s.t.email": ("pii_level", "masked_email")})
        result = select_findings(cols, classification, llm)
        by_name = {f.entity_name: f for f in result}
        # the classified-but-unmapped column produced no finding at all...
        assert "c.s.t.mystery" not in by_name
        # ...and crucially the LLM did NOT get to tag it
        assert not any(f.entity_name == "c.s.t.mystery" for f in result)
        # the un-classified column still falls back to the LLM
        assert by_name["c.s.t.email"].source == LLM
        # and it is reported as authoritative-but-unmapped for surfacing
        assert classification.unmapped_columns(cols) == [("c.s.t.mystery", "some_novel_type")]


# ---------------------------------------------------------------------------
# Fail-closed scan states + decision (BLOCKING #2)
# ---------------------------------------------------------------------------
class TestScanStates:
    def test_tags_present_is_classified(self):
        def run_sql(sql):
            if "column_tags" in sql:
                return [["c", "s", "t", "email", "class.email", ""]]
            return []
        scan = scan_from_run_sql(run_sql, ["c.s.t"])
        assert scan.state == SCAN_CLASSIFIED
        assert scan.is_classified is True
        assert scan.source is not None and scan.source.has_native_data()

    def test_clean_empty_scan_is_no_tags(self):
        scan = scan_from_run_sql(lambda sql: [], ["c.s.t"])
        assert scan.state == SCAN_NO_TAGS
        assert scan.is_classified is False
        assert scan.is_conclusive_negative is True
        assert scan.is_inconclusive is True

    def test_no_concrete_tables_is_unavailable(self):
        scan = scan_from_run_sql(lambda sql: [], ["c.s.*"])
        assert scan.state == SCAN_UNAVAILABLE
        assert scan.is_classified is False

    def test_failed_column_tags_read_is_error(self):
        def run_sql(sql):
            raise RuntimeError("permission denied on system.information_schema.column_tags")
        scan = scan_from_run_sql(run_sql, ["c.s.t"])
        assert scan.state == SCAN_ERROR
        assert scan.source is None

    def test_absent_results_table_alone_is_tolerated(self):
        # (a) A genuine "table or view not found" on the OPTIONAL results table
        # is tolerated: column_tags still make this a classified scan.
        def run_sql(sql):
            if "column_tags" in sql:
                return [["c", "s", "t", "email", "class.email", ""]]
            raise RuntimeError(
                "[TABLE_OR_VIEW_NOT_FOUND] The table or view "
                "`system`.`data_classification`.`results` cannot be found."
            )
        scan = scan_from_run_sql(run_sql, ["c.s.t"])
        assert scan.state == SCAN_CLASSIFIED

    def test_missing_results_schema_is_tolerated(self):
        # A missing system.data_classification SCHEMA is also "absent".
        def run_sql(sql):
            if "column_tags" in sql:
                return [["c", "s", "t", "email", "class.email", ""]]
            raise RuntimeError(
                "[SCHEMA_NOT_FOUND] The schema `system`.`data_classification` cannot be found."
            )
        scan = scan_from_run_sql(run_sql, ["c.s.t"])
        assert scan.state == SCAN_CLASSIFIED

    def test_results_permission_error_fails_closed_despite_tags(self):
        # (b) BLOCKING regression: a permission/other error on the AUTHORITATIVE
        # results table must NOT be swallowed as "absent" — even though
        # column_tags returned rows, the scan fails closed as SCAN_ERROR.
        def run_sql(sql):
            if "column_tags" in sql:
                return [["c", "s", "t", "email", "class.email", ""]]
            raise RuntimeError(
                "[INSUFFICIENT_PERMISSIONS] User does not have SELECT on "
                "system.data_classification.results"
            )
        scan = scan_from_run_sql(run_sql, ["c.s.t"])
        assert scan.state == SCAN_ERROR
        assert scan.is_classified is False
        assert scan.source is None

    def test_results_warehouse_timeout_fails_closed(self):
        def run_sql(sql):
            if "column_tags" in sql:
                return [["c", "s", "t", "email", "class.email", ""]]
            raise RuntimeError("statement execution timed out on the SQL warehouse")
        scan = scan_from_run_sql(run_sql, ["c.s.t"])
        assert scan.state == SCAN_ERROR

    def test_results_schema_drift_fails_closed(self):
        # Schema drift (renamed/removed column) says "not found" but is a real
        # error, not an absent table.
        def run_sql(sql):
            if "column_tags" in sql:
                return [["c", "s", "t", "email", "class.email", ""]]
            raise RuntimeError(
                "[UNRESOLVED_COLUMN.WITH_SUGGESTION] A column with name `class_tag` "
                "cannot be resolved."
            )
        scan = scan_from_run_sql(run_sql, ["c.s.t"])
        assert scan.state == SCAN_ERROR

    def test_states_are_distinct(self):
        classified = scan_from_run_sql(
            lambda s: [["c", "s", "t", "email", "class.email", ""]] if "column_tags" in s else [],
            ["c.s.t"],
        ).state
        no_tags = scan_from_run_sql(lambda s: [], ["c.s.t"]).state
        unavailable = scan_from_run_sql(lambda s: [], ["c.s.*"]).state
        error = scan_from_run_sql(lambda s: (_ for _ in ()).throw(RuntimeError("x")), ["c.s.t"]).state
        assert len({classified, no_tags, unavailable, error}) == 4


class TestClassificationDecision:
    def test_classified_always_uses_classification(self):
        scan = ClassificationScan(
            SCAN_CLASSIFIED,
            ClassificationSource(tag_rows=[("c", "s", "t", "email", "class.email", "")]),
            "1 classified column(s)",
        )
        assert classification_decision(scan, allow_llm_when_unverified=False) == DECISION_USE_CLASSIFICATION
        assert classification_decision(scan, allow_llm_when_unverified=True) == DECISION_USE_CLASSIFICATION

    @pytest.mark.parametrize("state", [SCAN_UNAVAILABLE, SCAN_ERROR, SCAN_NO_TAGS])
    def test_inconclusive_fails_closed_unless_opted_in(self, state):
        scan = ClassificationScan(state, None, "detail")
        # default: FAIL CLOSED — never a silent LLM fallback
        assert classification_decision(scan, allow_llm_when_unverified=False) == DECISION_FAIL_CLOSED
        # explicit opt-in downgrades to a distinctly-logged LLM fallback
        assert classification_decision(scan, allow_llm_when_unverified=True) == DECISION_USE_LLM

    def test_fail_closed_is_distinct_from_llm_fallback(self):
        # The three inconclusive states must NOT collapse to the same silent
        # LLM outcome as a positive classification.
        scan = ClassificationScan(SCAN_UNAVAILABLE, None, "no warehouse")
        assert classification_decision(scan, False) != DECISION_USE_LLM
        assert classification_decision(scan, False) != DECISION_USE_CLASSIFICATION


# ---------------------------------------------------------------------------
# main()-level wiring: _resolve_classification_source (BLOCKING #2 follow-up)
# ---------------------------------------------------------------------------
# These exercise the ACTUAL glue main() uses (scan -> decision -> exit/continue/
# log), so they fail if main() stops calling the decision or stops exiting 3 —
# unlike tests that only call classification_decision() directly.
class TestResolveClassificationSource:
    def _patch_scan(self, monkeypatch, scan):
        import generate_abac
        monkeypatch.setattr(generate_abac, "_scan_native_classification",
                            lambda table_refs, auth_cfg: scan)
        return generate_abac

    @pytest.mark.parametrize("state", [SCAN_UNAVAILABLE, SCAN_ERROR, SCAN_NO_TAGS])
    def test_inconclusive_scan_exits_3(self, monkeypatch, capsys, state):
        ga = self._patch_scan(monkeypatch, ClassificationScan(state, None, "detail"))
        with pytest.raises(SystemExit) as exc:
            ga._resolve_classification_source(["c.s.t"], {}, "full", allow_llm_sensitivity=False)
        assert exc.value.code == 3
        assert "FAIL-CLOSED" in capsys.readouterr().out

    @pytest.mark.parametrize("state", [SCAN_UNAVAILABLE, SCAN_ERROR, SCAN_NO_TAGS])
    def test_opt_in_continues_without_exit(self, monkeypatch, capsys, state):
        ga = self._patch_scan(monkeypatch, ClassificationScan(state, None, "detail"))
        # opt-in must NOT exit; returns None (LLM fallback) and logs the state.
        result = ga._resolve_classification_source(
            ["c.s.t"], {}, "full", allow_llm_sensitivity=True
        )
        assert result is None
        out = capsys.readouterr().out
        assert "UNVERIFIED" in out
        assert state in out  # the DISTINCT state is surfaced, not masked

    def test_classified_scan_returns_source(self, monkeypatch, capsys):
        src = ClassificationSource(tag_rows=[("c", "s", "t", "email", "class.email", "")])
        ga = self._patch_scan(
            monkeypatch, ClassificationScan(SCAN_CLASSIFIED, src, "1 classified column(s)")
        )
        result = ga._resolve_classification_source(
            ["c.s.t"], {}, "full", allow_llm_sensitivity=False
        )
        assert result is src
        assert "authoritative" in capsys.readouterr().out

    def test_genie_mode_skips_scan(self, monkeypatch):
        import generate_abac
        called = {"n": 0}

        def _boom(table_refs, auth_cfg):
            called["n"] += 1
            raise AssertionError("scan should not run in genie mode")

        monkeypatch.setattr(generate_abac, "_scan_native_classification", _boom)
        result = generate_abac._resolve_classification_source(
            ["c.s.t"], {}, "genie", allow_llm_sensitivity=False
        )
        assert result is None
        assert called["n"] == 0


# ---------------------------------------------------------------------------
# Integration: generate_abac.autofix_untagged_pii_columns
# ---------------------------------------------------------------------------
_TFVARS = """\
tag_assignments = [
  { entity_type = "columns", entity_name = "cat.sch.tbl.id", tag_key = "pii_level", tag_value = "masked_account" },
]
"""

_DDL = """\
CREATE TABLE cat.sch.tbl (
  id BIGINT,
  email STRING,
  contact STRING
);
"""


@pytest.fixture
def _paths(tmp_path):
    tfvars = tmp_path / "abac.auto.tfvars"
    tfvars.write_text(_TFVARS)
    ddl = tmp_path / "ddl" / "_fetched.sql"
    ddl.parent.mkdir(parents=True)
    ddl.write_text(_DDL)
    return tfvars, ddl


class TestAutofixIntegration:
    def test_default_none_is_unchanged_legacy_behaviour(self, _paths):
        import generate_abac
        tfvars, ddl = _paths
        added = generate_abac.autofix_untagged_pii_columns(tfvars, ddl_path=ddl)
        # Only the 'email' column matches a DDL pattern; 'contact' does not.
        assert added == 1
        cfg = assert_valid_hcl(tfvars)
        entries = {(a["entity_name"], a["tag_key"], a["tag_value"])
                   for a in cfg["tag_assignments"]}
        assert ("cat.sch.tbl.email", "pii_level", "masked_email") in entries
        assert not any(a["entity_name"] == "cat.sch.tbl.contact"
                       for a in cfg["tag_assignments"])

    def test_classification_wins_over_llm_for_same_column(self, _paths):
        import generate_abac
        tfvars, ddl = _paths
        # Native classification says the 'email' column is actually a credit card.
        classification = ClassificationSource(
            tag_rows=[("cat", "sch", "tbl", "email", "class.credit_card", "")],
        )
        added = generate_abac.autofix_untagged_pii_columns(
            tfvars, ddl_path=ddl, classification_source=classification,
        )
        assert added == 1
        cfg = assert_valid_hcl(tfvars)
        email_tags = [a for a in cfg["tag_assignments"]
                      if a["entity_name"] == "cat.sch.tbl.email"]
        assert len(email_tags) == 1
        # classification's pci value wins; the LLM's masked_email is NOT used
        assert email_tags[0]["tag_key"] == "pci_level"
        assert email_tags[0]["tag_value"] == "masked_card_last4"

    def test_classification_adds_column_llm_would_miss(self, _paths):
        import generate_abac
        tfvars, ddl = _paths
        classification = ClassificationSource(
            tag_rows=[("cat", "sch", "tbl", "contact", "class.email", "")],
        )
        added = generate_abac.autofix_untagged_pii_columns(
            tfvars, ddl_path=ddl, classification_source=classification,
        )
        # 'contact' (from classification) + 'email' (from LLM)
        assert added == 2
        cfg = assert_valid_hcl(tfvars)
        by_name = {a["entity_name"]: a for a in cfg["tag_assignments"]}
        assert by_name["cat.sch.tbl.contact"]["tag_value"] == "masked_email"
        assert by_name["cat.sch.tbl.email"]["tag_value"] == "masked_email"

    def test_source_labelled_in_log_output(self, _paths, capsys):
        import generate_abac
        tfvars, ddl = _paths
        classification = ClassificationSource(
            tag_rows=[("cat", "sch", "tbl", "contact", "class.email", "")],
        )
        generate_abac.autofix_untagged_pii_columns(
            tfvars, ddl_path=ddl, classification_source=classification,
        )
        out = capsys.readouterr().out
        assert "[source: classification]" in out
        assert "[source: llm]" in out

    def test_classification_finding_dropped_when_uncovered(self, tmp_path, capsys):
        # A classification value with no covering masking function must NOT be
        # injected — it goes through the SAME coverage check as the LLM path.
        import generate_abac
        tfvars = tmp_path / "abac.auto.tfvars"
        tfvars.write_text(_TFVARS)
        ddl = tmp_path / "ddl" / "_fetched.sql"
        ddl.parent.mkdir(parents=True)
        ddl.write_text(
            "CREATE TABLE cat.sch.tbl (\n  id BIGINT,\n  birthdate STRING\n);\n"
        )
        # SQL file covers only masked_email; masked_dob (needs mask_date_to_year)
        # is therefore uncovered.
        sql = tmp_path / "masking_functions.sql"
        sql.write_text("CREATE FUNCTION cat.sch.mask_email(x STRING) RETURNS STRING RETURN x;\n")

        classification = ClassificationSource(
            tag_rows=[("cat", "sch", "tbl", "birthdate", "class.date_of_birth", "")],
        )
        added = generate_abac.autofix_untagged_pii_columns(
            tfvars, ddl_path=ddl, sql_path=sql, classification_source=classification,
        )
        # nothing added: classification's masked_dob is uncovered and dropped,
        # and the LLM is suppressed on that (natively-classified) column.
        assert added == 0
        cfg = assert_valid_hcl(tfvars)
        assert not any(a["entity_name"] == "cat.sch.tbl.birthdate"
                       for a in cfg["tag_assignments"])
        out = capsys.readouterr().out
        assert "no covering masking function" in out

    def test_native_replaces_existing_conflicting_llm_assignment(self, tmp_path):
        # BLOCKING #1: an LLM-generated assignment already present for a column
        # must be OVERRIDDEN by native classification, not left in place.
        import generate_abac
        tfvars = tmp_path / "abac.auto.tfvars"
        tfvars.write_text(
            'tag_assignments = [\n'
            '  { entity_type = "columns", entity_name = "cat.sch.tbl.email", '
            'tag_key = "pii_level", tag_value = "masked_email" },\n'
            ']\n'
        )
        ddl = tmp_path / "ddl" / "_fetched.sql"
        ddl.parent.mkdir(parents=True)
        ddl.write_text("CREATE TABLE cat.sch.tbl (\n  id BIGINT,\n  email STRING\n);\n")
        # Native classification says that column is actually a credit card.
        classification = ClassificationSource(
            tag_rows=[("cat", "sch", "tbl", "email", "class.credit_card", "")],
        )
        generate_abac.autofix_untagged_pii_columns(
            tfvars, ddl_path=ddl, classification_source=classification,
        )
        cfg = assert_valid_hcl(tfvars)
        email_tags = [a for a in cfg["tag_assignments"]
                      if a["entity_name"] == "cat.sch.tbl.email"]
        # exactly one assignment, and it is the native one — the LLM's
        # masked_email was replaced, not duplicated.
        assert len(email_tags) == 1
        assert email_tags[0]["tag_key"] == "pci_level"
        assert email_tags[0]["tag_value"] == "masked_card_last4"

    def test_unmapped_native_removes_existing_llm_assignment(self, tmp_path):
        # An unmapped native class is still authoritative: it must clear a
        # pre-existing LLM assignment (and persist that removal) rather than
        # letting the LLM tag stand.
        import generate_abac
        tfvars = tmp_path / "abac.auto.tfvars"
        tfvars.write_text(
            'tag_assignments = [\n'
            '  { entity_type = "columns", entity_name = "cat.sch.tbl.email", '
            'tag_key = "pii_level", tag_value = "masked_email" },\n'
            ']\n'
        )
        ddl = tmp_path / "ddl" / "_fetched.sql"
        ddl.parent.mkdir(parents=True)
        ddl.write_text("CREATE TABLE cat.sch.tbl (\n  id BIGINT,\n  email STRING\n);\n")
        classification = ClassificationSource(
            tag_rows=[("cat", "sch", "tbl", "email", "class.some_novel_type", "")],
        )
        added = generate_abac.autofix_untagged_pii_columns(
            tfvars, ddl_path=ddl, classification_source=classification,
        )
        assert added == 0
        cfg = assert_valid_hcl(tfvars)
        # the pre-existing LLM assignment for the classified column is gone
        assert not any(a["entity_name"] == "cat.sch.tbl.email"
                       for a in cfg.get("tag_assignments", []))

    def test_unmapped_native_class_surfaced_and_llm_suppressed(self, _paths, capsys):
        # 'contact' carries an unmapped class.* tag: no governed tag applied,
        # LLM override suppressed, and the column surfaced in the log.
        import generate_abac
        tfvars, ddl = _paths
        classification = ClassificationSource(
            tag_rows=[("cat", "sch", "tbl", "contact", "class.some_novel_type", "")],
        )
        added = generate_abac.autofix_untagged_pii_columns(
            tfvars, ddl_path=ddl, classification_source=classification,
        )
        # only 'email' (LLM) is tagged; 'contact' is claimed-but-unmapped
        assert added == 1
        cfg = assert_valid_hcl(tfvars)
        assert not any(a["entity_name"] == "cat.sch.tbl.contact"
                       for a in cfg["tag_assignments"])
        out = capsys.readouterr().out
        assert "cat.sch.tbl.contact" in out
        assert "no governed mapping" in out
