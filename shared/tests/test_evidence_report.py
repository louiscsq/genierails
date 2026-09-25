import json
from datetime import datetime, timezone

from evidence_report import assemble_report, configured_tables, main, render_markdown, write_report


COL = {"catalog": "main", "schema": "sales", "table": "customers", "column": "email"}


def test_assemble_report_joins_and_sorts_mocked_state():
    report = assemble_report(
        [COL],
        classifications=[{**COL, "status": "complete", "scanned_at": "2026-09-25T01:02:03Z"}],
        tags=[{**COL, "name": "pii", "value": "email"}],
        masks=[{**COL, "name": "main.governance.mask_email"}],
        policies=[{**COL, "name": "main.governance.region_filter"}],
        grants=[{**COL, "principal": "analysts", "privilege": "SELECT", "scope": "TABLE"}],
        generated_at=datetime(2026, 9, 26, tzinfo=timezone.utc),
        approved_by="compliance@example.com",
        approved_at="2026-09-26T00:00:00Z",
        source="mock-live",
    )
    assert report["schema_version"] == "1.0"
    assert report["header"]["generated_at"] == "2026-09-26T00:00:00Z"
    item = report["evidence"][0]
    assert item["classification"] == {"status": "complete", "scanned_at": "2026-09-25T01:02:03Z"}
    assert item["detected_tags"] == [{"name": "pii", "value": "email"}]
    assert item["applied_mask"] == "main.governance.mask_email"
    assert item["applied_policies"] == ["main.governance.region_filter"]
    assert item["grants"][0]["principal"] == "analysts"


def test_missing_live_inputs_have_explicit_offline_values():
    item = assemble_report([COL])["evidence"][0]
    assert item["classification"] == {"status": "not_run", "scanned_at": None}
    assert item["detected_tags"] == []
    assert item["applied_mask"] is None
    assert item["applied_policies"] == []
    assert item["grants"] == []


def test_json_and_markdown_outputs(tmp_path):
    report = assemble_report([COL], generated_at=datetime(2026, 9, 26, tzinfo=timezone.utc))
    json_path, md_path = write_report(report, tmp_path)
    assert json.loads(json_path.read_text())["report_type"] == "genierails.compliance_evidence"
    markdown = md_path.read_text()
    assert "# GenieRails Compliance Evidence" in markdown
    assert "main.sales.customers | email | not_run" in markdown
    assert render_markdown(report) == markdown


def test_cli_stays_offline_unless_integration_flag_is_set(tmp_path, monkeypatch):
    env_dir = tmp_path / "dev"
    (env_dir / "data_access").mkdir(parents=True)
    (env_dir / "data_access" / "abac.auto.tfvars").write_text('''
tag_assignments = [{
  entity_type = "columns"
  entity_name = "main.sales.customers.email"
  tag_name = "pii"
  tag_value = "email"
}]
''')
    monkeypatch.delenv("GENIERAILS_EVIDENCE_INTEGRATION", raising=False)

    def forbidden_collector(*args):
        raise AssertionError("offline mode made a live call")

    assert main(["--env-dir", str(env_dir)], collector=forbidden_collector) == 0
    artifact = json.loads((env_dir / "generated/evidence/compliance-evidence-v1.0.json").read_text())
    assert artifact["header"]["source"] == "offline-config"
    assert artifact["evidence"][0]["detected_tags"] == [{"name": "pii", "value": "email"}]


def test_configured_tables_includes_all_genie_tables_and_governance_fallback(tmp_path):
    (tmp_path / "data_access").mkdir()
    (tmp_path / "env.auto.tfvars").write_text('''
uc_tables = ["main.sales.orders"]
genie_spaces = [{ name = "support", uc_tables = ["main.support.tickets"] }]
''')
    (tmp_path / "data_access" / "abac.auto.tfvars").write_text('''
tag_assignments = [{ entity_type = "columns", entity_name = "main.hr.people.ssn", tag_name = "pii", tag_value = "ssn" }]
''')
    assert configured_tables(tmp_path) == [
        "main.hr.people", "main.sales.orders", "main.support.tickets"
    ]
