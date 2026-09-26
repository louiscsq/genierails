import json

from generate_abac import (
    coverage_denominator,
    discover_agent_footprint,
    footprint_table_refs,
    scope_ddl_to_footprint,
)


def test_footprint_enumerated_from_space_definition():
    serialized = json.dumps({
        "data_sources": {"tables": [{"identifier": "cat.sales.orders"}]},
        "instructions": {
            "join_specs": [{
                "left": {"identifier": "cat.sales.orders"},
                "right": {"identifier": "cat.crm.customers"},
                "sql": "cat.sales.orders.customer_id = cat.crm.customers.customer_id",
            }],
            "sql_snippets": {
                "measures": [{"sql": ["sum(cat.sales.orders.amount)"]}],
            },
        },
    })

    footprint = discover_agent_footprint(serialized)

    assert footprint == [
        {"table": "cat.crm.customers", "columns": []},
        {"table": "cat.sales.orders", "columns": []},
    ]
    assert footprint_table_refs(footprint) == ["cat.crm.customers", "cat.sales.orders"]


def test_declared_footprint_fallback_for_new_space_is_deterministic():
    footprint = discover_agent_footprint(declared_footprint=[
        {"table": "cat.sales.orders", "columns": ["email", "id", "email"]},
        "cat.crm.customers.name",
        "cat.sales.orders.id",
    ])

    assert footprint == [
        {"table": "cat.crm.customers", "columns": ["name"]},
        {"table": "cat.sales.orders", "columns": ["email", "id"]},
    ]


def test_coverage_denominator_uses_agent_footprint():
    footprint = discover_agent_footprint(declared_footprint=[
        {"table": "cat.sales.orders", "columns": ["email"]},
    ])
    assignments = [
        {"entity_type": "columns", "entity_name": "cat.sales.orders.email", "tag_key": "pii", "tag_value": "email"},
        {"entity_type": "columns", "entity_name": "cat.sales.orders.internal_note", "tag_key": "pii", "tag_value": "text"},
        {"entity_type": "columns", "entity_name": "cat.hr.people.ssn", "tag_key": "pii", "tag_value": "ssn"},
    ]

    assert [item["entity_name"] for item in coverage_denominator(assignments, footprint)] == [
        "cat.sales.orders.email"
    ]


def test_explicit_columns_bound_fetched_ddl_scan_scope():
    ddl = """CREATE TABLE cat.sales.orders (
  id BIGINT,
  email STRING,
  internal_note STRING
);"""
    footprint = discover_agent_footprint(declared_footprint=[
        {"table": "cat.sales.orders", "columns": ["id", "email"]},
    ])
    scoped = scope_ddl_to_footprint(ddl, footprint)
    assert "email STRING" in scoped
    assert "id BIGINT" in scoped
    assert "internal_note" not in scoped
