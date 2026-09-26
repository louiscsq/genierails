import json

from generate_abac import (
    discover_agent_footprint,
    footprint_contains_column,
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


def test_wildcard_footprint_keeps_concrete_column_in_scan_denominator():
    footprint = discover_agent_footprint(
        declared_footprint=["dev_catalog.finance.*"]
    )

    assert footprint_contains_column(
        footprint, "dev_catalog.finance.invoices.email"
    )


def test_footprint_column_matching_is_case_insensitive():
    footprint = discover_agent_footprint(declared_footprint=[
        {"table": "Cat.Schema.Orders", "columns": ["Email"]},
    ])

    assert footprint_contains_column(footprint, "cat.schema.orders.email")
    assert not footprint_contains_column(footprint, "cat.schema.orders.internal_note")


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


def test_explicit_ddl_column_scope_is_case_insensitive():
    ddl = """CREATE TABLE cat.schema.orders (
  Email STRING,
  Internal_Note STRING
);"""
    footprint = discover_agent_footprint(declared_footprint=[
        {"table": "Cat.Schema.Orders", "columns": ["email"]},
    ])

    scoped = scope_ddl_to_footprint(ddl, footprint)
    assert "Email STRING" in scoped
    assert "Internal_Note" not in scoped
