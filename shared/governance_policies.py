"""Pure construction and validation of deterministic governance policies."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from deterministic_governance import NEVER_RAW_TREATMENTS
from mask_library import load_library, sql_body

FAILSAFE_TREATMENT = "unmapped_redact"
POLICY_COMMENT = "GenieRails deterministic governance policy"

_SQL_TYPES = ("STRING", "BIGINT", "DOUBLE", "DECIMAL(38,9)", "DATE", "TIMESTAMP", "TIMESTAMP_NTZ")


def expand_principals(principals: Sequence[str], members: Mapping[str, Sequence[str]]) -> set[str]:
    """Expand nested account groups transitively (cycles are harmless)."""
    expanded: set[str] = set()
    pending = list(principals)
    while pending:
        principal = pending.pop()
        if principal in expanded:
            continue
        expanded.add(principal)
        pending.extend(members.get(principal, ()))
    return expanded


def principal_sets_are_disjoint(
    partial_to: Sequence[str], partial_except: Sequence[str],
    full_to: Sequence[str], full_except: Sequence[str],
    members: Mapping[str, Sequence[str]] | None = None,
) -> bool:
    """Return whether the effective partial and full populations are disjoint."""
    graph = members or {}
    partial = expand_principals(partial_to, graph) - expand_principals(partial_except, graph)
    full = expand_principals(full_to, graph) - expand_principals(full_except, graph)
    return partial.isdisjoint(full)


def build_deterministic_policies(
    *, catalogs_by_treatment: Mapping[str, Sequence[str]],
    access_tier_groups: Sequence[str], raw_exempt_principals: Sequence[str] = (),
    deployer_principal: str = "", function_schema: str = "default",
) -> list[dict]:
    """Build the two caller-independent policies for each treatment in use.

    Never-raw (including the unmapped-class fail-safe) policies deliberately
    carry no exceptions: every principal is sent through the full mask.
    """
    tier1 = list(access_tier_groups[:1])
    tier2 = list(access_tier_groups[1:-1])
    ordinary_exceptions = list(dict.fromkeys(
        tier1 + list(raw_exempt_principals) + ([deployer_principal] if deployer_principal else [])
    ))
    full_exceptions = list(dict.fromkeys(tier1 + tier2 + list(raw_exempt_principals)
                                         + ([deployer_principal] if deployer_principal else [])))
    result: list[dict] = []
    for treatment in sorted(catalogs_by_treatment):
        never_raw = treatment in NEVER_RAW_TREATMENTS or treatment == FAILSAFE_TREATMENT
        for catalog in sorted(set(catalogs_by_treatment[treatment])):
            common = {
                "policy_type": "POLICY_TYPE_COLUMN_MASK", "catalog": catalog,
                "comment": POLICY_COMMENT,
                "match_condition": f"hasTagValue('gr_treatment', '{treatment}')",
                "match_alias": f"gr_treatment_{treatment}",
                "function_catalog": catalog, "function_schema": function_schema,
            }
            # One full policy covers everybody for never-raw data; emitting a
            # second matching policy would itself cause MULTIPLE_MASKS.
            if tier2 and not never_raw:
                result.append(common | {
                    "name": f"gr_mask_{catalog}_{treatment}_partial",
                    "to_principals": tier2,
                    "except_principals": ordinary_exceptions,
                    "function_name": f"gr_mask_{treatment}_partial",
                })
            result.append(common | {
                "name": f"gr_mask_{catalog}_{treatment}_full",
                "to_principals": ["account users"],
                "except_principals": [] if never_raw else full_exceptions,
                "function_name": f"gr_mask_{treatment}_full",
            })
    return result


def render_mask_functions(treatments: Sequence[str], *, catalog: str, schema: str) -> str:
    """Render overloaded, caller-independent partial/full functions in the library."""
    library = load_library()
    blocks: list[str] = []
    for treatment in sorted(set(treatments)):
        item = library["treatments"].get(treatment)
        partial = "redacted" if treatment == FAILSAFE_TREATMENT else (item or {}).get("partial", "redacted")
        full = (item or {}).get("full", "redacted")
        for suffix, version in (("partial", partial), ("full", full)):
            for sql_type in _SQL_TYPES:
                blocks.append(
                    f"CREATE OR REPLACE FUNCTION `{catalog}`.`{schema}`.`gr_mask_{treatment}_{suffix}`"
                    f"(value {sql_type}) RETURNS {sql_type} RETURN {sql_body(version, sql_type)};"
                )
    return "\n\n".join(blocks) + ("\n" if blocks else "")
