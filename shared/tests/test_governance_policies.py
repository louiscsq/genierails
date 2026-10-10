from governance_policies import (
    FAILSAFE_TREATMENT, build_deterministic_policies, expand_principals,
    principal_sets_are_disjoint,
)


def test_ordinary_treatment_has_partial_and_full_disjoint_shapes():
    policies = build_deterministic_policies(
        catalogs_by_treatment={"email_partial": ["cat"]},
        access_tier_groups=["raw", "regional", "masked"],
        raw_exempt_principals=["etl"], deployer_principal="sp",
    )
    partial, full = policies
    assert partial["to_principals"] == ["regional"]
    assert partial["except_principals"] == ["raw", "etl", "sp"]
    assert full["to_principals"] == ["account users"]
    assert full["except_principals"] == ["raw", "regional", "etl", "sp"]


def test_never_raw_and_unmapped_have_one_full_policy_with_no_exceptions():
    policies = build_deterministic_policies(
        catalogs_by_treatment={"secret": ["cat"], FAILSAFE_TREATMENT: ["cat"]},
        access_tier_groups=["raw", "partial", "full"],
        raw_exempt_principals=["etl"], deployer_principal="sp",
    )
    assert len(policies) == 2
    assert all(p["to_principals"] == ["account users"] for p in policies)
    assert all(p["except_principals"] == [] for p in policies)
    assert all(p["function_name"].endswith("_full") for p in policies)


def test_partial_and_full_effective_sets_are_disjoint_with_nested_groups():
    members = {"regional": ["alice", "nested"], "nested": ["bob"],
               "raw": ["admin"], "account users": ["alice", "bob", "admin", "outsider"]}
    assert expand_principals(["regional"], members) >= {"alice", "bob"}
    assert principal_sets_are_disjoint(
        ["regional"], ["raw"], ["account users"], ["raw", "regional"], members,
    )


def test_only_treatments_in_use_get_policies():
    policies = build_deterministic_policies(
        catalogs_by_treatment={"email_partial": ["cat"]},
        access_tier_groups=["raw", "partial", "full"],
    )
    assert {p["match_condition"] for p in policies} == {
        "hasTagValue('gr_treatment', 'email_partial')"
    }
