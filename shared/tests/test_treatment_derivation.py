"""Option-B single enforcement-tag derivation tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from treatment_derivation import (
    derive_treatment_model,
    load_treatment_config,
    matching_masks_by_column,
    resolve_treatment,
)


def _base_config():
    return {
        "tag_policies": [
            {"key": "pii_level", "values": ["masked_email", "masked_ssn"]},
            {"key": "pci_level", "values": ["redacted_cvv"]},
        ],
        "tag_assignments": [
            {"entity_type": "columns", "entity_name": "cat.sch.people.contact", "tag_key": "pii_level", "tag_value": "masked_email"},
            {"entity_type": "columns", "entity_name": "cat.sch.people.contact", "tag_key": "pci_level", "tag_value": "redacted_cvv"},
            {"entity_type": "columns", "entity_name": "cat.sch.people.ssn", "tag_key": "pii_level", "tag_value": "masked_ssn"},
        ],
        "fgac_policies": [
            {"name": "old_email", "policy_type": "POLICY_TYPE_COLUMN_MASK", "catalog": "cat", "to_principals": ["analysts"], "match_condition": "hasTagValue('pii_level', 'masked_email')", "function_name": "mask_email", "function_schema": "security"},
            {"name": "old_cvv", "policy_type": "POLICY_TYPE_COLUMN_MASK", "catalog": "cat", "to_principals": ["analysts"], "match_condition": "hasTagValue('pci_level', 'redacted_cvv')", "function_name": "mask_redact", "function_schema": "security"},
        ],
    }


def test_precedence_multi_tag_column_resolves_to_single_strictest_treatment():
    config = load_treatment_config()
    treatment = resolve_treatment(
        [("pii_level", "masked_email"), ("pci_level", "redacted_cvv")], config
    )
    assert treatment is not None
    assert treatment.value == "redact"

    derived, _ = derive_treatment_model(_base_config(), config)
    contact = [
        item for item in derived["tag_assignments"]
        if item["entity_name"] == "cat.sch.people.contact"
    ]
    assert contact == [{
        "entity_type": "columns", "entity_name": "cat.sch.people.contact",
        "tag_key": "gr.treatment", "tag_value": "redact",
    }]


def test_rekeyed_masks_match_no_column_more_than_once():
    derived, _ = derive_treatment_model(_base_config(), load_treatment_config())
    matches = matching_masks_by_column(derived)
    assert matches
    assert all(len(policy_names) == 1 for policy_names in matches.values())
    masks = [p for p in derived["fgac_policies"] if p["policy_type"] == "POLICY_TYPE_COLUMN_MASK"]
    assert all("hasTagValue('gr.treatment'," in p["match_condition"] for p in masks)
    assert len({p["match_condition"] for p in masks}) == len(masks)
