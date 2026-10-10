run "legacy_plans_zero_resources" {
  command = plan
  variables {
    governance_mode            = "legacy"
    transition_id              = "change"
    previous_release_succeeded = true
    replacement_verified       = true
  }
  assert {
    condition = (length(terraform_data.create_replacements) == 0
      && length(terraform_data.verify_replacements) == 0
      && length(terraform_data.switch_tags_and_tiers) == 0
      && length(terraform_data.verify_switched) == 0
    && length(terraform_data.retire_old) == 0)
    error_message = "legacy mode must have a zero-resource staged plan"
  }
}

run "first_release_keeps_old_policy" {
  command = plan
  variables {
    governance_mode            = "deterministic"
    transition_id              = "change"
    previous_release_succeeded = false
    replacement_verified       = true
  }
  assert {
    condition     = length(terraform_data.retire_old) == 0
    error_message = "the release that installs a replacement must not retire the old policy"
  }
}

run "later_verified_release_may_retire" {
  command = apply
  variables {
    governance_mode            = "deterministic"
    transition_id              = "change"
    previous_release_succeeded = true
    replacement_verified       = true
  }
  assert {
    condition = (terraform_data.verify_replacements[0].input == terraform_data.create_replacements[0].output
      && terraform_data.switch_tags_and_tiers[0].input == terraform_data.verify_replacements[0].output
      && terraform_data.verify_switched[0].input == terraform_data.switch_tags_and_tiers[0].output
    && terraform_data.retire_old[0].input == terraform_data.verify_switched[0].output)
    error_message = "create -> verify -> switch -> verify -> retire dependency chain changed"
  }
}

run "unverified_replacement_cannot_be_destroyed" {
  command = plan
  variables {
    governance_mode            = "deterministic"
    transition_id              = "change"
    previous_release_succeeded = true
    replacement_verified       = false
  }
  expect_failures = [terraform_data.retire_old[0]]
}
