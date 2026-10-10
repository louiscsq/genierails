terraform {
  required_version = ">= 1.7"
}

variable "governance_mode" { type = string }
variable "transition_id" { type = string }
variable "previous_release_succeeded" { type = bool }
variable "replacement_verified" { type = bool }

locals {
  enabled = var.governance_mode == "deterministic" && var.transition_id != ""
}

# This small module is the executable dependency contract used by the data
# access stage hooks.  The hooks target one token at a time; Terraform cannot
# reorder a retag/tier switch ahead of creation and verification.
resource "terraform_data" "create_replacements" {
  count = local.enabled ? 1 : 0
  input = var.transition_id
}

resource "terraform_data" "verify_replacements" {
  count      = local.enabled ? 1 : 0
  input      = terraform_data.create_replacements[0].output
  depends_on = [terraform_data.create_replacements]
}

resource "terraform_data" "switch_tags_and_tiers" {
  count      = local.enabled ? 1 : 0
  input      = terraform_data.verify_replacements[0].output
  depends_on = [terraform_data.verify_replacements]
}

resource "terraform_data" "verify_switched" {
  count      = local.enabled ? 1 : 0
  input      = terraform_data.switch_tags_and_tiers[0].output
  depends_on = [terraform_data.switch_tags_and_tiers]
}

resource "terraform_data" "retire_old" {
  count      = local.enabled && var.previous_release_succeeded ? 1 : 0
  input      = terraform_data.verify_switched[0].output
  depends_on = [terraform_data.verify_switched]

  lifecycle {
    precondition {
      condition     = var.replacement_verified
      error_message = "A live policy/function cannot be retired before its replacement passed post-switch verification."
    }
  }
}
