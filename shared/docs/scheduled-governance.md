# Scheduled Steady-State Governance

Roadmap item: **scheduled prod re-scan + drift/coverage on a schedule.**

GenieRails governance is normally re-derived on demand — a developer runs
`make audit-schema`, `make generate-delta`, and `make validate` when a schema
changes (see [playbook.md](playbook.md) and [cicd.md](cicd.md)). The scheduled
governance job runs those **same steady-state entrypoints** on a cron so drift
is detected (and incrementally re-classified) without waiting for someone to
kick off a scan.

It is an opt-in **wrapper only** — it adds no new re-derive logic. The
scheduled tasks call the existing scripts exactly as the `make` targets do:

| Task             | Wraps                        | Equivalent make target   |
| ---------------- | ---------------------------- | ------------------------ |
| `audit_schema`   | `scripts/audit_schema_drift.py` | `make audit-schema`   |
| `generate_delta` | `generate_abac.py --delta`   | `make generate-delta`    |
| `coverage_check` | `validate_abac.py`           | `make validate-generated`|

The tasks run in order `audit_schema → generate_delta → coverage_check`. The
`audit_schema` task exits non-zero when drift is found, so a **red
`audit_schema` task is the drift signal**; `generate_delta` is wired with
`run_if = ALL_DONE` so it still runs and resolves the drift, and
`coverage_check` re-validates the regenerated config.

## Disabled by default

The job is defined in
[`roots/workspace/scheduled_governance.tf`](../roots/workspace/scheduled_governance.tf)
and gated by `enable_scheduled_governance`, which defaults to `false`. Adding
the file changes **nothing** about `make apply` for existing environments —
the `databricks_job` resource has `count = 0` until you opt in.

## Enabling it

1. Copy the snippet from
   [`scheduled_governance.auto.tfvars.example`](../scheduled_governance.auto.tfvars.example)
   into the target environment's `env.auto.tfvars` (the tfvars file the
   workspace layer loads), for example `aws/envs/prod/env.auto.tfvars`:

   ```hcl
   enable_scheduled_governance = true
   scheduled_governance_env    = "prod"
   scheduled_governance_cloud  = "aws"          # or "azure"
   scheduled_governance_cron   = "0 0 6 * * ?"   # daily 06:00
   scheduled_governance_git_url = "https://github.com/<org>/<repo>"
   scheduled_governance_notification_emails = ["governance-team@example.com"]
   ```

2. Apply the workspace layer:

   ```bash
   make apply ENV=prod
   ```

   Terraform creates one Databricks Job named
   `GenieRails steady-state governance (prod)` running on serverless compute,
   scheduled per your cron expression.

3. Confirm it in the workspace: **Workflows → Jobs**. The job id and URL are
   exposed as the `scheduled_governance_job_id` / `scheduled_governance_job_url`
   outputs.

## Configuration reference

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `enable_scheduled_governance` | `false` | Master opt-in. `false` = no job created. |
| `scheduled_governance_env` | `"prod"` | Environment the scan targets. |
| `scheduled_governance_cloud` | `"aws"` | Cloud subdir holding `envs/` (`aws`/`azure`). |
| `scheduled_governance_cron` | `"0 0 6 * * ?"` | Quartz cron cadence (daily 06:00). |
| `scheduled_governance_timezone` | `"UTC"` | Timezone the cron is evaluated in. |
| `scheduled_governance_git_url` | `""` | Repo the job checks out. **Required when enabled.** |
| `scheduled_governance_git_branch` | `"main"` | Branch to check out. |
| `scheduled_governance_git_provider` | `"gitHub"` | Git provider for the Jobs Git source. |
| `scheduled_governance_serverless_client` | `"2"` | Serverless environment client version. |
| `scheduled_governance_notification_emails` | `[]` | Emails notified on failure. |
| `scheduled_governance_job_name` | `""` | Override the generated job name. |

## Notes

- The scan re-scans **live** table schemas, so the job's service principal needs
  the same workspace + warehouse access the manual `make audit-schema ENV=prod`
  flow uses.
- `generate_delta` is constrained to existing governed keys/values — it
  classifies new columns and drops stale assignments; it does **not** perform a
  full regeneration. Review and deploy any config changes through your normal
  CI/apply flow.
- The job **reports and re-derives**; it does not auto-`apply` Terraform. Wiring
  the delta output back into a commit/apply pipeline is intentionally left to
  your existing CI (see [cicd.md](cicd.md)).
