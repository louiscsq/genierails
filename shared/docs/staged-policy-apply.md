# Staged policy apply interface

`scripts/staged_policy_apply.py` owns the release state machine for deterministic
governance. It invokes executable hooks in this fixed order:

1. `create`: create replacement functions and policies under new names; retain
   every live generation.
2. `verify-created`: run `SHOW EFFECTIVE POLICIES` and tier queries.
3. `switch`: apply treatment retags and tier moves, with tightening moves first.
4. `verify-switched`: repeat effective-policy and tier-query verification.
5. `retire`: remove the generation recorded by an earlier successful release.

The first four hooks are mandatory. `retire` is invoked only when the journal
contains a retirement from an earlier successful release; the generation made
obsolete by the current release is merely recorded. Every non-zero hook result
stops the run, is returned to the caller, and records the completed stages plus
the old and new fingerprints. Legacy mode writes no journal and invokes no hook.

Hooks receive `GENIERAILS_POLICY_RELEASE_ID`,
`GENIERAILS_POLICY_FINGERPRINT`, `GENIERAILS_OLD_POLICY_FINGERPRINT`, and
`GENIERAILS_RETIRE_FINGERPRINT`. They must be argv executables (not shell
fragments), and must be idempotent because an operator resumes a failed release
by rerunning it under the environment lock.

## Adjacent rollout interfaces

Step 5 supplies the create/switch hooks and versioned function, policy, and
treatment-value names. Its create hook must render both retained and replacement
generations; it must reject a Terraform plan containing a live policy/function
destroy. Step 7 runs its reader and weakening checks before this controller. A
permitted loosening still uses the same staged path and `order_tier_moves()`;
step 6 does not interpret `ACK`.
