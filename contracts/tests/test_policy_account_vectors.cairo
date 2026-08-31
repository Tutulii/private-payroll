use payo_contracts::policy_account::{PolicyState};
use payo_contracts::policy_account::PayoPolicyAccount::run_leaf;

#[test]
fn policy_run_leaf_matches_typescript_vector() {
    let policy = PolicyState {
        configured: true,
        revoked: false,
        session_public_key: 1,
        pool: 2.try_into().unwrap(),
        seal: 3.try_into().unwrap(),
        seal_mode: 0,
        proof_version: 1,
        schema_version: 1,
        payroll_policy_root_high: 41,
        payroll_policy_root_low: 42,
        token_set_commitment: 51,
        recipient_set_commitment: 52,
        purpose_commitment: 53,
        amount_limit_commitment: 54,
        authorized_runs_root: 1,
        valid_after: 900,
        valid_before: 2_000,
        period_seconds: 600,
        max_calls_per_period: 1,
        max_call_count: 1,
        period_started_at: 900,
        period_call_count: 0,
        used_call_count: 0,
    };
    assert(
        run_leaf(0x5041594f, policy, 11, 12, 21, 22, 31, 32)
            == 0x37caed23da62c77c20fe581f9360c834aad52fcf558d6c2f2f8e3d743796462,
        'policy vector mismatch',
    );
}
