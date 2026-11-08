//! The spend rule. `decide` is the only code that judges a spend: `request_spend` runs it on the
//! stored policy, the `check_spend` view runs it on a copy, so the two can never disagree.

use near_sdk::AccountId;
use near_sdk::json_types::U128;

use crate::types::{DenyReason, Policy};

/// Starts a fresh window (start = now, spent = 0) once `now_ms` reaches the end of the current one.
fn roll_window(policy: &mut Policy, now_ms: u64) {
    let window_end_ms = policy
        .window_start_ms
        .saturating_add(policy.window_secs.saturating_mul(1_000));
    if now_ms >= window_end_ms {
        policy.window_start_ms = now_ms;
        policy.window_spent = U128(0);
    }
}

/// Rolls `policy`'s window to `now_ms`, then returns every reason to refuse sending `amount`
/// yoctoNEAR to `receiver`, in `DenyReason` order. An empty list means approved.
///
/// `vault_available` is the spendable vault balance, as the `vault_available` view reports it.
pub(crate) fn decide(
    policy: &mut Policy,
    receiver: &AccountId,
    amount: u128,
    now_ms: u64,
    vault_available: u128,
) -> Vec<DenyReason> {
    roll_window(policy, now_ms);

    let mut reasons = Vec::new();
    if policy.revoked {
        reasons.push(DenyReason::Revoked);
    }
    if amount == 0 {
        reasons.push(DenyReason::ZeroAmount);
    }
    if !policy.allowed_receivers.contains(receiver) {
        reasons.push(DenyReason::ReceiverNotAllowed);
    }
    if amount > policy.per_tx_max.0 {
        reasons.push(DenyReason::OverPerTxMax);
    }
    // An overflowing sum is over any limit.
    let over_window = policy
        .window_spent
        .0
        .checked_add(amount)
        .is_none_or(|spent| spent > policy.window_limit.0);
    if over_window {
        reasons.push(DenyReason::OverWindowLimit);
    }
    if amount > vault_available {
        reasons.push(DenyReason::InsufficientVaultBalance);
    }
    reasons
}
