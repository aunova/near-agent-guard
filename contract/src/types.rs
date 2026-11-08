//! JSON wire shapes. Every amount is a yoctoNEAR decimal string (`U128`).

use near_sdk::json_types::U128;
use near_sdk::{AccountId, near};

/// One agent's spending policy, exactly as `get_policy` returns it.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub per_tx_max: U128,
    pub window_limit: U128,
    pub window_secs: u64,
    pub allowed_receivers: Vec<AccountId>,
    pub revoked: bool,
    pub window_start_ms: u64,
    pub window_spent: U128,
}

/// Why a spend is refused. A decision lists every reason that applies, in declaration order.
#[near(serializers = [borsh, json])]
#[serde(rename_all = "snake_case")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    /// Only `check_spend` reports this; `request_spend` panics for an unknown agent instead.
    UnknownAgent,
    Revoked,
    ZeroAmount,
    ReceiverNotAllowed,
    OverPerTxMax,
    OverWindowLimit,
    InsufficientVaultBalance,
}

/// Result of the `check_spend` view. `approved` is true exactly when `reasons` is empty.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub approved: bool,
    pub reasons: Vec<DenyReason>,
}

/// Return value of `request_spend`. A denial is a successful transaction carrying this receipt.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendReceipt {
    pub ledger_index: u64,
    pub approved: bool,
    pub reasons: Vec<DenyReason>,
}

/// What happened to the NEAR transfer behind a ledger entry.
#[near(serializers = [borsh, json])]
#[serde(rename_all = "snake_case")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferStatus {
    /// The spend was denied, so no transfer was sent.
    NotAttempted,
    /// Approved and sent; `on_transfer` has not run yet.
    Pending,
    Succeeded,
    Failed,
}

/// One recorded spend attempt, approved or denied.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerEntry {
    pub index: u64,
    pub agent: AccountId,
    pub receiver: AccountId,
    pub amount: U128,
    /// Id of the bridge's signed audit `attempt` event: 64 lowercase hex characters.
    pub attempt_id: String,
    pub memo: Option<String>,
    pub approved: bool,
    pub reasons: Vec<DenyReason>,
    pub transfer: TransferStatus,
    pub block_height: u64,
    pub timestamp_ms: u64,
}
