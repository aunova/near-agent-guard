//! `agent-guard`: a NEAR vault an AI agent can spend from without ever holding a key that can do
//! anything else.
//!
//! The owner (full-access key) gives each agent a [`Policy`]: a per-transaction cap, a rolling
//! window cap, a receiver allowlist and a revocation switch. The agent calls `request_spend` with a
//! function-call key that may call nothing else. Every attempt from a known agent, approved or
//! denied, is appended to an on-chain ledger with the id of the bridge's signed audit event, so the
//! off-chain audit log and the chain cross-check.

#![forbid(unsafe_code)]

mod events;
mod rules;
#[cfg(test)]
mod tests;
pub mod types;

use near_sdk::json_types::U128;
use near_sdk::store::lookup_map::Entry;
use near_sdk::store::{LookupMap, LookupSet, Vector};
use near_sdk::{
    AccountId, BorshStorageKey, Gas, NearToken, PanicOnDefault, Promise, PromiseError,
    assert_one_yocto, env, near, require,
};

use crate::events::{
    AgentRevokedData, GuardEvent, OwnerWithdrawData, PolicySetData, SpendData, TransferSettledData,
};
use crate::types::{Decision, DenyReason, LedgerEntry, Policy, SpendReceipt, TransferStatus};

/// Most receivers one policy may allow.
const MAX_RECEIVERS: usize = 32;
/// Longest memo `request_spend` accepts, in bytes.
const MAX_MEMO_BYTES: usize = 256;
/// Length of an attempt id: a hex SHA-256, i.e. a NIP-01 event id.
const ATTEMPT_ID_LEN: usize = 64;
/// Most entries one `get_ledger` call returns.
const MAX_LEDGER_PAGE: usize = 100;
/// Balance the vault always keeps on top of its storage stake.
const VAULT_RESERVE: NearToken = NearToken::from_millinear(100);
/// Gas reserved for the `on_transfer` callback; it also inherits the call's unused gas.
const ON_TRANSFER_GAS: Gas = Gas::from_tgas(10);

#[near(serializers = [borsh])]
#[derive(BorshStorageKey)]
enum StorageKey {
    Policies,
    Ledger,
    Attempts,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct AgentGuard {
    owner: AccountId,
    policies: LookupMap<AccountId, Policy>,
    ledger: Vector<LedgerEntry>,
    /// Every attempt id ever recorded, so a retried request can never spend twice.
    attempts: LookupSet<String>,
}

#[near]
impl AgentGuard {
    /// Private: only the vault account itself can initialize, so nobody can front-run the
    /// deployment and make themselves owner. Deploy and call `new` in one transaction.
    #[init]
    #[private]
    pub fn new(owner: AccountId) -> Self {
        Self {
            owner,
            policies: LookupMap::new(StorageKey::Policies),
            ledger: Vector::new(StorageKey::Ledger),
            attempts: LookupSet::new(StorageKey::Attempts),
        }
    }

    /// Creates `agent`'s policy with a fresh window, or replaces the limits and allowlist of an
    /// existing one while keeping its window. Always clears `revoked`.
    ///
    /// Owner only, with exactly 1 yoctoNEAR attached: a function-call key cannot attach a deposit,
    /// so only a full-access key can sign this.
    #[payable]
    pub fn set_policy(
        &mut self,
        agent: AccountId,
        per_tx_max: U128,
        window_limit: U128,
        window_secs: u64,
        allowed_receivers: Vec<AccountId>,
    ) {
        self.assert_owner();
        assert_one_yocto();
        require!(window_secs > 0, "window_secs must be greater than 0");
        require!(
            allowed_receivers.len() <= MAX_RECEIVERS,
            format!("at most {MAX_RECEIVERS} allowed_receivers")
        );

        let now_ms = env::block_timestamp_ms();
        let policy = match self.policies.entry(agent.clone()) {
            Entry::Occupied(entry) => {
                let policy = entry.into_mut();
                policy.per_tx_max = per_tx_max;
                policy.window_limit = window_limit;
                policy.window_secs = window_secs;
                policy.allowed_receivers = allowed_receivers;
                policy.revoked = false;
                policy
            }
            Entry::Vacant(entry) => entry.insert(Policy {
                per_tx_max,
                window_limit,
                window_secs,
                allowed_receivers,
                revoked: false,
                window_start_ms: now_ms,
                window_spent: U128(0),
            }),
        };
        GuardEvent::PolicySet(&[PolicySetData {
            agent: &agent,
            per_tx_max,
            window_limit,
            window_secs,
            allowed_receivers: &policy.allowed_receivers,
        }])
        .emit();
    }

    /// Revokes `agent`: every later `request_spend` from it is denied with `revoked` until
    /// `set_policy` is called again. Owner only, with exactly 1 yoctoNEAR attached.
    #[payable]
    pub fn revoke(&mut self, agent: AccountId) {
        self.assert_owner();
        assert_one_yocto();
        let Some(policy) = self.policies.get_mut(&agent) else {
            env::panic_str(&format!("unknown agent {agent}"))
        };
        policy.revoked = true;
        GuardEvent::AgentRevoked(&[AgentRevokedData { agent: &agent }]).emit();
    }

    /// Sends `amount` yoctoNEAR of `vault_available` to the owner: the recovery path once the
    /// vault account's own keys are deleted. Owner only, with exactly 1 yoctoNEAR attached. Not an
    /// agent spend, so it adds no ledger entry.
    #[payable]
    pub fn withdraw(&mut self, amount: U128) {
        self.assert_owner();
        assert_one_yocto();
        require!(amount.0 > 0, "withdraw amount must be greater than 0");
        require!(
            amount.0 <= available_yocto(),
            "withdraw amount exceeds vault_available"
        );
        GuardEvent::OwnerWithdraw(&[OwnerWithdrawData { amount }]).emit();
        Promise::new(self.owner.clone())
            .transfer(NearToken::from_yoctonear(amount.0))
            .detach();
    }

    /// The calling agent asks the vault to send `amount` yoctoNEAR to `receiver`.
    ///
    /// Panics, leaving no state and no ledger entry, for an unknown agent (so strangers cannot
    /// make the vault pay storage for spam), an `attempt_id` that is not 64 lowercase hex
    /// characters, a memo over 256 bytes, or an `attempt_id` already recorded (a bridge retry can
    /// never spend twice). Otherwise records the decision and returns normally whether it approves
    /// or denies: a denial is a successful transaction, so it is on-chain. An approval sends the
    /// transfer, and `on_transfer` settles the entry when it lands.
    pub fn request_spend(
        &mut self,
        receiver: AccountId,
        amount: U128,
        attempt_id: String,
        memo: Option<String>,
    ) -> SpendReceipt {
        let agent = env::predecessor_account_id();
        let now_ms = env::block_timestamp_ms();
        let vault_available = available_yocto();
        let Some(policy) = self.policies.get_mut(&agent) else {
            env::panic_str(&format!("unknown agent {agent}"))
        };
        require!(
            is_attempt_id(&attempt_id),
            "attempt_id must be exactly 64 lowercase hex characters"
        );
        require!(
            memo.as_ref()
                .is_none_or(|memo| memo.len() <= MAX_MEMO_BYTES),
            format!("memo exceeds {MAX_MEMO_BYTES} bytes")
        );
        // Records the id; false means it was already recorded. A panic anywhere in this call
        // rolls the write back.
        let first_attempt = self.attempts.insert(attempt_id.clone());
        require!(first_attempt, "duplicate attempt_id");

        let reasons = rules::decide(policy, &receiver, amount.0, now_ms, vault_available);
        let approved = reasons.is_empty();
        if approved {
            // Approval means window_spent + amount <= window_limit, so this cannot saturate.
            policy.window_spent = U128(policy.window_spent.0.saturating_add(amount.0));
        }

        let index = u64::from(self.ledger.len());
        let entry = LedgerEntry {
            index,
            agent,
            receiver,
            amount,
            attempt_id,
            memo,
            approved,
            reasons,
            transfer: if approved {
                TransferStatus::Pending
            } else {
                TransferStatus::NotAttempted
            },
            block_height: env::block_height(),
            timestamp_ms: now_ms,
        };
        let spend = SpendData {
            index,
            agent: &entry.agent,
            receiver: &entry.receiver,
            amount,
            attempt_id: &entry.attempt_id,
            reasons: &entry.reasons,
        };
        if approved {
            GuardEvent::SpendApproved(&[spend]).emit();
            Promise::new(entry.receiver.clone())
                .transfer(NearToken::from_yoctonear(amount.0))
                .then(
                    Self::ext(env::current_account_id())
                        .with_static_gas(ON_TRANSFER_GAS)
                        .on_transfer(index),
                )
                .detach();
        } else {
            GuardEvent::SpendDenied(&[spend]).emit();
        }

        let receipt = SpendReceipt {
            ledger_index: index,
            approved,
            reasons: entry.reasons.clone(),
        };
        self.ledger.push(entry);
        receipt
    }

    /// Callback of an approved spend's transfer. Success marks the entry `succeeded`. Failure
    /// marks it `failed` and gives the amount back to the agent's window, but only if the entry
    /// was charged to the window that is still current (saturating at 0).
    #[private]
    pub fn on_transfer(&mut self, index: u64, #[callback_result] result: Result<(), PromiseError>) {
        let Some(entry) = u32::try_from(index)
            .ok()
            .and_then(|position| self.ledger.get_mut(position))
        else {
            env::panic_str(&format!("no ledger entry at index {index}"))
        };
        require!(
            entry.transfer == TransferStatus::Pending,
            format!("ledger entry {index} is not pending")
        );

        let window_refund = match result {
            Err(PromiseError::Failed) => {
                entry.transfer = TransferStatus::Failed;
                match self.policies.get_mut(&entry.agent) {
                    Some(policy) if entry.timestamp_ms >= policy.window_start_ms => {
                        let refund = policy.window_spent.0.min(entry.amount.0);
                        policy.window_spent = U128(policy.window_spent.0 - refund);
                        refund
                    }
                    // The entry belongs to an earlier window, which no longer counts.
                    _ => 0,
                }
            }
            // `Ok`, or `TooLong` (PromiseError is non-exhaustive): the transfer receipt succeeded
            // and only its result was long. Only `Failed` can hand window capacity back.
            _ => {
                entry.transfer = TransferStatus::Succeeded;
                0
            }
        };
        GuardEvent::TransferSettled(&[TransferSettledData {
            index,
            agent: &entry.agent,
            receiver: &entry.receiver,
            amount: entry.amount,
            transfer: entry.transfer,
            window_refund: U128(window_refund),
        }])
        .emit();
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn get_policy(&self, agent: AccountId) -> Option<Policy> {
        self.policies.get(&agent).cloned()
    }

    /// What `request_spend` would decide right now: the same rule, applied to a copy of the policy
    /// whose window is rolled forward if it has expired.
    pub fn check_spend(&self, agent: AccountId, receiver: AccountId, amount: U128) -> Decision {
        let Some(stored) = self.policies.get(&agent) else {
            return Decision {
                approved: false,
                reasons: vec![DenyReason::UnknownAgent],
            };
        };
        let mut policy = stored.clone();
        let reasons = rules::decide(
            &mut policy,
            &receiver,
            amount.0,
            env::block_timestamp_ms(),
            available_yocto(),
        );
        Decision {
            approved: reasons.is_empty(),
            reasons,
        }
    }

    /// Up to `limit` entries (capped at 100) starting at `from_index`.
    pub fn get_ledger(&self, from_index: u64, limit: u64) -> Vec<LedgerEntry> {
        // An index beyond usize is beyond any ledger.
        let Ok(skip) = usize::try_from(from_index) else {
            return Vec::new();
        };
        let take =
            usize::try_from(limit).map_or(MAX_LEDGER_PAGE, |limit| limit.min(MAX_LEDGER_PAGE));
        self.ledger.iter().skip(skip).take(take).cloned().collect()
    }

    pub fn ledger_len(&self) -> u64 {
        u64::from(self.ledger.len())
    }

    /// Account balance minus storage stake minus the 0.1 NEAR reserve, saturating at 0. The same
    /// figure decides `insufficient_vault_balance` and caps `withdraw`.
    pub fn vault_available(&self) -> U128 {
        U128(available_yocto())
    }
}

impl AgentGuard {
    fn assert_owner(&self) {
        require!(
            env::predecessor_account_id() == self.owner,
            "only the owner can call this method"
        );
    }
}

/// See [`AgentGuard::vault_available`].
fn available_yocto() -> u128 {
    let storage_stake =
        u128::from(env::storage_usage()).saturating_mul(env::storage_byte_cost().as_yoctonear());
    env::account_balance()
        .as_yoctonear()
        .saturating_sub(storage_stake)
        .saturating_sub(VAULT_RESERVE.as_yoctonear())
}

fn is_attempt_id(id: &str) -> bool {
    id.len() == ATTEMPT_ID_LEN
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
