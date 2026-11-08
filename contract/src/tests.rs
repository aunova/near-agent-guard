//! Unit tests on near-sdk's mocked blockchain (`testing_env!`).
//!
//! Calling a method directly skips the wrapper near-sdk generates for wasm, so `#[private]`, the
//! non-payable deposit check and real promise execution are proven in `tests/sandbox.rs`.
//! Everything inside the method bodies is proven here.

use near_sdk::json_types::U128;
use near_sdk::mock::MockAction;
use near_sdk::serde_json;
use near_sdk::test_utils::{VMContextBuilder, get_created_receipts, get_logs};
use near_sdk::{AccountId, NearToken, PromiseError, env, testing_env};

use crate::rules::decide;
use crate::types::DenyReason::{
    InsufficientVaultBalance, OverPerTxMax, OverWindowLimit, ReceiverNotAllowed, Revoked,
    UnknownAgent, ZeroAmount,
};
use crate::types::{Decision, DenyReason, LedgerEntry, Policy, SpendReceipt, TransferStatus};
use crate::{AgentGuard, MAX_ENTRY_STORAGE_BYTES, ON_TRANSFER_GAS};

const ONE_NEAR: u128 = 10u128.pow(24);
const HALF_NEAR: u128 = ONE_NEAR / 2;
const T0_MS: u64 = 1_762_600_000_000;
const DAY_SECS: u64 = 86_400;
const DAY_MS: u64 = DAY_SECS * 1_000;
const BLOCK_HEIGHT: u64 = 4_242;
/// Default mocked vault: 100 NEAR held, 100 kB stored (1 NEAR stake), so 98.9 NEAR available.
const BALANCE: u128 = 100 * ONE_NEAR;
const STORAGE_BYTES: u64 = 100_000;
/// `setup`'s `max_entries_per_window`: room for the 105-entry pagination test in one window.
const CAP: u32 = 200;
const APPROVED: [DenyReason; 0] = [];

fn account(id: &str) -> AccountId {
    id.parse().unwrap()
}

fn vault() -> AccountId {
    account("vault.aunova-guard.testnet")
}

fn owner() -> AccountId {
    account("aunova-guard.testnet")
}

fn agent() -> AccountId {
    account("agent.aunova-guard.testnet")
}

fn vendor() -> AccountId {
    account("vendor.aunova-guard.testnet")
}

fn drain() -> AccountId {
    account("drain.aunova-guard.testnet")
}

/// A valid attempt id: `n` as 64 lowercase hex digits.
fn attempt(n: u64) -> String {
    format!("{n:064x}")
}

/// Next call: `caller` calls the vault at `now_ms` attaching `deposit` yoctoNEAR, while the vault
/// holds `balance` yoctoNEAR and stores `storage_bytes` bytes.
fn env_full(caller: &AccountId, deposit: u128, now_ms: u64, balance: u128, storage_bytes: u64) {
    testing_env!(
        VMContextBuilder::new()
            .current_account_id(vault())
            .signer_account_id(caller.clone())
            .predecessor_account_id(caller.clone())
            .attached_deposit(NearToken::from_yoctonear(deposit))
            .block_timestamp(now_ms * 1_000_000)
            .block_height(BLOCK_HEIGHT)
            .account_balance(NearToken::from_yoctonear(balance))
            .storage_usage(storage_bytes)
            .build()
    );
}

fn call_as(caller: &AccountId, deposit: u128, now_ms: u64) {
    env_full(caller, deposit, now_ms, BALANCE, STORAGE_BYTES);
}

/// The policy `setup` gives the agent: 0.5 NEAR per transaction, 1 NEAR and `CAP` entries per day,
/// to the vendor only, window starting at T0.
fn policy(per_tx_max: u128, window_limit: u128) -> Policy {
    Policy {
        per_tx_max: U128(per_tx_max),
        window_limit: U128(window_limit),
        window_secs: DAY_SECS,
        max_entries_per_window: CAP,
        allowed_receivers: vec![vendor()],
        revoked: false,
        window_start_ms: T0_MS,
        window_spent: U128(0),
        window_entries: 0,
    }
}

/// A vault owned by `owner()`, with `policy(HALF_NEAR, ONE_NEAR)` set for `agent()` at T0.
fn setup() -> AgentGuard {
    call_as(&vault(), 0, T0_MS);
    let mut guard = AgentGuard::new(owner());
    call_as(&owner(), 1, T0_MS);
    guard.set_policy(
        agent(),
        U128(HALF_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        CAP,
        vec![vendor()],
    );
    guard
}

/// `setup`, plus an approved 0.5 NEAR spend to the vendor at T0 + 1 s (ledger index 0, pending).
fn approved_pending() -> AgentGuard {
    let mut guard = setup();
    call_as(&agent(), 0, T0_MS + 1_000);
    assert!(spend(&mut guard, vendor(), HALF_NEAR, 1).approved);
    guard
}

fn spend(guard: &mut AgentGuard, receiver: AccountId, yocto: u128, n: u64) -> SpendReceipt {
    guard.request_spend(receiver, U128(yocto), attempt(n), None)
}

fn entry(guard: &AgentGuard, index: u64) -> LedgerEntry {
    guard
        .get_ledger(index, 1)
        .into_iter()
        .next()
        .expect("ledger entry")
}

/// The agent's stored (window_start_ms, window_spent).
fn window(guard: &AgentGuard) -> (u64, u128) {
    let policy = guard.get_policy(agent()).expect("agent policy");
    (policy.window_start_ms, policy.window_spent.0)
}

/// The agent's stored window_entries.
fn entries(guard: &AgentGuard) -> u32 {
    guard
        .get_policy(agent())
        .expect("agent policy")
        .window_entries
}

/// The NEP-297 log line for event `name` carrying one `data` object.
fn event(name: &str, data: &str) -> String {
    format!(
        r#"EVENT_JSON:{{"standard":"agent_guard","version":"1.0.0","event":"{name}","data":[{data}]}}"#
    )
}

// Wire shapes, byte for byte as spec section 1 writes them.

#[test]
fn policy_json_is_the_spec_shape() {
    let mut policy = policy(HALF_NEAR, ONE_NEAR);
    policy.window_start_ms = 1_762_600_000_000;
    policy.window_entries = 3;
    assert_eq!(
        serde_json::to_string(&policy).unwrap(),
        r#"{"per_tx_max":"500000000000000000000000","window_limit":"1000000000000000000000000","window_secs":86400,"max_entries_per_window":200,"allowed_receivers":["vendor.aunova-guard.testnet"],"revoked":false,"window_start_ms":1762600000000,"window_spent":"0","window_entries":3}"#
    );
}

#[test]
fn decision_and_receipt_json_are_the_spec_shape() {
    let reasons = vec![ReceiverNotAllowed, OverPerTxMax, OverWindowLimit];
    let decision = Decision {
        approved: false,
        reasons: reasons.clone(),
    };
    assert_eq!(
        serde_json::to_string(&decision).unwrap(),
        r#"{"approved":false,"reasons":["receiver_not_allowed","over_per_tx_max","over_window_limit"]}"#
    );
    let receipt = SpendReceipt {
        ledger_index: 1,
        approved: false,
        reasons,
    };
    assert_eq!(
        serde_json::to_string(&receipt).unwrap(),
        r#"{"ledger_index":1,"approved":false,"reasons":["receiver_not_allowed","over_per_tx_max","over_window_limit"]}"#
    );
}

#[test]
fn ledger_entry_json_is_the_spec_shape() {
    let entry = LedgerEntry {
        index: 0,
        agent: agent(),
        receiver: vendor(),
        amount: U128(HALF_NEAR),
        attempt_id: attempt(1),
        memo: Some("INV-2026-11-001".to_owned()),
        approved: true,
        reasons: vec![],
        transfer: TransferStatus::Succeeded,
        block_height: 123_456,
        timestamp_ms: 1_762_600_000_000,
    };
    assert_eq!(
        serde_json::to_string(&entry).unwrap(),
        format!(
            r#"{{"index":0,"agent":"agent.aunova-guard.testnet","receiver":"vendor.aunova-guard.testnet","amount":"500000000000000000000000","attempt_id":"{}","memo":"INV-2026-11-001","approved":true,"reasons":[],"transfer":"succeeded","block_height":123456,"timestamp_ms":1762600000000}}"#,
            attempt(1)
        )
    );
}

#[test]
fn deny_reasons_and_transfer_statuses_use_the_spec_names() {
    let reasons = [
        UnknownAgent,
        Revoked,
        ZeroAmount,
        ReceiverNotAllowed,
        OverPerTxMax,
        OverWindowLimit,
        InsufficientVaultBalance,
    ];
    assert_eq!(
        serde_json::to_string(&reasons).unwrap(),
        r#"["unknown_agent","revoked","zero_amount","receiver_not_allowed","over_per_tx_max","over_window_limit","insufficient_vault_balance"]"#
    );
    let statuses = [
        TransferStatus::NotAttempted,
        TransferStatus::Pending,
        TransferStatus::Succeeded,
        TransferStatus::Failed,
    ];
    assert_eq!(
        serde_json::to_string(&statuses).unwrap(),
        r#"["not_attempted","pending","succeeded","failed"]"#
    );
}

// The rule: decide().

#[test]
fn decide_lists_every_applicable_reason_in_spec_order() {
    let mut revoked = policy(HALF_NEAR, ONE_NEAR);
    revoked.revoked = true;
    // 5 NEAR to drain from a revoked agent while the vault can spend 1 NEAR: five reasons.
    assert_eq!(
        decide(
            &mut revoked.clone(),
            &drain(),
            5 * ONE_NEAR,
            T0_MS,
            ONE_NEAR
        ),
        [
            Revoked,
            ReceiverNotAllowed,
            OverPerTxMax,
            OverWindowLimit,
            InsufficientVaultBalance
        ]
    );
    // zero_amount sits between revoked and receiver_not_allowed.
    assert_eq!(
        decide(&mut revoked, &drain(), 0, T0_MS, ONE_NEAR),
        [Revoked, ZeroAmount, ReceiverNotAllowed]
    );
}

#[test]
fn decide_fires_each_reason_alone_exactly_past_its_limit() {
    let plenty = 10 * ONE_NEAR;
    let base = policy(HALF_NEAR, ONE_NEAR);
    let judge = |policy: &Policy, receiver: AccountId, amount: u128, available: u128| {
        decide(&mut policy.clone(), &receiver, amount, T0_MS, available)
    };

    assert_eq!(judge(&base, vendor(), HALF_NEAR, plenty), APPROVED);
    assert_eq!(
        judge(&base, vendor(), HALF_NEAR + 1, plenty),
        [OverPerTxMax]
    );
    assert_eq!(judge(&base, vendor(), 0, plenty), [ZeroAmount]);
    assert_eq!(judge(&base, drain(), 1, plenty), [ReceiverNotAllowed]);

    let mut revoked = base.clone();
    revoked.revoked = true;
    assert_eq!(judge(&revoked, vendor(), 1, plenty), [Revoked]);

    // 0.75 NEAR already spent: 0.25 NEAR exactly fills the window, one yocto more does not.
    let mut charged = base.clone();
    charged.window_spent = U128(ONE_NEAR - HALF_NEAR / 2);
    assert_eq!(judge(&charged, vendor(), HALF_NEAR / 2, plenty), APPROVED);
    assert_eq!(
        judge(&charged, vendor(), HALF_NEAR / 2 + 1, plenty),
        [OverWindowLimit]
    );

    assert_eq!(judge(&base, vendor(), HALF_NEAR, HALF_NEAR), APPROVED);
    assert_eq!(
        judge(&base, vendor(), HALF_NEAR, HALF_NEAR - 1),
        [InsufficientVaultBalance]
    );
}

#[test]
fn decide_counts_an_overflowing_window_sum_as_over_the_limit() {
    let mut full = policy(u128::MAX, u128::MAX);
    full.window_spent = U128(u128::MAX);
    assert_eq!(
        decide(&mut full, &vendor(), 1, T0_MS, u128::MAX),
        [OverWindowLimit]
    );
}

#[test]
fn decide_rolls_the_window_exactly_at_its_end() {
    let mut minute = policy(ONE_NEAR, ONE_NEAR);
    minute.window_secs = 60;
    minute.window_spent = U128(ONE_NEAR);

    // One millisecond before the end: still the full window, left untouched.
    assert_eq!(
        decide(&mut minute, &vendor(), 1, T0_MS + 59_999, u128::MAX),
        [OverWindowLimit]
    );
    assert_eq!(
        (minute.window_start_ms, minute.window_spent.0),
        (T0_MS, ONE_NEAR)
    );

    // At the end: a fresh window starting now.
    assert_eq!(
        decide(&mut minute, &vendor(), 1, T0_MS + 60_000, u128::MAX),
        APPROVED
    );
    assert_eq!(
        (minute.window_start_ms, minute.window_spent.0),
        (T0_MS + 60_000, 0)
    );
}

#[test]
fn decide_saturates_a_window_end_beyond_u64() {
    let mut endless = policy(ONE_NEAR, ONE_NEAR);
    endless.window_secs = u64::MAX;
    endless.window_spent = U128(ONE_NEAR);
    // window_start_ms + u64::MAX seconds saturates instead of overflowing: no roll a century on.
    let century_later = T0_MS + 100 * 365 * DAY_MS;
    assert_eq!(
        decide(&mut endless, &vendor(), 1, century_later, u128::MAX),
        [OverWindowLimit]
    );
    assert_eq!(endless.window_start_ms, T0_MS);
}

// set_policy and revoke.

#[test]
fn set_policy_creates_a_fresh_window_and_emits_policy_set() {
    call_as(&vault(), 0, T0_MS);
    let mut guard = AgentGuard::new(owner());
    call_as(&owner(), 1, T0_MS);
    guard.set_policy(
        agent(),
        U128(HALF_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        CAP,
        vec![vendor()],
    );

    assert_eq!(guard.get_owner(), owner());
    assert_eq!(guard.get_policy(agent()), Some(policy(HALF_NEAR, ONE_NEAR)));
    assert_eq!(guard.get_policy(drain()), None);
    assert_eq!(
        get_logs(),
        [event(
            "policy_set",
            r#"{"agent":"agent.aunova-guard.testnet","per_tx_max":"500000000000000000000000","window_limit":"1000000000000000000000000","window_secs":86400,"max_entries_per_window":200,"allowed_receivers":["vendor.aunova-guard.testnet"]}"#
        )]
    );
}

#[test]
fn set_policy_on_an_existing_agent_keeps_the_window_and_clears_revoked() {
    let mut guard = approved_pending();
    call_as(&owner(), 1, T0_MS + 2_000);
    guard.revoke(agent());
    call_as(&owner(), 1, T0_MS + 3_000);
    guard.set_policy(
        agent(),
        U128(ONE_NEAR),
        U128(2 * ONE_NEAR),
        3_600,
        7,
        vec![vendor(), drain()],
    );
    assert_eq!(
        guard.get_policy(agent()),
        Some(Policy {
            per_tx_max: U128(ONE_NEAR),
            window_limit: U128(2 * ONE_NEAR),
            window_secs: 3_600,
            max_entries_per_window: 7,
            allowed_receivers: vec![vendor(), drain()],
            revoked: false,
            window_start_ms: T0_MS,
            window_spent: U128(HALF_NEAR),
            window_entries: 1,
        })
    );
}

#[test]
#[should_panic(expected = "only the owner can call this method")]
fn set_policy_rejects_a_non_owner() {
    let mut guard = setup();
    call_as(&drain(), 1, T0_MS);
    guard.set_policy(
        drain(),
        U128(ONE_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        CAP,
        vec![drain()],
    );
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn set_policy_rejects_a_missing_yocto() {
    let mut guard = setup();
    call_as(&owner(), 0, T0_MS);
    guard.set_policy(
        agent(),
        U128(ONE_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        CAP,
        vec![vendor()],
    );
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn set_policy_rejects_two_yocto() {
    let mut guard = setup();
    call_as(&owner(), 2, T0_MS);
    guard.set_policy(
        agent(),
        U128(ONE_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        CAP,
        vec![vendor()],
    );
}

#[test]
#[should_panic(expected = "window_secs must be greater than 0")]
fn set_policy_rejects_a_zero_window() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.set_policy(
        agent(),
        U128(ONE_NEAR),
        U128(ONE_NEAR),
        0,
        CAP,
        vec![vendor()],
    );
}

fn set_entry_cap(max_entries_per_window: u32) -> AgentGuard {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.set_policy(
        agent(),
        U128(HALF_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        max_entries_per_window,
        vec![vendor()],
    );
    guard
}

#[test]
fn set_policy_accepts_entry_caps_from_1_to_1000() {
    for cap in [1, 1_000] {
        let guard = set_entry_cap(cap);
        assert_eq!(
            guard.get_policy(agent()).unwrap().max_entries_per_window,
            cap
        );
    }
}

#[test]
#[should_panic(expected = "max_entries_per_window must be between 1 and 1000")]
fn set_policy_rejects_a_zero_entry_cap() {
    set_entry_cap(0);
}

#[test]
#[should_panic(expected = "max_entries_per_window must be between 1 and 1000")]
fn set_policy_rejects_an_entry_cap_over_1000() {
    set_entry_cap(1_001);
}

fn receivers(count: usize) -> Vec<AccountId> {
    (0..count)
        .map(|n| account(&format!("receiver{n}.testnet")))
        .collect()
}

#[test]
fn set_policy_accepts_32_receivers() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.set_policy(
        agent(),
        U128(ONE_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        CAP,
        receivers(32),
    );
    assert_eq!(
        guard.get_policy(agent()).unwrap().allowed_receivers.len(),
        32
    );
}

#[test]
#[should_panic(expected = "at most 32 allowed_receivers")]
fn set_policy_rejects_33_receivers() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.set_policy(
        agent(),
        U128(ONE_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        CAP,
        receivers(33),
    );
}

#[test]
fn revoke_emits_agent_revoked_and_check_spend_reports_revoked() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.revoke(agent());
    assert!(guard.get_policy(agent()).unwrap().revoked);
    assert_eq!(
        get_logs(),
        [event(
            "agent_revoked",
            r#"{"agent":"agent.aunova-guard.testnet"}"#
        )]
    );
    assert_eq!(
        guard.check_spend(agent(), vendor(), U128(1)),
        Decision {
            approved: false,
            reasons: vec![Revoked],
        }
    );
}

#[test]
#[should_panic(expected = "agent revoked")]
fn a_revoked_agent_cannot_record_anything() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.revoke(agent());
    call_as(&agent(), 0, T0_MS + 1_000);
    spend(&mut guard, vendor(), 1, 1);
}

#[test]
#[should_panic(expected = "unknown agent drain.aunova-guard.testnet")]
fn revoke_rejects_an_unknown_agent() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.revoke(drain());
}

#[test]
#[should_panic(expected = "only the owner can call this method")]
fn revoke_rejects_a_non_owner() {
    let mut guard = setup();
    call_as(&agent(), 1, T0_MS);
    guard.revoke(agent());
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn revoke_rejects_a_missing_yocto() {
    let mut guard = setup();
    call_as(&owner(), 0, T0_MS);
    guard.revoke(agent());
}

// request_spend.

#[test]
fn approved_spend_records_charges_and_sends_the_transfer_with_its_callback() {
    let mut guard = setup();
    call_as(&agent(), 0, T0_MS + 1_000);
    let receipt = guard.request_spend(
        vendor(),
        U128(HALF_NEAR),
        attempt(1),
        Some("INV-2026-11-001".to_owned()),
    );

    assert_eq!(
        receipt,
        SpendReceipt {
            ledger_index: 0,
            approved: true,
            reasons: vec![],
        }
    );
    assert_eq!(
        entry(&guard, 0),
        LedgerEntry {
            index: 0,
            agent: agent(),
            receiver: vendor(),
            amount: U128(HALF_NEAR),
            attempt_id: attempt(1),
            memo: Some("INV-2026-11-001".to_owned()),
            approved: true,
            reasons: vec![],
            transfer: TransferStatus::Pending,
            block_height: BLOCK_HEIGHT,
            timestamp_ms: T0_MS + 1_000,
        }
    );
    assert_eq!(window(&guard), (T0_MS, HALF_NEAR));

    let receipts = get_created_receipts();
    assert_eq!(receipts.len(), 2, "{receipts:?}");
    assert_eq!(receipts[0].receiver_id, vendor());
    assert!(
        matches!(
            receipts[0].actions.as_slice(),
            [MockAction::Transfer { deposit, .. }] if *deposit == NearToken::from_yoctonear(HALF_NEAR)
        ),
        "{:?}",
        receipts[0]
    );
    assert_eq!(receipts[1].receiver_id, vault());
    assert_eq!(receipts[1].receipt_indices, [0]);
    assert!(
        matches!(
            receipts[1].actions.as_slice(),
            [MockAction::FunctionCallWeight { method_name, args, attached_deposit, prepaid_gas, .. }]
                if method_name == b"on_transfer"
                    && args == br#"{"index":0}"#
                    && *attached_deposit == NearToken::from_yoctonear(0)
                    && *prepaid_gas == ON_TRANSFER_GAS
        ),
        "{:?}",
        receipts[1]
    );

    assert_eq!(
        get_logs(),
        [event(
            "spend_approved",
            &format!(
                r#"{{"index":0,"agent":"agent.aunova-guard.testnet","receiver":"vendor.aunova-guard.testnet","amount":"500000000000000000000000","attempt_id":"{}","reasons":[]}}"#,
                attempt(1)
            )
        )]
    );
}

#[test]
fn denied_spend_is_recorded_with_every_reason_and_sends_nothing() {
    let mut guard = setup();
    call_as(&agent(), 0, T0_MS + 1_000);
    let receipt = spend(&mut guard, drain(), 5 * ONE_NEAR, 2);

    assert_eq!(
        receipt,
        SpendReceipt {
            ledger_index: 0,
            approved: false,
            reasons: vec![ReceiverNotAllowed, OverPerTxMax, OverWindowLimit],
        }
    );
    let recorded = entry(&guard, 0);
    assert!(!recorded.approved);
    assert_eq!(recorded.reasons, receipt.reasons);
    assert_eq!(recorded.transfer, TransferStatus::NotAttempted);
    assert_eq!(recorded.memo, None);
    assert_eq!(window(&guard), (T0_MS, 0));
    assert!(get_created_receipts().is_empty());
    assert_eq!(
        get_logs(),
        [event(
            "spend_denied",
            &format!(
                r#"{{"index":0,"agent":"agent.aunova-guard.testnet","receiver":"drain.aunova-guard.testnet","amount":"5000000000000000000000000","attempt_id":"{}","reasons":["receiver_not_allowed","over_per_tx_max","over_window_limit"]}}"#,
                attempt(2)
            )
        )]
    );
}

#[test]
fn request_spend_rolls_the_stored_window() {
    let mut guard = setup();
    call_as(&agent(), 0, T0_MS + 1_000);
    assert!(spend(&mut guard, vendor(), HALF_NEAR, 1).approved);
    assert!(spend(&mut guard, vendor(), HALF_NEAR, 2).approved);
    assert_eq!(spend(&mut guard, vendor(), 1, 3).reasons, [OverWindowLimit]);

    call_as(&agent(), 0, T0_MS + DAY_MS);
    assert!(spend(&mut guard, vendor(), HALF_NEAR, 4).approved);
    assert_eq!(window(&guard), (T0_MS + DAY_MS, HALF_NEAR));
}

#[test]
fn check_spend_runs_request_spends_rule_and_rolls_only_a_copy() {
    let mut guard = approved_pending();

    // Same moment: the view and the call agree on a 0.6 NEAR request.
    call_as(&agent(), 0, T0_MS + 2_000);
    let decision = guard.check_spend(agent(), vendor(), U128(HALF_NEAR + ONE_NEAR / 10));
    assert_eq!(
        decision,
        Decision {
            approved: false,
            reasons: vec![OverPerTxMax, OverWindowLimit],
        }
    );
    let receipt = spend(&mut guard, vendor(), HALF_NEAR + ONE_NEAR / 10, 2);
    assert_eq!(
        (receipt.approved, receipt.reasons),
        (decision.approved, decision.reasons)
    );

    // Once the window has ended the view rolls a copy, so the full limit is free again...
    call_as(&agent(), 0, T0_MS + DAY_MS);
    assert_eq!(
        guard.check_spend(agent(), vendor(), U128(HALF_NEAR)),
        Decision {
            approved: true,
            reasons: vec![],
        }
    );
    // ...while the stored policy is untouched.
    assert_eq!(window(&guard), (T0_MS, HALF_NEAR));
}

#[test]
fn check_spend_reports_an_unknown_agent() {
    let guard = setup();
    assert_eq!(
        serde_json::to_string(&guard.check_spend(drain(), vendor(), U128(1))).unwrap(),
        r#"{"approved":false,"reasons":["unknown_agent"]}"#
    );
}

#[test]
#[should_panic(expected = "unknown agent drain.aunova-guard.testnet")]
fn request_spend_rejects_an_unknown_agent() {
    let mut guard = setup();
    call_as(&drain(), 0, T0_MS);
    spend(&mut guard, drain(), 1, 1);
}

fn spend_with_attempt_id(attempt_id: String) -> SpendReceipt {
    let mut guard = setup();
    call_as(&agent(), 0, T0_MS);
    guard.request_spend(vendor(), U128(1), attempt_id, None)
}

#[test]
fn attempt_id_accepts_every_lowercase_hex_digit() {
    assert!(spend_with_attempt_id("0123456789abcdef".repeat(4)).approved);
}

#[test]
#[should_panic(expected = "attempt_id must be exactly 64 lowercase hex characters")]
fn attempt_id_of_63_characters_is_rejected() {
    spend_with_attempt_id("a".repeat(63));
}

#[test]
#[should_panic(expected = "attempt_id must be exactly 64 lowercase hex characters")]
fn attempt_id_of_65_characters_is_rejected() {
    spend_with_attempt_id("a".repeat(65));
}

#[test]
#[should_panic(expected = "attempt_id must be exactly 64 lowercase hex characters")]
fn uppercase_attempt_id_is_rejected() {
    spend_with_attempt_id("A".repeat(64));
}

#[test]
#[should_panic(expected = "attempt_id must be exactly 64 lowercase hex characters")]
fn non_hex_attempt_id_is_rejected() {
    spend_with_attempt_id("g".repeat(64));
}

fn spend_with_memo(memo: String) -> SpendReceipt {
    let mut guard = setup();
    call_as(&agent(), 0, T0_MS);
    guard.request_spend(vendor(), U128(1), attempt(1), Some(memo))
}

#[test]
fn memo_of_256_bytes_is_accepted() {
    // 128 characters of 2 bytes each: the limit counts bytes, not characters.
    assert!(spend_with_memo("é".repeat(128)).approved);
}

#[test]
#[should_panic(expected = "memo exceeds 256 bytes")]
fn memo_of_257_bytes_is_rejected() {
    // Only 129 characters, but 257 bytes.
    spend_with_memo(format!("{}a", "é".repeat(128)));
}

#[test]
#[should_panic(expected = "duplicate attempt_id")]
fn duplicate_attempt_id_is_rejected() {
    let mut guard = setup();
    call_as(&agent(), 0, T0_MS);
    spend(&mut guard, vendor(), 1, 7);
    spend(&mut guard, vendor(), 1, 7);
}

#[test]
#[should_panic(expected = "duplicate attempt_id")]
fn a_denied_attempt_id_cannot_be_retried() {
    let mut guard = setup();
    call_as(&agent(), 0, T0_MS);
    assert!(!spend(&mut guard, drain(), 1, 8).approved);
    spend(&mut guard, vendor(), 1, 8);
}

#[test]
#[should_panic(expected = "duplicate attempt_id")]
fn attempt_ids_are_unique_across_agents() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.set_policy(
        drain(),
        U128(ONE_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        CAP,
        vec![vendor()],
    );
    call_as(&agent(), 0, T0_MS);
    spend(&mut guard, vendor(), 1, 9);
    call_as(&drain(), 0, T0_MS);
    spend(&mut guard, vendor(), 1, 9);
}

// The per-window entry cap.

#[test]
fn approved_and_denied_entries_both_count_against_the_window() {
    let mut guard = set_entry_cap(2);
    call_as(&agent(), 0, T0_MS + 1_000);
    assert!(spend(&mut guard, vendor(), 1, 1).approved);
    assert_eq!(entries(&guard), 1);
    assert!(!spend(&mut guard, drain(), 1, 2).approved);
    assert_eq!(entries(&guard), 2);
}

#[test]
#[should_panic(expected = "window entry cap reached")]
fn a_full_window_refuses_further_requests() {
    let mut guard = set_entry_cap(2);
    call_as(&agent(), 0, T0_MS + 1_000);
    spend(&mut guard, vendor(), 1, 1);
    spend(&mut guard, drain(), 1, 2);
    spend(&mut guard, drain(), 1, 3);
}

#[test]
fn the_entry_count_resets_when_the_window_rolls() {
    let mut guard = set_entry_cap(2);
    call_as(&agent(), 0, T0_MS + 1_000);
    spend(&mut guard, vendor(), 1, 1);
    spend(&mut guard, drain(), 1, 2);
    // The window started at T0 and lasts a day; this request rolls it before the cap is checked.
    call_as(&agent(), 0, T0_MS + DAY_MS);
    assert!(spend(&mut guard, vendor(), 1, 3).approved);
    assert_eq!(entries(&guard), 1);
    assert_eq!(window(&guard).0, T0_MS + DAY_MS);
}

#[test]
#[should_panic(expected = "window entry cap reached")]
fn lowering_the_cap_below_the_count_refuses_until_the_window_rolls() {
    let mut guard = set_entry_cap(3);
    call_as(&agent(), 0, T0_MS + 1_000);
    spend(&mut guard, vendor(), 1, 1);
    spend(&mut guard, drain(), 1, 2);
    call_as(&owner(), 1, T0_MS + 2_000);
    guard.set_policy(
        agent(),
        U128(HALF_NEAR),
        U128(ONE_NEAR),
        DAY_SECS,
        1,
        vec![vendor()],
    );
    call_as(&agent(), 0, T0_MS + 3_000);
    spend(&mut guard, vendor(), 1, 3);
}

#[test]
fn max_entry_storage_bytes_is_the_measured_worst_case() {
    // The longest agent and receiver ids (64 characters), the longest memo (256 bytes) and the
    // most reasons a recorded entry can carry.
    let long_agent = account(&"a".repeat(64));
    call_as(&vault(), 0, T0_MS);
    let mut guard = AgentGuard::new(owner());
    call_as(&owner(), 1, T0_MS);
    guard.set_policy(
        long_agent.clone(),
        U128(1),
        U128(1),
        DAY_SECS,
        CAP,
        vec![vendor()],
    );
    // Write out everything cached so far, so the delta below is the entry alone.
    guard.policies.flush();
    guard.ledger.flush();

    call_as(&long_agent, 0, T0_MS + 1_000);
    let before = env::storage_usage();
    let receipt = guard.request_spend(
        account(&"f".repeat(64)),
        U128(u128::MAX),
        attempt(1),
        Some("x".repeat(256)),
    );
    assert_eq!(
        receipt.reasons,
        [
            ReceiverNotAllowed,
            OverPerTxMax,
            OverWindowLimit,
            InsufficientVaultBalance
        ]
    );
    guard.policies.flush();
    guard.ledger.flush();
    assert_eq!(env::storage_usage() - before, MAX_ENTRY_STORAGE_BYTES);
    assert_eq!(
        AgentGuard::max_entry_storage_bytes(),
        MAX_ENTRY_STORAGE_BYTES
    );
}

// Ledger pagination.

#[test]
fn get_ledger_pages_at_most_100_entries() {
    let mut guard = setup();
    for n in 0..105 {
        // One call per spend, as on chain: a single call may log at most 16 KiB.
        call_as(&agent(), 0, T0_MS);
        spend(&mut guard, drain(), 1, n);
    }
    let indices = |page: Vec<LedgerEntry>| page.iter().map(|entry| entry.index).collect::<Vec<_>>();

    assert_eq!(guard.ledger_len(), 105);
    assert_eq!(
        indices(guard.get_ledger(0, 1_000)),
        (0..100).collect::<Vec<_>>()
    );
    assert_eq!(
        indices(guard.get_ledger(100, 100)),
        (100..105).collect::<Vec<_>>()
    );
    assert_eq!(
        indices(guard.get_ledger(2, u64::MAX)),
        (2..102).collect::<Vec<_>>()
    );
    assert!(guard.get_ledger(105, 1).is_empty());
    assert!(guard.get_ledger(3, 0).is_empty());
    assert!(guard.get_ledger(u64::MAX, u64::MAX).is_empty());
    assert_eq!(entry(&guard, 42).attempt_id, attempt(42));
}

// on_transfer.

#[test]
fn successful_transfer_settles_succeeded_without_refund() {
    let mut guard = approved_pending();
    call_as(&vault(), 0, T0_MS + 2_000);
    guard.on_transfer(0, Ok(()));
    assert_eq!(entry(&guard, 0).transfer, TransferStatus::Succeeded);
    assert_eq!(window(&guard), (T0_MS, HALF_NEAR));
    assert_eq!(
        get_logs(),
        [event(
            "transfer_settled",
            r#"{"index":0,"agent":"agent.aunova-guard.testnet","receiver":"vendor.aunova-guard.testnet","amount":"500000000000000000000000","transfer":"succeeded","window_refund":"0"}"#
        )]
    );
}

#[test]
fn a_too_long_result_still_counts_as_success() {
    let mut guard = approved_pending();
    call_as(&vault(), 0, T0_MS + 2_000);
    guard.on_transfer(0, Err(PromiseError::TooLong(1)));
    assert_eq!(entry(&guard, 0).transfer, TransferStatus::Succeeded);
    assert_eq!(window(&guard), (T0_MS, HALF_NEAR));
}

#[test]
fn failed_transfer_in_the_current_window_is_refunded() {
    let mut guard = approved_pending();
    call_as(&vault(), 0, T0_MS + 2_000);
    guard.on_transfer(0, Err(PromiseError::Failed));
    assert_eq!(entry(&guard, 0).transfer, TransferStatus::Failed);
    assert_eq!(window(&guard), (T0_MS, 0));
    assert_eq!(
        get_logs(),
        [event(
            "transfer_settled",
            r#"{"index":0,"agent":"agent.aunova-guard.testnet","receiver":"vendor.aunova-guard.testnet","amount":"500000000000000000000000","transfer":"failed","window_refund":"500000000000000000000000"}"#
        )]
    );
}

#[test]
fn failed_transfer_from_an_earlier_window_is_not_refunded() {
    let mut guard = approved_pending();
    // A day later a new window starts and is charged 0.3 NEAR before the old transfer settles.
    call_as(&agent(), 0, T0_MS + DAY_MS);
    assert!(spend(&mut guard, vendor(), 3 * ONE_NEAR / 10, 2).approved);
    call_as(&vault(), 0, T0_MS + DAY_MS + 1_000);
    guard.on_transfer(0, Err(PromiseError::Failed));

    assert_eq!(entry(&guard, 0).transfer, TransferStatus::Failed);
    assert_eq!(window(&guard), (T0_MS + DAY_MS, 3 * ONE_NEAR / 10));
    assert!(
        get_logs()[0].ends_with(r#""transfer":"failed","window_refund":"0"}]}"#),
        "{:?}",
        get_logs()
    );
}

#[test]
#[should_panic(expected = "ledger entry 0 is not pending")]
fn a_denied_entry_cannot_be_settled() {
    let mut guard = setup();
    call_as(&agent(), 0, T0_MS);
    assert!(!spend(&mut guard, drain(), 1, 1).approved);
    call_as(&vault(), 0, T0_MS);
    guard.on_transfer(0, Ok(()));
}

#[test]
#[should_panic(expected = "ledger entry 0 is not pending")]
fn a_transfer_settles_only_once() {
    let mut guard = approved_pending();
    call_as(&vault(), 0, T0_MS + 2_000);
    guard.on_transfer(0, Err(PromiseError::Failed));
    guard.on_transfer(0, Err(PromiseError::Failed));
}

#[test]
#[should_panic(expected = "no ledger entry at index 9")]
fn settling_a_missing_entry_panics() {
    let mut guard = approved_pending();
    call_as(&vault(), 0, T0_MS + 2_000);
    guard.on_transfer(9, Ok(()));
}

// vault_available and withdraw.

#[test]
fn vault_available_is_balance_minus_storage_stake_minus_reserve() {
    let guard = setup();
    // 10 NEAR held, 100 kB stored (1 NEAR at 10^19 yoctoNEAR per byte), 0.1 NEAR reserve.
    env_full(&owner(), 0, T0_MS, 10 * ONE_NEAR, 100_000);
    assert_eq!(guard.vault_available(), U128(89 * ONE_NEAR / 10));
    // Less than stake plus reserve: zero, not an underflow.
    env_full(&owner(), 0, T0_MS, ONE_NEAR, 100_000);
    assert_eq!(guard.vault_available(), U128(0));
}

#[test]
fn insufficient_vault_balance_uses_the_vault_available_figure() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.set_policy(
        agent(),
        U128(u128::MAX),
        U128(u128::MAX),
        DAY_SECS,
        CAP,
        vec![vendor()],
    );

    // 10 NEAR held, 1 NEAR stake, 0.1 NEAR reserve: 8.9 NEAR spendable.
    env_full(&agent(), 0, T0_MS, 10 * ONE_NEAR, 100_000);
    let available = 89 * ONE_NEAR / 10;
    assert_eq!(
        guard
            .check_spend(agent(), vendor(), U128(available + 1))
            .reasons,
        [InsufficientVaultBalance]
    );
    assert_eq!(
        spend(&mut guard, vendor(), available + 1, 1).reasons,
        [InsufficientVaultBalance]
    );
    // A fresh call: the denied attempt above already stored its id, which costs storage.
    env_full(&agent(), 0, T0_MS, 10 * ONE_NEAR, 100_000);
    assert!(spend(&mut guard, vendor(), available, 2).approved);
}

#[test]
fn withdraw_sends_the_amount_to_the_owner_without_a_ledger_entry() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.withdraw(U128(2 * ONE_NEAR));

    let receipts = get_created_receipts();
    assert_eq!(receipts.len(), 1, "{receipts:?}");
    assert_eq!(receipts[0].receiver_id, owner());
    assert!(
        matches!(
            receipts[0].actions.as_slice(),
            [MockAction::Transfer { deposit, .. }] if *deposit == NearToken::from_near(2)
        ),
        "{:?}",
        receipts[0]
    );
    assert_eq!(
        get_logs(),
        [event(
            "owner_withdraw",
            r#"{"amount":"2000000000000000000000000"}"#
        )]
    );
    assert_eq!(guard.ledger_len(), 0);
}

#[test]
fn withdraw_may_take_exactly_vault_available() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    let available = guard.vault_available();
    guard.withdraw(available);
    assert_eq!(get_created_receipts().len(), 1);
}

#[test]
#[should_panic(expected = "withdraw amount exceeds vault_available")]
fn withdraw_rejects_more_than_vault_available() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    let available = guard.vault_available().0;
    guard.withdraw(U128(available + 1));
}

#[test]
#[should_panic(expected = "withdraw amount must be greater than 0")]
fn withdraw_rejects_zero() {
    let mut guard = setup();
    call_as(&owner(), 1, T0_MS);
    guard.withdraw(U128(0));
}

#[test]
#[should_panic(expected = "only the owner can call this method")]
fn withdraw_rejects_a_non_owner() {
    let mut guard = setup();
    call_as(&agent(), 1, T0_MS);
    guard.withdraw(U128(ONE_NEAR));
}

#[test]
#[should_panic(expected = "Requires attached deposit of exactly 1 yoctoNEAR")]
fn withdraw_rejects_a_missing_yocto() {
    let mut guard = setup();
    call_as(&owner(), 0, T0_MS);
    guard.withdraw(U128(ONE_NEAR));
}
