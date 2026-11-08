//! Sandbox tests: a local neard runs the wasm that `cargo near build non-reproducible-wasm` wrote
//! to `target/near/agent_guard.wasm`. They deploy whatever file is there, so rebuild it after
//! changing the contract.
//!
//! The agent signs ONLY with a function-call access key (receiver = the vault, methods =
//! `["request_spend"]`), exactly like the bridge on testnet. Every rejection prints the error the
//! chain returned, so `cargo test -- --show-output` shows each guard firing.

use std::error::Error;

use agent_guard::types::{Decision, DenyReason, LedgerEntry, Policy, SpendReceipt, TransferStatus};
use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
use near_jsonrpc_client::methods::broadcast_tx_commit::RpcTransactionError;
use near_primitives::errors::{
    ActionError, ActionErrorKind, FunctionCallError, InvalidAccessKeyError, InvalidTxError,
    TxExecutionError,
};
use near_sdk::json_types::U128;
use near_sdk::serde_json::{self, json};
use near_workspaces::error::{ErrorKind, RpcErrorCode};
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::types::{AccessKeyPermission, Gas, KeyType, NearToken, SecretKey};
use near_workspaces::{AccessKey, Account, AccountId, Contract, Worker};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WASM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/near/agent_guard.wasm");
const ONE_NEAR: u128 = 10u128.pow(24);
const HALF_NEAR: u128 = ONE_NEAR / 2;
/// The gas the bridge attaches to `request_spend`.
const SPEND_GAS: Gas = Gas::from_tgas(50);
const MEMO: &str = "INV-2026-11-001";
/// `max_entries_per_window` of the scenario policies; only the griefing test reaches a cap.
const ENTRY_CAP: u32 = 100;
/// yoctoNEAR per byte of storage (`env::storage_byte_cost`).
const STORAGE_BYTE_COST: u128 = 10u128.pow(19);

fn contract_wasm() -> Vec<u8> {
    std::fs::read(WASM).unwrap_or_else(|err| {
        panic!("{WASM}: {err}. Build it first: cargo near build non-reproducible-wasm")
    })
}

/// A valid attempt id: `n` as 64 lowercase hex digits.
fn attempt(n: u64) -> String {
    format!("{n:064x}")
}

struct Scene {
    worker: Worker<Sandbox>,
    root: Account,
    owner: Account,
    vault: Contract,
    /// Signs with the function-call key only.
    agent: Account,
    vendor: Account,
    drain: Account,
}

async fn subaccount(parent: &Account, name: &str, near: u128) -> TestResult<Account> {
    Ok(parent
        .create_subaccount(name)
        .initial_balance(NearToken::from_near(near))
        .keys(SecretKey::from_random(KeyType::ED25519))
        .transact()
        .await?
        .into_result()?)
}

/// Creates `<name>.<root>` holding `near` NEAR and deploys the contract to it, uninitialized.
async fn deploy_uninitialized(root: &Account, name: &str, near: u128) -> TestResult<Contract> {
    let account = subaccount(root, name, near).await?;
    Ok(account.deploy(&contract_wasm()).await?.into_result()?)
}

/// Adds a function-call key (receiver = the vault, methods = `["request_spend"]`, `allowance`) to
/// `agent_full_access` and returns the agent signing with that key only. Its full-access key is
/// used once, here, and then dropped.
async fn function_call_key(
    worker: &Worker<Sandbox>,
    agent_full_access: &Account,
    vault: &Contract,
    allowance: NearToken,
) -> TestResult<Account> {
    let key = SecretKey::from_random(KeyType::ED25519);
    agent_full_access
        .batch(agent_full_access.id())
        .add_key(
            key.public_key(),
            AccessKey::function_call_access(vault.id(), &["request_spend"], Some(allowance)),
        )
        .transact()
        .await?
        .into_result()?;
    let agent = Account::from_secret_key(agent_full_access.id().clone(), key, worker);

    // The key the agent signs with really is the restricted one.
    let view = agent
        .view_access_key(&agent.secret_key().public_key())
        .await?;
    match view.permission {
        AccessKeyPermission::FunctionCall(permission) => {
            assert_eq!(permission.receiver_id, vault.id().as_str());
            assert_eq!(permission.method_names, ["request_spend"]);
            assert_eq!(
                permission.allowance,
                Some(allowance),
                "a finite gas allowance"
            );
        }
        AccessKeyPermission::FullAccess => panic!("the agent must not sign with a full-access key"),
    }
    Ok(agent)
}

/// Owner, vendor, drain, an initialized vault, and an agent whose policy allows 0.5 NEAR per
/// transaction, 1 NEAR and `ENTRY_CAP` entries per day, to the vendor only. The agent signs with
/// a function-call key holding a 1 NEAR allowance.
async fn setup() -> TestResult<Scene> {
    let worker = near_workspaces::sandbox().await?;
    let root = worker.root_account()?;
    let owner = subaccount(&root, "owner", 30).await?;
    let vendor = subaccount(&root, "vendor", 5).await?;
    let drain = subaccount(&root, "drain", 5).await?;
    let agent_full_access = subaccount(&root, "agent", 5).await?;

    let vault = deploy_uninitialized(&root, "vault", 20).await?;
    vault
        .call("new")
        .args_json(json!({ "owner": owner.id() }))
        .transact()
        .await?
        .into_result()?;
    set_policy(
        &owner,
        &vault,
        agent_full_access.id(),
        HALF_NEAR,
        ONE_NEAR,
        ENTRY_CAP,
        &[vendor.id()],
    )
    .await?
    .into_result()?;
    let agent =
        function_call_key(&worker, &agent_full_access, &vault, NearToken::from_near(1)).await?;

    Ok(Scene {
        worker,
        root,
        owner,
        vault,
        agent,
        vendor,
        drain,
    })
}

async fn set_policy(
    owner: &Account,
    vault: &Contract,
    agent: &AccountId,
    per_tx_max: u128,
    window_limit: u128,
    max_entries_per_window: u32,
    receivers: &[&AccountId],
) -> TestResult<ExecutionFinalResult> {
    Ok(owner
        .call(vault.id(), "set_policy")
        .args_json(json!({
            "agent": agent,
            "per_tx_max": U128(per_tx_max),
            "window_limit": U128(window_limit),
            "window_secs": 86_400,
            "max_entries_per_window": max_entries_per_window,
            "allowed_receivers": receivers,
        }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?)
}

/// `request_spend` signed by the agent's function-call key, with the bridge's gas.
async fn request_spend(
    scene: &Scene,
    receiver: &AccountId,
    yocto: u128,
    attempt_id: &str,
) -> TestResult<ExecutionFinalResult> {
    Ok(scene
        .agent
        .call(scene.vault.id(), "request_spend")
        .args_json(json!({
            "receiver": receiver,
            "amount": U128(yocto),
            "attempt_id": attempt_id,
            "memo": MEMO,
        }))
        .gas(SPEND_GAS)
        .transact()
        .await?)
}

async fn balance(account: &Account) -> TestResult<u128> {
    Ok(account.view_account().await?.balance.as_yoctonear())
}

async fn ledger_entry(scene: &Scene, index: u64) -> TestResult<LedgerEntry> {
    let entries: Vec<LedgerEntry> = scene
        .vault
        .view("get_ledger")
        .args_json(json!({ "from_index": index, "limit": 1 }))
        .await?
        .json()?;
    Ok(entries.into_iter().next().ok_or("no ledger entry")?)
}

async fn ledger_len(scene: &Scene) -> TestResult<u64> {
    Ok(scene.vault.view("ledger_len").await?.json()?)
}

async fn agent_policy(scene: &Scene) -> TestResult<Policy> {
    let policy: Option<Policy> = scene
        .vault
        .view("get_policy")
        .args_json(json!({ "agent": scene.agent.id() }))
        .await?
        .json()?;
    Ok(policy.ok_or("agent has no policy")?)
}

async fn vault_available(vault: &Contract) -> TestResult<u128> {
    let available: U128 = vault.view("vault_available").await?.json()?;
    Ok(available.0)
}

async fn storage_usage(worker: &Worker<Sandbox>, vault: &Contract) -> TestResult<u64> {
    Ok(worker.view_account(vault.id()).await?.storage_usage)
}

/// The verdict of a transaction the node refused to accept at all. Panics on any other failure.
fn protocol_rejection(err: near_workspaces::error::Error) -> InvalidTxError {
    assert_eq!(
        err.kind(),
        &ErrorKind::Rpc(RpcErrorCode::BroadcastTxFailure),
        "expected the node to refuse the transaction, got: {err}"
    );
    let cause = err
        .into_inner()
        .expect("a broadcast failure carries the RPC error");
    let rpc = cause
        .downcast::<JsonRpcError<RpcTransactionError>>()
        .expect("the cause is the broadcast_tx_commit RPC error");
    match *rpc {
        JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
            RpcTransactionError::InvalidTransaction { context },
        )) => context,
        other => panic!("expected an InvalidTransaction verdict, got: {other}"),
    }
}

/// The panic message of a transaction the node accepted but whose contract call panicked.
fn contract_panic(outcome: &ExecutionFinalResult) -> String {
    let failed = outcome
        .failures()
        .first()
        .copied()
        .cloned()
        .unwrap_or_else(|| panic!("expected the contract call to panic: {outcome:?}"));
    let err = failed
        .into_result()
        .expect_err("a failed outcome converts into an error");
    let cause = err
        .into_inner()
        .expect("an execution error carries its cause");
    match *cause
        .downcast::<TxExecutionError>()
        .expect("the cause is a TxExecutionError")
    {
        TxExecutionError::ActionError(ActionError {
            kind: ActionErrorKind::FunctionCallError(FunctionCallError::ExecutionError(message)),
            ..
        }) => message,
        other => panic!("expected a contract panic, got: {other}"),
    }
}

/// The NEP-297 events in a transaction's logs whose `event` is `name`.
fn events(outcome: &ExecutionFinalResult, name: &str) -> Vec<serde_json::Value> {
    outcome
        .logs()
        .iter()
        .filter_map(|log| log.strip_prefix("EVENT_JSON:"))
        .map(|body| serde_json::from_str::<serde_json::Value>(body).expect("event is JSON"))
        .filter(|event| event["standard"] == "agent_guard" && event["event"] == name)
        .collect()
}

#[tokio::test]
async fn scenario_1_approved_spend_pays_the_vendor_exactly() -> TestResult {
    let scene = setup().await?;
    let vendor_before = balance(&scene.vendor).await?;

    let outcome = request_spend(&scene, scene.vendor.id(), HALF_NEAR, &attempt(1)).await?;
    assert_eq!(events(&outcome, "spend_approved").len(), 1);
    assert_eq!(
        events(&outcome, "transfer_settled")[0]["data"][0]["transfer"],
        "succeeded"
    );
    let receipt: SpendReceipt = outcome.json()?;
    assert_eq!(
        receipt,
        SpendReceipt {
            ledger_index: 0,
            approved: true,
            reasons: vec![],
        }
    );

    let gained = balance(&scene.vendor).await? - vendor_before;
    assert_eq!(
        gained, HALF_NEAR,
        "the vendor receives exactly the approved amount"
    );
    let entry = ledger_entry(&scene, 0).await?;
    assert!(entry.approved);
    assert!(entry.reasons.is_empty());
    assert_eq!(entry.transfer, TransferStatus::Succeeded);
    assert_eq!(entry.attempt_id, attempt(1));
    assert_eq!(entry.memo.as_deref(), Some(MEMO));
    assert_eq!(agent_policy(&scene).await?.window_spent, U128(HALF_NEAR));
    println!(
        "[scenario 1] approved: vendor +{gained} yoctoNEAR; ledger[0] = {}",
        serde_json::to_string(&entry)?
    );
    Ok(())
}

#[tokio::test]
async fn scenario_2_injected_overlimit_spend_is_denied_on_chain() -> TestResult {
    let scene = setup().await?;
    let drain_before = balance(&scene.drain).await?;

    let outcome = request_spend(&scene, scene.drain.id(), 5 * ONE_NEAR, &attempt(2)).await?;
    assert!(
        outcome.is_success(),
        "a denial is a successful transaction: {outcome:?}"
    );
    assert_eq!(events(&outcome, "spend_denied").len(), 1);
    let receipt: SpendReceipt = outcome.json()?;
    let reasons = [
        DenyReason::ReceiverNotAllowed,
        DenyReason::OverPerTxMax,
        DenyReason::OverWindowLimit,
    ];
    assert!(!receipt.approved);
    assert_eq!(receipt.reasons, reasons);

    assert_eq!(
        balance(&scene.drain).await?,
        drain_before,
        "drain receives nothing"
    );
    let entry = ledger_entry(&scene, receipt.ledger_index).await?;
    assert!(!entry.approved);
    assert_eq!(entry.reasons, reasons);
    assert_eq!(entry.transfer, TransferStatus::NotAttempted);
    println!(
        "[scenario 2] denied on-chain, transaction succeeded: receipt = {}; ledger[{}] = {}",
        serde_json::to_string(&receipt)?,
        entry.index,
        serde_json::to_string(&entry)?
    );
    Ok(())
}

#[tokio::test]
async fn scenario_3_function_call_key_cannot_call_set_policy() -> TestResult {
    let scene = setup().await?;
    let raise = json!({
        "agent": scene.agent.id(),
        "per_tx_max": U128(100 * ONE_NEAR),
        "window_limit": U128(100 * ONE_NEAR),
        "window_secs": 86_400,
        "max_entries_per_window": ENTRY_CAP,
        "allowed_receivers": [scene.drain.id()],
    });

    let err = scene
        .agent
        .call(scene.vault.id(), "set_policy")
        .args_json(&raise)
        .transact()
        .await
        .expect_err("the protocol must refuse set_policy signed by the function-call key");
    let rejection = protocol_rejection(err);
    println!(
        "[scenario 3] set_policy via function-call key REJECTED by protocol: {rejection:?} ({rejection})"
    );
    assert!(
        matches!(
            &rejection,
            InvalidTxError::InvalidAccessKeyError(InvalidAccessKeyError::MethodNameMismatch { method_name })
                if method_name == "set_policy"
        ),
        "unexpected rejection: {rejection:?}"
    );

    // set_policy demands 1 yoctoNEAR, and a function-call key cannot attach any deposit.
    let err = scene
        .agent
        .call(scene.vault.id(), "set_policy")
        .args_json(&raise)
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await
        .expect_err("the protocol must refuse a deposit from the function-call key");
    let rejection = protocol_rejection(err);
    println!(
        "[scenario 3] set_policy + 1 yoctoNEAR via function-call key REJECTED by protocol: {rejection:?} ({rejection})"
    );
    assert!(
        matches!(
            rejection,
            InvalidTxError::InvalidAccessKeyError(InvalidAccessKeyError::DepositWithFunctionCall)
        ),
        "unexpected rejection: {rejection:?}"
    );

    assert_eq!(
        agent_policy(&scene).await?.per_tx_max,
        U128(HALF_NEAR),
        "policy unchanged"
    );
    Ok(())
}

#[tokio::test]
async fn scenario_4_function_call_key_cannot_transfer() -> TestResult {
    let scene = setup().await?;
    let drain_before = balance(&scene.drain).await?;

    // 0.1 NEAR plus gas fits the key's 1 NEAR allowance, so the key's permission is what refuses it.
    let err = scene
        .agent
        .transfer_near(scene.drain.id(), NearToken::from_millinear(100))
        .await
        .expect_err("the protocol must refuse a Transfer signed by the function-call key");
    let rejection = protocol_rejection(err);
    println!(
        "[scenario 4] Transfer of 0.1 NEAR via function-call key REJECTED by protocol: {rejection:?} ({rejection})"
    );
    assert!(
        matches!(
            rejection,
            InvalidTxError::InvalidAccessKeyError(InvalidAccessKeyError::RequiresFullAccess)
        ),
        "unexpected rejection: {rejection:?}"
    );

    // A transfer whose deposit plus gas exceeds the key's allowance is refused for that first,
    // before the permission check is reached.
    let err = scene
        .agent
        .transfer_near(scene.drain.id(), NearToken::from_near(1))
        .await
        .expect_err("the protocol must refuse a Transfer signed by the function-call key");
    let rejection = protocol_rejection(err);
    println!(
        "[scenario 4] Transfer of 1 NEAR via function-call key REJECTED by protocol: {rejection:?} ({rejection})"
    );
    assert!(
        matches!(
            rejection,
            InvalidTxError::InvalidAccessKeyError(InvalidAccessKeyError::NotEnoughAllowance { .. })
        ),
        "unexpected rejection: {rejection:?}"
    );

    assert_eq!(
        balance(&scene.drain).await?,
        drain_before,
        "drain receives nothing"
    );
    Ok(())
}

#[tokio::test]
async fn scenario_5_owner_set_policy_requires_exactly_one_yocto() -> TestResult {
    let scene = setup().await?;
    let raise = json!({
        "agent": scene.agent.id(),
        "per_tx_max": U128(ONE_NEAR),
        "window_limit": U128(2 * ONE_NEAR),
        "window_secs": 86_400,
        "max_entries_per_window": ENTRY_CAP,
        "allowed_receivers": [scene.vendor.id()],
    });

    let outcome = scene
        .owner
        .call(scene.vault.id(), "set_policy")
        .args_json(&raise)
        .transact()
        .await?;
    let message = contract_panic(&outcome);
    println!("[scenario 5] owner set_policy without 1 yoctoNEAR FAILED: {message}");
    assert_eq!(
        message,
        "Smart contract panicked: Requires attached deposit of exactly 1 yoctoNEAR"
    );
    assert_eq!(
        agent_policy(&scene).await?.per_tx_max,
        U128(HALF_NEAR),
        "policy unchanged"
    );

    scene
        .owner
        .call(scene.vault.id(), "set_policy")
        .args_json(&raise)
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    let policy = agent_policy(&scene).await?;
    assert_eq!(
        (policy.per_tx_max, policy.window_limit),
        (U128(ONE_NEAR), U128(2 * ONE_NEAR))
    );
    println!(
        "[scenario 5] owner set_policy with 1 yoctoNEAR succeeded: {}",
        serde_json::to_string(&policy)?
    );
    Ok(())
}

#[tokio::test]
async fn scenario_6_failed_transfer_is_marked_failed_and_refunded() -> TestResult {
    let scene = setup().await?;
    let ghost: AccountId = format!("ghost.{}", scene.root.id()).parse()?;
    assert!(
        scene.worker.view_account(&ghost).await.is_err(),
        "{ghost} must not exist"
    );
    set_policy(
        &scene.owner,
        &scene.vault,
        scene.agent.id(),
        HALF_NEAR,
        ONE_NEAR,
        ENTRY_CAP,
        &[scene.vendor.id(), &ghost],
    )
    .await?
    .into_result()?;

    let outcome = request_spend(&scene, &ghost, 3 * ONE_NEAR / 10, &attempt(6)).await?;
    let settled = events(&outcome, "transfer_settled");
    let receipt: SpendReceipt = outcome.json()?;
    assert!(
        receipt.approved,
        "the policy approves the spend: {receipt:?}"
    );

    let entry = ledger_entry(&scene, receipt.ledger_index).await?;
    assert_eq!(entry.transfer, TransferStatus::Failed);
    assert_eq!(
        agent_policy(&scene).await?.window_spent,
        U128(0),
        "window refunded"
    );
    assert_eq!(settled.len(), 1);
    assert_eq!(
        settled[0]["data"][0]["window_refund"],
        "300000000000000000000000"
    );
    println!(
        "[scenario 6] transfer to nonexistent {ghost} failed; callback settled it: ledger[{}] = {}; event = {}",
        entry.index,
        serde_json::to_string(&entry)?,
        settled[0]
    );
    Ok(())
}

#[tokio::test]
async fn scenario_7_duplicate_attempt_id_panics_and_records_nothing() -> TestResult {
    let scene = setup().await?;
    request_spend(&scene, scene.vendor.id(), ONE_NEAR / 10, &attempt(7))
        .await?
        .into_result()?;
    assert_eq!(ledger_len(&scene).await?, 1);

    let outcome = request_spend(&scene, scene.vendor.id(), ONE_NEAR / 10, &attempt(7)).await?;
    let message = contract_panic(&outcome);
    println!("[scenario 7] replayed attempt_id FAILED: {message}");
    assert_eq!(message, "Smart contract panicked: duplicate attempt_id");
    assert_eq!(ledger_len(&scene).await?, 1, "no second ledger entry");
    Ok(())
}

#[tokio::test]
async fn scenario_8_revoked_agent_is_refused_and_stores_nothing() -> TestResult {
    let scene = setup().await?;
    scene
        .owner
        .call(scene.vault.id(), "revoke")
        .args_json(json!({ "agent": scene.agent.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    let vendor_before = balance(&scene.vendor).await?;
    let storage_before = storage_usage(&scene.worker, &scene.vault).await?;

    let outcome = request_spend(&scene, scene.vendor.id(), ONE_NEAR / 10, &attempt(8)).await?;
    let message = contract_panic(&outcome);
    println!("[scenario 8] revoked agent's request_spend FAILED: {message}");
    assert_eq!(message, "Smart contract panicked: agent revoked");
    assert_eq!(ledger_len(&scene).await?, 0, "no ledger entry");
    assert_eq!(
        storage_usage(&scene.worker, &scene.vault).await?,
        storage_before,
        "the vault stores nothing for a revoked agent"
    );
    assert_eq!(
        balance(&scene.vendor).await?,
        vendor_before,
        "vendor receives nothing"
    );

    let decision: Decision = scene
        .vault
        .view("check_spend")
        .args_json(json!({
            "agent": scene.agent.id(),
            "receiver": scene.vendor.id(),
            "amount": U128(ONE_NEAR / 10),
        }))
        .await?
        .json()?;
    assert_eq!(
        decision,
        Decision {
            approved: false,
            reasons: vec![DenyReason::Revoked],
        }
    );
    println!(
        "[scenario 8] check_spend still reports: {}",
        serde_json::to_string(&decision)?
    );
    Ok(())
}

#[tokio::test]
async fn a_third_party_cannot_initialize_the_vault() -> TestResult {
    let worker = near_workspaces::sandbox().await?;
    let root = worker.root_account()?;
    let owner = subaccount(&root, "owner", 5).await?;
    let stranger = subaccount(&root, "stranger", 5).await?;
    let vault = deploy_uninitialized(&root, "vault", 20).await?;

    let outcome = stranger
        .call(vault.id(), "new")
        .args_json(json!({ "owner": stranger.id() }))
        .transact()
        .await?;
    let message = contract_panic(&outcome);
    println!("[init] stranger calling new FAILED: {message}");
    assert_eq!(message, "Smart contract panicked: Method new is private");

    vault
        .call("new")
        .args_json(json!({ "owner": owner.id() }))
        .transact()
        .await?
        .into_result()?;
    let recorded: AccountId = vault.view("get_owner").await?.json()?;
    assert_eq!(&recorded, owner.id());
    Ok(())
}

#[tokio::test]
async fn owner_withdraw_moves_funds_to_the_owner() -> TestResult {
    let scene = setup().await?;
    let amount = 2 * ONE_NEAR;
    let owner_before = balance(&scene.owner).await?;
    let available_before = vault_available(&scene.vault).await?;

    let outcome = scene
        .owner
        .call(scene.vault.id(), "withdraw")
        .args_json(json!({ "amount": U128(amount) }))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?;
    let withdrawn = events(&outcome, "owner_withdraw");
    outcome.into_result()?;
    assert_eq!(withdrawn.len(), 1);
    assert_eq!(
        withdrawn[0]["data"][0]["amount"],
        "2000000000000000000000000"
    );

    let gained = balance(&scene.owner).await? - owner_before;
    assert!(
        gained < amount,
        "the owner pays gas and the 1 yoctoNEAR deposit: gained {gained}"
    );
    let cost = amount - gained;
    assert!(
        cost < ONE_NEAR / 100,
        "the call costs the owner {cost} yoctoNEAR"
    );
    // Exactly `amount` leaves the vault; the attached 1 yoctoNEAR stays in it.
    let spent = available_before - vault_available(&scene.vault).await?;
    assert_eq!(spent, amount - 1, "vault_available drops by the amount");
    assert_eq!(
        ledger_len(&scene).await?,
        0,
        "a withdrawal is not a ledger entry"
    );
    println!(
        "[withdraw] owner +{gained} yoctoNEAR for a {amount} yoctoNEAR withdrawal (cost {cost}: gas + 1 yoctoNEAR); vault_available -{spent}"
    );
    Ok(())
}

/// Karl's storage-griefing probe, run against the fix. An agent's function-call key (0.5 NEAR
/// allowance) spams denied requests with the longest agent id, receiver and memo until the vault
/// refuses. The window entry cap bounds the storage the vault pays for, a revoked agent stores
/// nothing, and the owner can still withdraw everything spendable from a small vault.
#[tokio::test]
async fn denied_request_spam_is_capped_per_window_and_the_vault_stays_usable() -> TestResult {
    const CAP: u32 = 10;
    let worker = near_workspaces::sandbox().await?;
    let root = worker.root_account()?;
    let owner = subaccount(&root, "owner", 30).await?;
    let vendor = subaccount(&root, "vendor", 5).await?;
    // A 64-character agent id, the longest a ledger entry can carry.
    let rogue_name = "r".repeat(64 - root.id().as_str().len() - 1);
    let rogue_full_access = subaccount(&root, &rogue_name, 2).await?;
    assert_eq!(rogue_full_access.id().as_str().len(), 64);
    // A small vault, as in the probe: about 1.2 NEAR spendable beside its code's storage stake.
    let vault = deploy_uninitialized(&root, "vault", 3).await?;
    vault
        .call("new")
        .args_json(json!({ "owner": owner.id() }))
        .transact()
        .await?
        .into_result()?;
    set_policy(
        &owner,
        &vault,
        rogue_full_access.id(),
        ONE_NEAR / 10,
        ONE_NEAR,
        CAP,
        &[vendor.id()],
    )
    .await?
    .into_result()?;
    let rogue = function_call_key(
        &worker,
        &rogue_full_access,
        &vault,
        NearToken::from_millinear(500),
    )
    .await?;

    let storage_before = storage_usage(&worker, &vault).await?;
    let available_before = vault_available(&vault).await?;
    let (receiver, memo) = ("f".repeat(64), "x".repeat(256));
    let spam = |n: u64| {
        rogue
            .call(vault.id(), "request_spend")
            .args_json(json!({
                "receiver": receiver,
                "amount": U128(u128::MAX),
                "attempt_id": attempt(50_000 + n),
                "memo": memo,
            }))
            .gas(SPEND_GAS)
            .transact()
    };
    let mut recorded: u32 = 0;
    let mut refusal = None;
    for n in 0..=u64::from(CAP) {
        let outcome = spam(n).await?;
        if outcome.is_success() {
            let receipt: SpendReceipt = outcome.json()?;
            assert!(
                !receipt.approved,
                "every spam request is denied: {receipt:?}"
            );
            recorded += 1;
        } else {
            refusal = Some(contract_panic(&outcome));
            break;
        }
    }
    println!("[storage griefing] {recorded} denied entries recorded, then: {refusal:?}");
    let refusal = refusal.ok_or("the vault never refused the spam")?;
    assert_eq!(recorded, CAP);
    assert_eq!(refusal, "Smart contract panicked: window entry cap reached");

    let per_entry: u64 = vault.view("max_entry_storage_bytes").await?.json()?;
    let storage_added = storage_usage(&worker, &vault).await? - storage_before;
    let locked = available_before - vault_available(&vault).await?;
    let bound = u128::from(CAP) * u128::from(per_entry) * STORAGE_BYTE_COST;
    println!(
        "[storage griefing] vault storage +{storage_added} B = {} B/entry (max_entry_storage_bytes {per_entry}); vault_available -{locked} yoctoNEAR, bound {CAP} x {per_entry} B x 10^19 = {bound}",
        storage_added / u64::from(CAP)
    );
    assert_eq!(
        storage_added,
        u64::from(CAP) * per_entry,
        "each worst-case entry adds exactly max_entry_storage_bytes; the refused call adds nothing"
    );
    assert!(
        locked <= bound,
        "vault_available dropped by {locked}, over the bound {bound}"
    );

    owner
        .call(vault.id(), "revoke")
        .args_json(json!({ "agent": rogue.id() }))
        .deposit(NearToken::from_yoctonear(1))
        .transact()
        .await?
        .into_result()?;
    let storage_revoked = storage_usage(&worker, &vault).await?;
    let message = contract_panic(&spam(u64::from(CAP) + 1).await?);
    println!("[storage griefing] revoked agent's request_spend FAILED: {message}");
    assert_eq!(message, "Smart contract panicked: agent revoked");
    assert_eq!(
        storage_usage(&worker, &vault).await?,
        storage_revoked,
        "a revoked agent stores nothing"
    );

    let spendable = vault_available(&vault).await?;
    owner
        .call(vault.id(), "withdraw")
        .args_json(json!({ "amount": U128(spendable) }))
        .deposit(NearToken::from_yoctonear(1))
        .gas(Gas::from_tgas(30))
        .transact()
        .await?
        .into_result()?;
    println!("[storage griefing] owner withdrew all {spendable} yoctoNEAR still spendable");
    Ok(())
}
