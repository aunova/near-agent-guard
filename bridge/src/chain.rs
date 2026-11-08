//! The NEAR side: view calls through near-api, and transactions that near-api builds and signs
//! but that are posted with a direct JSON-RPC `send_tx`.
//!
//! Why not near-api's own send: nearcore skip-serialises `InvalidTransaction.context` (the
//! JSON-RPC `cause.info` is `{}`) and carries the detail only in the legacy `error.data` field,
//! which near-openapi-client 0.8.0's typed error drops. Through near-api a method-name mismatch
//! and a Transfer needing full access are indistinguishable; reading `error.data` here they are not.
//!
//! No error message from this module contains the RPC URL: only `Rpc::label` (scheme, host, port).

use std::collections::HashMap;
use std::error::Error as StdError;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use near_api::advanced::ExecuteSignedTransaction;
use near_api::errors::{
    ExecuteTransactionError, MetaSignError, QueryError, RetryError, SendRequestError, SignerError,
};
use near_api::types::transaction::SignedTransaction;
use near_api::types::transaction::actions::TransferAction;
use near_api::{
    AccountId, Contract, NearGas, NearToken, NetworkConfig, Reference, Signer, Transaction,
    types::Action,
};
use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use tokio::time::timeout;

use crate::config::Rpc;
use crate::screen::{PayIntent, parse_yocto};

/// Gas for `request_spend` (shared contract, gate step 4).
const REQUEST_SPEND_TGAS: u64 = 50;
/// Gas for the escalation attempt; the protocol refuses it before any is burnt.
const ESCALATE_TGAS: u64 = 30;
/// Limit the escalation attempt tries to set: 100 NEAR per tx and per window.
const ESCALATED_LIMIT_YOCTO: &str = "100000000000000000000000000";
/// Overall deadline for nonce fetch plus `send_tx` until FINAL.
const SEND_DEADLINE: Duration = Duration::from_secs(60);
/// Deadline for one view call (near-api retries inside it).
const VIEW_DEADLINE: Duration = Duration::from_secs(30);
/// Posts of the same signed transaction; resending is idempotent (same hash).
const SEND_ATTEMPTS: u32 = 4;
/// HTTP limits for the direct `send_tx` post.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// A FINAL outcome for one call with a transfer and a callback is a few kB; anything near this
/// is not a reply we can use.
const MAX_RPC_BODY_BYTES: usize = 2 * 1024 * 1024;
/// The contract caps `get_ledger` pages at 100.
const LEDGER_PAGE: u64 = 100;
/// `guard verify` reads the whole ledger; refuse rather than half-check a larger one.
const MAX_LEDGER_SCAN: u64 = 10_000;
/// Re-reads of a ledger entry whose transfer still shows `pending` (a lagging RPC replica).
const TRANSFER_SETTLE_READS: u32 = 5;
/// Longest chain-supplied text kept in a message.
const MAX_DETAIL_CHARS: usize = 300;

/// `get_ledger` entry (shared contract, section 1).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LedgerEntry {
    pub index: u64,
    pub agent: String,
    pub receiver: String,
    #[serde(deserialize_with = "yocto_string")]
    pub amount: u128,
    pub attempt_id: String,
    pub memo: Option<String>,
    pub approved: bool,
    pub reasons: Vec<String>,
    pub transfer: String,
    pub block_height: u64,
    pub timestamp_ms: u64,
}

/// `get_policy` value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Policy {
    #[serde(deserialize_with = "yocto_string")]
    pub per_tx_max: u128,
    #[serde(deserialize_with = "yocto_string")]
    pub window_limit: u128,
    pub window_secs: u64,
    /// Most ledger entries the agent may add per window.
    pub max_entries_per_window: u32,
    pub allowed_receivers: Vec<String>,
    pub revoked: bool,
    pub window_start_ms: u64,
    #[serde(deserialize_with = "yocto_string")]
    pub window_spent: u128,
    /// Ledger entries added in the current window.
    pub window_entries: u32,
}

/// NEAR's storage price: 10^19 yoctoNEAR per byte (1 NEAR per 100 kB).
const STORAGE_BYTE_COST: u128 = 10_000_000_000_000_000_000;

/// The most yoctoNEAR of the vault's balance one agent can lock as storage stake per window:
/// `max_entries_per_window` x `max_entry_storage_bytes` x 10^19. `None` if values from the RPC
/// would overflow `u128`.
pub fn window_storage_bound(max_entries_per_window: u32, max_entry_storage_bytes: u64) -> Option<u128> {
    u128::from(max_entries_per_window)
        .checked_mul(u128::from(max_entry_storage_bytes))?
        .checked_mul(STORAGE_BYTE_COST)
}

/// `request_spend` return value.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SpendReceipt {
    pub ledger_index: u64,
    pub approved: bool,
    pub reasons: Vec<String>,
}

fn yocto_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    let digits = String::deserialize(deserializer)?;
    parse_yocto(&digits).ok_or_else(|| D::Error::custom("expected a yoctoNEAR decimal string"))
}

/// An exact NEAR decimal for display: 10^24 yocto = 1 NEAR, trailing zeros dropped.
pub fn format_near(yocto: u128) -> String {
    const YOCTO_PER_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
    let (whole, fraction) = (yocto / YOCTO_PER_NEAR, yocto % YOCTO_PER_NEAR);
    if fraction == 0 {
        return whole.to_string();
    }
    let fraction = format!("{fraction:024}");
    format!("{whole}.{}", fraction.trim_end_matches('0'))
}

/// A transaction NEAR refused before execution, from the JSON-RPC `error.data`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// snake_case `InvalidAccessKeyError` variant (`method_name_mismatch`, `requires_full_access`,
    /// `not_enough_allowance`, ...) or other `InvalidTxError` variant (`invalid_nonce`, ...).
    pub kind: String,
    /// The variant's fields as compact JSON, possibly empty.
    pub detail: String,
}

/// What a posted transaction came to.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TxOutcome {
    /// FINAL; the call returned these bytes.
    Success(Vec<u8>),
    /// FINAL, but execution failed (for example a contract panic): the `Failure` JSON.
    Failed(Value),
    /// Refused by the protocol; never included in a block.
    Rejected(Rejection),
}

/// Result of `request_spend` as the gate needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendOutcome {
    Decided {
        tx_hash: String,
        receipt: SpendReceipt,
        /// The ledger entry's transfer status; `None` if it could not be read back.
        transfer: Option<String>,
    },
    Failed {
        tx_hash: Option<String>,
        /// A code when the vault itself refused the call (see `vault_refusal`), else empty.
        reasons: Vec<String>,
        message: String,
    },
}

/// The breakout attempts `guard attack` makes with the function-call key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackKind {
    /// Call `set_policy` on the vault, no deposit, to raise the agent's own limits.
    Escalate,
    /// The same call with the 1 yoctoNEAR `set_policy` requires attached.
    EscalateWithDeposit,
    /// Send 0.1 NEAR straight to the attacker. Kept under the key's 0.5 NEAR allowance: nearcore
    /// checks the allowance before the permission, and a larger amount would be refused with
    /// `not_enough_allowance` instead of showing the permission check.
    Transfer,
}

impl AttackKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Escalate => "escalate",
            Self::EscalateWithDeposit => "escalate-1yocto",
            Self::Transfer => "transfer",
        }
    }

    /// The refusal a correctly scoped function-call key should produce.
    pub fn expected_rejection(self) -> &'static str {
        match self {
            Self::Escalate => "method_name_mismatch",
            Self::EscalateWithDeposit => "deposit_with_function_call",
            Self::Transfer => "requires_full_access",
        }
    }

    fn deposit(self) -> NearToken {
        match self {
            Self::Escalate => NearToken::from_yoctonear(0),
            Self::EscalateWithDeposit => NearToken::from_yoctonear(1),
            Self::Transfer => NearToken::from_millinear(100),
        }
    }
}

/// What a breakout attempt came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttackOutcome {
    Rejected(Rejection),
    /// The protocol let it execute; the key is not scoped as it should be.
    Accepted { tx_hash: String, detail: String },
    Error(String),
}

/// `set_policy` arguments the escalation attempts send.
fn escalate_args(agent: &AccountId, attacker: &AccountId) -> Value {
    json!({
        "agent": agent,
        "per_tx_max": ESCALATED_LIMIT_YOCTO,
        "window_limit": ESCALATED_LIMIT_YOCTO,
        "window_secs": 86_400,
        "allowed_receivers": [attacker],
    })
}

/// Description of an attack, logged as its raw request.
pub fn attack_request(kind: AttackKind, agent: &AccountId, contract: &AccountId, attacker: &AccountId) -> Value {
    let deposit = kind.deposit().as_yoctonear().to_string();
    match kind {
        AttackKind::Escalate | AttackKind::EscalateWithDeposit => json!({
            "attack": kind.name(),
            "signer": agent,
            "receiver": contract,
            "method": "set_policy",
            "args": escalate_args(agent, attacker),
            "deposit": deposit,
            "gas_tgas": ESCALATE_TGAS,
        }),
        AttackKind::Transfer => json!({
            "attack": kind.name(),
            "signer": agent,
            "receiver": attacker,
            "action": "Transfer",
            "deposit": deposit,
        }),
    }
}

/// The message of a contract panic inside an execution `Failure`, if that is what failed.
fn contract_panic(failure: &Value) -> Option<&str> {
    failure
        .get("ActionError")?
        .get("kind")?
        .get("FunctionCallError")?
        .get("ExecutionError")?
        .as_str()?
        .strip_prefix("Smart contract panicked: ")
}

/// A reason code for each of the vault's own `request_spend` refusals (the contract's panic
/// strings; such a call leaves no state and no ledger entry).
fn vault_refusal(panic: &str) -> Option<&'static str> {
    match panic {
        "attempt_id must be exactly 64 lowercase hex characters" => Some("invalid_attempt_id"),
        "memo exceeds 256 bytes" => Some("memo_too_long"),
        "duplicate attempt_id" => Some("duplicate_attempt_id"),
        "agent revoked" => Some("revoked"),
        "window entry cap reached" => Some("window_entry_cap"),
        _ if panic.starts_with("unknown agent") => Some("unknown_agent"),
        _ => None,
    }
}

/// Talks to one contract on one RPC endpoint on behalf of one agent account.
pub struct Chain {
    network: NetworkConfig,
    rpc: Rpc,
    http: reqwest::Client,
    contract: AccountId,
    agent: AccountId,
    /// Set once the RPC's `status` reported chain_id `testnet`; nothing touches the chain before.
    testnet_confirmed: AtomicBool,
}

impl Chain {
    pub fn new(rpc: Rpc, contract: AccountId, agent: AccountId) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .build()
            .map_err(|_| "cannot initialise the HTTP client (TLS backend)".to_owned())?;
        Ok(Self {
            network: NetworkConfig::from_rpc_url("testnet", rpc.url.clone()),
            rpc,
            http,
            contract,
            agent,
            testnet_confirmed: AtomicBool::new(false),
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.rpc.label
    }

    pub fn contract(&self) -> &AccountId {
        &self.contract
    }

    pub fn agent(&self) -> &AccountId {
        &self.agent
    }

    /// `request_spend(receiver, amount, attempt_id, memo)` signed by the function-call key, 50 Tgas,
    /// waited on until FINAL so the transfer callback has settled; then the ledger entry is read
    /// back for the transfer status.
    pub async fn request_spend(&self, signer: &Arc<Signer>, intent: &PayIntent, attempt_id: &str) -> SpendOutcome {
        if let Err(message) = self.ensure_testnet().await {
            return SpendOutcome::Failed {
                tx_hash: None,
                reasons: Vec::new(),
                message,
            };
        }
        let args = json!({
            "receiver": intent.receiver,
            "amount": intent.amount_yocto.to_string(),
            "attempt_id": attempt_id,
            "memo": intent.memo,
        });
        let transaction = Contract(self.contract.clone())
            .call_function("request_spend", args)
            .transaction()
            .gas(NearGas::from_tgas(REQUEST_SPEND_TGAS))
            .with_signer(self.agent.clone(), Arc::clone(signer));
        let signed = match self.presign(transaction).await {
            Ok(signed) => signed,
            Err(message) => {
                return SpendOutcome::Failed {
                    tx_hash: None,
                    reasons: Vec::new(),
                    message,
                };
            }
        };
        let tx_hash = signed.get_hash().to_string();
        let outcome = match self.send_until_final(&signed).await {
            Ok(outcome) => outcome,
            Err(message) => {
                return SpendOutcome::Failed {
                    tx_hash: Some(tx_hash),
                    reasons: Vec::new(),
                    message,
                };
            }
        };
        match outcome {
            TxOutcome::Success(bytes) => match serde_json::from_slice::<SpendReceipt>(&bytes) {
                Ok(receipt) => {
                    let transfer = self.settled_transfer(receipt.ledger_index, attempt_id).await;
                    SpendOutcome::Decided {
                        tx_hash,
                        receipt,
                        transfer,
                    }
                }
                Err(_) => SpendOutcome::Failed {
                    tx_hash: Some(tx_hash),
                    reasons: Vec::new(),
                    message: "request_spend returned a value that is not a SpendReceipt".to_owned(),
                },
            },
            TxOutcome::Failed(failure) => {
                let (reasons, message) = match contract_panic(&failure) {
                    Some(panic) => match vault_refusal(panic) {
                        Some(code) => (vec![code.to_owned()], format!("the vault refused the call: {}", clip(panic))),
                        None => (Vec::new(), format!("request_spend panicked: {}", clip(panic))),
                    },
                    None => (Vec::new(), format!("request_spend failed on-chain: {}", compact(&failure))),
                };
                SpendOutcome::Failed {
                    tx_hash: Some(tx_hash),
                    reasons,
                    message,
                }
            }
            TxOutcome::Rejected(rejection) => SpendOutcome::Failed {
                tx_hash: None,
                reasons: Vec::new(),
                message: format!(
                    "NEAR refused the transaction before execution: {} {}",
                    rejection.kind, rejection.detail
                ),
            },
        }
    }

    /// Signs and posts one breakout attempt with the function-call key.
    pub async fn attack(&self, signer: &Arc<Signer>, kind: AttackKind, attacker: &AccountId) -> AttackOutcome {
        if let Err(message) = self.ensure_testnet().await {
            return AttackOutcome::Error(message);
        }
        let transaction = match kind {
            AttackKind::Escalate | AttackKind::EscalateWithDeposit => Contract(self.contract.clone())
                .call_function("set_policy", escalate_args(&self.agent, attacker))
                .transaction()
                .gas(NearGas::from_tgas(ESCALATE_TGAS))
                .deposit(kind.deposit())
                .with_signer(self.agent.clone(), Arc::clone(signer)),
            AttackKind::Transfer => Transaction::construct(self.agent.clone(), attacker.clone())
                .add_action(Action::Transfer(TransferAction {
                    deposit: kind.deposit(),
                }))
                .with_signer(Arc::clone(signer)),
        };
        let signed = match self.presign(transaction).await {
            Ok(signed) => signed,
            Err(message) => return AttackOutcome::Error(message),
        };
        let tx_hash = signed.get_hash().to_string();
        match self.send_until_final(&signed).await {
            Ok(TxOutcome::Rejected(rejection)) => AttackOutcome::Rejected(rejection),
            Ok(TxOutcome::Success(bytes)) => AttackOutcome::Accepted {
                tx_hash,
                detail: format!("executed, returned {}", clip(&String::from_utf8_lossy(&bytes))),
            },
            Ok(TxOutcome::Failed(failure)) => AttackOutcome::Accepted {
                tx_hash,
                detail: format!("executed and failed on-chain: {}", compact(&failure)),
            },
            Err(message) => AttackOutcome::Error(message),
        }
    }

    pub async fn ledger_len(&self) -> Result<u64, String> {
        self.view("ledger_len", json!({})).await
    }

    pub async fn get_ledger(&self, from_index: u64, limit: u64) -> Result<Vec<LedgerEntry>, String> {
        self.view("get_ledger", json!({ "from_index": from_index, "limit": limit })).await
    }

    pub async fn policy(&self) -> Result<Option<Policy>, String> {
        self.view("get_policy", json!({ "agent": self.agent })).await
    }

    /// Most storage, in bytes, one recorded ledger entry can add.
    pub async fn max_entry_storage_bytes(&self) -> Result<u64, String> {
        self.view("max_entry_storage_bytes", json!({})).await
    }

    pub async fn vault_available(&self) -> Result<u128, String> {
        let digits: String = self.view("vault_available", json!({})).await?;
        parse_yocto(&digits).ok_or_else(|| "vault_available is not a yoctoNEAR decimal string".to_owned())
    }

    /// Every ledger entry, in pages, refusing ledgers above `MAX_LEDGER_SCAN`.
    pub async fn full_ledger(&self) -> Result<Vec<LedgerEntry>, String> {
        let len = self.ledger_len().await?;
        if len > MAX_LEDGER_SCAN {
            return Err(format!(
                "the ledger has {len} entries; this verifier reads at most {MAX_LEDGER_SCAN}"
            ));
        }
        let mut entries = Vec::new();
        let mut from = 0;
        while from < len {
            let page = self.get_ledger(from, LEDGER_PAGE).await?;
            if page.is_empty() {
                return Err(format!("get_ledger({from}) came back empty although ledger_len is {len}"));
            }
            from += page.len() as u64;
            entries.extend(page);
        }
        Ok(entries)
    }

    /// The transfer status of entry `index`, re-read while it still shows `pending`. Checks that
    /// the entry really is this attempt's.
    async fn settled_transfer(&self, index: u64, attempt_id: &str) -> Option<String> {
        for read in 1..=TRANSFER_SETTLE_READS {
            let entry = match self.get_ledger(index, 1).await {
                Ok(page) => page.into_iter().next(),
                Err(message) => {
                    eprintln!("guard: reading ledger entry {index} back failed: {message}");
                    return None;
                }
            };
            let Some(entry) = entry else {
                eprintln!("guard: ledger entry {index} does not exist");
                return None;
            };
            if entry.attempt_id != attempt_id {
                eprintln!("guard: ledger entry {index} records attempt {}, not {attempt_id}", entry.attempt_id);
                return None;
            }
            if entry.transfer != "pending" || read == TRANSFER_SETTLE_READS {
                return Some(entry.transfer);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        None
    }

    /// Refuses to go on unless the RPC's own `status` reports chain_id `testnet`: `NEAR_NETWORK`
    /// alone cannot stop a `NEAR_RPC_URL` that points at mainnet. Checked once per process.
    async fn ensure_testnet(&self) -> Result<(), String> {
        if self.testnet_confirmed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let body = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": "guard", "method": "status", "params": []}))
            .map_err(|_| "cannot encode the status request".to_owned())?;
        let reply = match timeout(VIEW_DEADLINE, self.post(&body)).await {
            Err(_) => return Err(format!("status: no answer from {} within {} s", self.rpc.label, VIEW_DEADLINE.as_secs())),
            Ok(Err(Post::Retry(message) | Post::Fatal(message))) => {
                return Err(format!("cannot confirm the RPC is testnet: {message}"));
            }
            Ok(Ok(reply)) => reply,
        };
        match reply.pointer("/result/chain_id").and_then(Value::as_str) {
            Some("testnet") => {
                self.testnet_confirmed.store(true, Ordering::Relaxed);
                Ok(())
            }
            Some(other) => Err(format!(
                "{} reports chain_id {}; near-agent-guard runs on testnet only and refuses it",
                self.rpc.label,
                clip(other)
            )),
            None => Err(format!("{} answered status without a chain_id; refusing", self.rpc.label)),
        }
    }

    async fn view<T: DeserializeOwned + Send + Sync + 'static>(&self, method: &str, args: Value) -> Result<T, String> {
        self.ensure_testnet().await?;
        let request = Contract(self.contract.clone())
            .call_function(method, args)
            .read_only::<T>()
            .at(Reference::Final)
            .fetch_from(&self.network);
        match timeout(VIEW_DEADLINE, request).await {
            Err(_) => Err(format!(
                "{method}: no answer from {} within {} s",
                self.rpc.label,
                VIEW_DEADLINE.as_secs()
            )),
            Ok(Err(error)) => Err(format!("{method} via {}: {}", self.rpc.label, describe_query(&error))),
            Ok(Ok(data)) => Ok(data.data),
        }
    }

    /// Fetches the nonce and block hash and signs with near-api; nothing is broadcast.
    async fn presign(&self, transaction: ExecuteSignedTransaction) -> Result<SignedTransaction, String> {
        let presigned = timeout(VIEW_DEADLINE, transaction.presign_with(&self.network))
            .await
            .map_err(|_| format!("fetching the access-key nonce from {} timed out", self.rpc.label))?
            .map_err(|error| format!("signing via {} failed: {}", self.rpc.label, describe_execute(&error)))?;
        presigned
            .transaction
            .signed()
            .ok_or_else(|| "near-api returned an unsigned transaction".to_owned())
    }

    async fn send_until_final(&self, signed: &SignedTransaction) -> Result<TxOutcome, String> {
        match timeout(SEND_DEADLINE, self.send_tx(signed)).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "no FINAL outcome from {} within {} s; the transaction may still execute, look it up by hash",
                self.rpc.label,
                SEND_DEADLINE.as_secs()
            )),
        }
    }

    /// Posts `send_tx` with `wait_until: FINAL`, resending the same signed transaction on RPC
    /// timeouts and connection failures.
    async fn send_tx(&self, signed: &SignedTransaction) -> Result<TxOutcome, String> {
        let bytes = borsh::to_vec(signed).map_err(|_| "cannot serialise the signed transaction".to_owned())?;
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "guard",
            "method": "send_tx",
            "params": { "signed_tx_base64": BASE64.encode(bytes), "wait_until": "FINAL" },
        }))
        .map_err(|_| "cannot encode the send_tx request".to_owned())?;

        let mut last = String::new();
        for attempt in 1..=SEND_ATTEMPTS {
            let reply = match self.post(&body).await {
                Ok(reply) => reply,
                Err(Post::Retry(message)) => {
                    last = message;
                    tokio::time::sleep(Duration::from_millis(500 * u64::from(attempt))).await;
                    continue;
                }
                Err(Post::Fatal(message)) => return Err(message),
            };
            match classify_send_reply(&reply) {
                SendReply::Outcome(outcome) => return Ok(outcome),
                SendReply::Timeout => last = format!("{} reported TIMEOUT_ERROR", self.rpc.label),
                SendReply::Error(message) => return Err(format!("send_tx via {}: {message}", self.rpc.label)),
            }
        }
        Err(format!("send_tx gave no FINAL outcome after {SEND_ATTEMPTS} posts; last: {last}"))
    }

    async fn post(&self, body: &[u8]) -> Result<Value, Post> {
        let mut response = self
            .http
            .post(self.rpc.url.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_vec())
            .send()
            .await
            .map_err(|error| {
                let message = format!("POST to {}: {}", self.rpc.label, describe_reqwest(&error));
                if error.is_timeout() || error.is_connect() {
                    Post::Retry(message)
                } else {
                    Post::Fatal(message)
                }
            })?;
        let status = response.status();
        let mut bytes = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if bytes.len() + chunk.len() > MAX_RPC_BODY_BYTES {
                        return Err(Post::Fatal(format!(
                            "{} sent a reply over {MAX_RPC_BODY_BYTES} bytes",
                            self.rpc.label
                        )));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(error) => {
                    return Err(Post::Retry(format!(
                        "reading the reply from {}: {}",
                        self.rpc.label,
                        describe_reqwest(&error)
                    )));
                }
            }
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            Post::Fatal(format!("{} answered HTTP {status} with a non-JSON body", self.rpc.label))
        })
    }
}

enum Post {
    Retry(String),
    Fatal(String),
}

#[derive(Debug, PartialEq, Eq)]
enum SendReply {
    Outcome(TxOutcome),
    Timeout,
    Error(String),
}

/// Reads a JSON-RPC `send_tx` reply.
fn classify_send_reply(reply: &Value) -> SendReply {
    if let Some(error) = reply.get("error") {
        let cause = error
            .get("cause")
            .and_then(|cause| cause.get("name"))
            .or_else(|| error.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("UNKNOWN_ERROR");
        return match cause {
            "TIMEOUT_ERROR" => SendReply::Timeout,
            "INVALID_TRANSACTION" => SendReply::Outcome(TxOutcome::Rejected(classify_invalid_tx(error.get("data")))),
            other => SendReply::Error(format!("{other} {}", compact(error.get("data").unwrap_or(&Value::Null)))),
        };
    }
    let Some(status) = reply.get("result").and_then(|result| result.get("status")) else {
        return SendReply::Error("reply has neither an error nor a result status".to_owned());
    };
    if let Some(encoded) = status.get("SuccessValue").and_then(Value::as_str) {
        return match BASE64.decode(encoded) {
            Ok(bytes) => SendReply::Outcome(TxOutcome::Success(bytes)),
            Err(_) => SendReply::Error("SuccessValue is not base64".to_owned()),
        };
    }
    if let Some(failure) = status.get("Failure") {
        return SendReply::Outcome(TxOutcome::Failed(failure.clone()));
    }
    SendReply::Error(format!("transaction is not final yet: {}", compact(status)))
}

/// Classifies `error.data` of an `INVALID_TRANSACTION` reply:
/// `{"TxExecutionError":{"InvalidTxError":{"InvalidAccessKeyError":{"MethodNameMismatch":{...}}}}}`.
fn classify_invalid_tx(data: Option<&Value>) -> Rejection {
    let Some(invalid) = data
        .and_then(|data| data.get("TxExecutionError"))
        .and_then(|error| error.get("InvalidTxError"))
    else {
        return Rejection {
            kind: "invalid_transaction".to_owned(),
            detail: data.map(compact).unwrap_or_default(),
        };
    };
    let (variant, body) = enum_variant(invalid);
    let (variant, body) = if variant == "InvalidAccessKeyError" {
        enum_variant(body)
    } else {
        (variant, body)
    };
    Rejection {
        kind: snake_case(variant),
        detail: if body.is_null() { String::new() } else { compact(body) },
    }
}

/// An externally tagged serde enum value: a bare string (unit variant) or `{"Variant": body}`.
fn enum_variant(value: &Value) -> (&str, &Value) {
    static NULL: Value = Value::Null;
    match value {
        Value::String(name) => (name, &NULL),
        Value::Object(map) if map.len() == 1 => map
            .iter()
            .next()
            .map_or(("unknown", value), |(name, body)| (name.as_str(), body)),
        _ => ("unknown", value),
    }
}

fn snake_case(camel: &str) -> String {
    let mut out = String::with_capacity(camel.len() + 4);
    for (index, c) in camel.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn compact(value: &Value) -> String {
    clip(&value.to_string())
}

/// At most `MAX_DETAIL_CHARS` chars, cut on a char boundary.
fn clip(text: &str) -> String {
    match text.char_indices().nth(MAX_DETAIL_CHARS) {
        Some((end, _)) => format!("{}…", text.get(..end).unwrap_or_default()),
        None => text.to_owned(),
    }
}

/// A `reqwest::Error` without its URL: classify it, then walk its sources (which do not carry
/// the URL; the top-level `Display` does).
fn describe_reqwest(error: &reqwest::Error) -> String {
    let kind = if error.is_timeout() {
        "timed out".to_owned()
    } else if error.is_connect() {
        "connection failed".to_owned()
    } else if error.is_decode() {
        "reply could not be decoded".to_owned()
    } else if error.is_body() {
        "reading the reply body failed".to_owned()
    } else if let Some(status) = error.status() {
        format!("HTTP {status}")
    } else {
        "request failed".to_owned()
    };
    let mut detail = kind;
    let mut source = error.source();
    while let Some(cause) = source {
        detail.push_str(": ");
        detail.push_str(&cause.to_string());
        source = cause.source();
    }
    clip(&detail)
}

/// A transport error from near-api's client, by its causes only (its own `Display` and `Debug`
/// can embed the request URL).
fn describe_transport(error: &(dyn StdError + 'static)) -> String {
    let mut source: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(cause) = source {
        if let Some(reqwest_error) = cause.downcast_ref::<reqwest::Error>() {
            return describe_reqwest(reqwest_error);
        }
        if cause.downcast_ref::<serde_json::Error>().is_some() {
            return "the RPC reply did not have the expected shape".to_owned();
        }
        source = cause.source();
    }
    "the RPC answered with an unexpected HTTP response".to_owned()
}

fn describe_send<E: std::fmt::Debug + Send + Sync>(error: &SendRequestError<E>) -> String {
    match error {
        SendRequestError::RequestCreationError(_) => "could not build the request".to_owned(),
        SendRequestError::TransportError(transport) => describe_transport(transport),
        // These carry RPC-supplied data only, so their Debug form is safe to show (clipped).
        SendRequestError::WasmExecutionError(failure) => clip(&format!("contract execution failed: {failure:?}")),
        SendRequestError::InternalError(internal) => clip(&format!("RPC internal error: {internal:?}")),
        SendRequestError::RequestValidationError(kind) => clip(&format!("RPC rejected the request: {kind:?}")),
        SendRequestError::ServerError(server) => clip(&format!("{server:?}")),
    }
}

fn describe_retry<E: std::fmt::Debug + Send + Sync>(error: &RetryError<SendRequestError<E>>) -> String {
    match error {
        RetryError::NoRpcEndpoints => "no RPC endpoint configured".to_owned(),
        RetryError::InvalidApiKey(_) => "the RPC API key is not a valid header value".to_owned(),
        RetryError::RetriesExhausted(inner) => format!("{} (retries exhausted)", describe_send(inner)),
        RetryError::Critical(inner) => describe_send(inner),
    }
}

fn describe_query<E: std::fmt::Debug + Send + Sync>(error: &QueryError<E>) -> String {
    match error {
        QueryError::QueryCreationError(_) => "could not build the query".to_owned(),
        QueryError::UnexpectedResponse { expected, got } => {
            format!("unexpected response kind (expected {expected}, got {got})")
        }
        QueryError::DeserializeError(_) => "the view returned JSON of an unexpected shape".to_owned(),
        QueryError::QueryError(retry) => describe_retry(retry),
        QueryError::InternalErrorNoResponse => "no response".to_owned(),
        QueryError::ArgumentValidationError(_) => "invalid view arguments".to_owned(),
        QueryError::ConversionError(_) => "the view result could not be converted".to_owned(),
    }
}

fn describe_signer(error: &SignerError) -> String {
    match error {
        SignerError::PublicKeyError(_) => "the signer has no public key".to_owned(),
        SignerError::SecretKeyIsNotAvailable => "the secret key is not available".to_owned(),
        SignerError::FetchNonceError(query) => format!("fetching the access-key nonce: {}", describe_query(query)),
        SignerError::IO(io) => format!("I/O error: {}", io.kind()),
    }
}

fn describe_execute(error: &ExecuteTransactionError) -> String {
    match error {
        ExecuteTransactionError::ArgumentValidationError(_) => "invalid call arguments".to_owned(),
        ExecuteTransactionError::PreQueryError(query) => describe_query(query),
        ExecuteTransactionError::ValidationError(_) => "transaction validation failed".to_owned(),
        ExecuteTransactionError::MetaSignError(MetaSignError::SignerError(signer))
        | ExecuteTransactionError::SignerError(signer) => describe_signer(signer),
        ExecuteTransactionError::MetaSignError(MetaSignError::DelegateActionIsNotSupported) => {
            "delegate actions are not supported".to_owned()
        }
        ExecuteTransactionError::TransactionError(retry) => describe_retry(retry),
        ExecuteTransactionError::DataConversionError(_) => "could not convert the RPC response".to_owned(),
    }
}

/// Ledger entries by index, for the verifier.
pub fn index_ledger(entries: &[LedgerEntry]) -> HashMap<u64, &LedgerEntry> {
    entries.iter().map(|entry| (entry.index, entry)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc_error(cause: &str, data: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": "guard",
            "error": { "name": "HANDLER_ERROR", "cause": { "name": cause, "info": {} }, "code": -32000, "message": "Server error", "data": data }
        })
    }

    #[test]
    fn method_name_mismatch_is_classified_from_error_data() {
        let reply = rpc_error(
            "INVALID_TRANSACTION",
            json!({"TxExecutionError": {"InvalidTxError": {"InvalidAccessKeyError": {"MethodNameMismatch": {"method_name": "set_policy"}}}}}),
        );
        assert_eq!(
            classify_send_reply(&reply),
            SendReply::Outcome(TxOutcome::Rejected(Rejection {
                kind: "method_name_mismatch".to_owned(),
                detail: r#"{"method_name":"set_policy"}"#.to_owned(),
            }))
        );
    }

    #[test]
    fn requires_full_access_is_classified_from_a_unit_variant() {
        let reply = rpc_error(
            "INVALID_TRANSACTION",
            json!({"TxExecutionError": {"InvalidTxError": {"InvalidAccessKeyError": "RequiresFullAccess"}}}),
        );
        assert_eq!(
            classify_send_reply(&reply),
            SendReply::Outcome(TxOutcome::Rejected(Rejection {
                kind: "requires_full_access".to_owned(),
                detail: String::new(),
            }))
        );
    }

    #[test]
    fn other_invalid_tx_errors_keep_their_variant() {
        let allowance = classify_invalid_tx(Some(&json!({"TxExecutionError": {"InvalidTxError": {"InvalidAccessKeyError": {"NotEnoughAllowance": {"account_id": "agent.testnet", "allowance": "1", "cost": "2", "public_key": "ed25519:x"}}}}})));
        assert_eq!(allowance.kind, "not_enough_allowance");
        let nonce = classify_invalid_tx(Some(&json!({"TxExecutionError": {"InvalidTxError": {"InvalidNonce": {"ak_nonce": 5, "tx_nonce": 4}}}})));
        assert_eq!(nonce.kind, "invalid_nonce");
        assert_eq!(nonce.detail, r#"{"ak_nonce":5,"tx_nonce":4}"#);
        // A node without the legacy data field still yields an honest, generic kind.
        assert_eq!(classify_invalid_tx(None).kind, "invalid_transaction");
    }

    #[test]
    fn timeouts_retry_and_unknown_errors_stop() {
        assert_eq!(classify_send_reply(&rpc_error("TIMEOUT_ERROR", json!("Timeout"))), SendReply::Timeout);
        assert!(matches!(
            classify_send_reply(&rpc_error("INTERNAL_ERROR", json!("boom"))),
            SendReply::Error(message) if message.starts_with("INTERNAL_ERROR")
        ));
    }

    #[test]
    fn final_results_are_decoded() {
        let receipt = br#"{"ledger_index":1,"approved":false,"reasons":["receiver_not_allowed"]}"#;
        let reply = json!({"result": {"final_execution_status": "FINAL", "status": {"SuccessValue": BASE64.encode(receipt)}}});
        assert_eq!(classify_send_reply(&reply), SendReply::Outcome(TxOutcome::Success(receipt.to_vec())));

        let reply = json!({"result": {"status": {"Failure": {"ActionError": {"index": 0, "kind": {"FunctionCallError": {"ExecutionError": "Smart contract panicked: duplicate attempt_id"}}}}}}});
        let SendReply::Outcome(TxOutcome::Failed(failure)) = classify_send_reply(&reply) else {
            panic!("expected a failure");
        };
        assert_eq!(contract_panic(&failure), Some("duplicate attempt_id"));

        let pending = json!({"result": {"status": "Started"}});
        assert!(matches!(classify_send_reply(&pending), SendReply::Error(_)));
    }

    #[test]
    fn spend_receipt_and_ledger_entry_parse_the_contract_shapes() {
        let receipt: SpendReceipt = serde_json::from_str(
            r#"{"ledger_index":1,"approved":false,"reasons":["receiver_not_allowed","over_per_tx_max","over_window_limit"]}"#,
        )
        .unwrap();
        assert_eq!(receipt.reasons.len(), 3);
        let entry: LedgerEntry = serde_json::from_str(
            r#"{"index":0,"agent":"agent.aunova-guard.testnet","receiver":"vendor.aunova-guard.testnet","amount":"500000000000000000000000",
                "attempt_id":"ab","memo":"INV-2026-11-001","approved":true,"reasons":[],"transfer":"succeeded",
                "block_height":123456,"timestamp_ms":1762600000000}"#,
        )
        .unwrap();
        assert_eq!(entry.amount, 500_000_000_000_000_000_000_000);
        let policy: Policy = serde_json::from_str(
            r#"{"per_tx_max":"500000000000000000000000","window_limit":"1000000000000000000000000","window_secs":86400,
                "max_entries_per_window":200,"allowed_receivers":["vendor.aunova-guard.testnet"],"revoked":false,
                "window_start_ms":1762600000000,"window_spent":"0","window_entries":3}"#,
        )
        .unwrap();
        assert_eq!(policy.window_limit, 1_000_000_000_000_000_000_000_000);
        assert_eq!((policy.window_entries, policy.max_entries_per_window), (3, 200));
        assert!(serde_json::from_str::<SpendReceipt>(r#"{"ledger_index":-1,"approved":true,"reasons":[]}"#).is_err());
    }

    #[test]
    fn the_window_storage_bound_is_cap_times_bytes_times_the_byte_cost() {
        // The contract's measured 669 bytes per entry.
        assert_eq!(window_storage_bound(200, 669).map(format_near).as_deref(), Some("1.338"));
        assert_eq!(window_storage_bound(1_000, 669).map(format_near).as_deref(), Some("6.69"));
        assert_eq!(window_storage_bound(1, 1), Some(10_000_000_000_000_000_000));
        // A lying RPC cannot make the bound wrap.
        assert_eq!(window_storage_bound(u32::MAX, u64::MAX), None);
    }

    #[test]
    fn near_amounts_format_exactly() {
        assert_eq!(format_near(500_000_000_000_000_000_000_000), "0.5");
        assert_eq!(format_near(5_000_000_000_000_000_000_000_000), "5");
        assert_eq!(format_near(1), "0.000000000000000000000001");
        assert_eq!(format_near(u128::MAX), "340282366920938.463463374607431768211455");
        assert_eq!(format_near(0), "0");
    }

    #[test]
    fn snake_case_and_clip() {
        assert_eq!(snake_case("MethodNameMismatch"), "method_name_mismatch");
        assert_eq!(snake_case("Expired"), "expired");
        let long = "é".repeat(400);
        let clipped = clip(&long);
        assert_eq!(clipped.chars().count(), MAX_DETAIL_CHARS + 1);
    }

    #[test]
    fn the_vaults_own_panics_map_to_reason_codes() {
        let failure = |message: &str| {
            json!({"ActionError": {"index": 0, "kind": {"FunctionCallError": {"ExecutionError": format!("Smart contract panicked: {message}")}}}})
        };
        for (message, code) in [
            ("unknown agent agent.aunova-guard.testnet", Some("unknown_agent")),
            ("attempt_id must be exactly 64 lowercase hex characters", Some("invalid_attempt_id")),
            ("memo exceeds 256 bytes", Some("memo_too_long")),
            ("duplicate attempt_id", Some("duplicate_attempt_id")),
            ("agent revoked", Some("revoked")),
            ("window entry cap reached", Some("window_entry_cap")),
            ("something else", None),
        ] {
            let failure = failure(message);
            assert_eq!(contract_panic(&failure), Some(message));
            assert_eq!(contract_panic(&failure).and_then(vault_refusal), code, "{message}");
        }
        let out_of_gas = json!({"ActionError": {"index": 0, "kind": {"FunctionCallError": {"ExecutionError": "Exceeded the prepaid gas."}}}});
        assert_eq!(contract_panic(&out_of_gas), None);
    }

    #[test]
    fn attack_requests_describe_what_is_signed() {
        let agent: AccountId = "agent.aunova-guard.testnet".parse().unwrap();
        let vault: AccountId = "vault.aunova-guard.testnet".parse().unwrap();
        let drain: AccountId = "drain.aunova-guard.testnet".parse().unwrap();
        let escalate = attack_request(AttackKind::Escalate, &agent, &vault, &drain);
        assert_eq!(escalate["method"], "set_policy");
        assert_eq!(escalate["deposit"], "0");
        assert_eq!(escalate["args"]["allowed_receivers"][0], "drain.aunova-guard.testnet");
        let with_deposit = attack_request(AttackKind::EscalateWithDeposit, &agent, &vault, &drain);
        assert_eq!(with_deposit["deposit"], "1");
        let transfer = attack_request(AttackKind::Transfer, &agent, &vault, &drain);
        // 0.1 NEAR: under the key's 0.5 NEAR allowance, so the permission check is what answers.
        assert_eq!(transfer["deposit"], "100000000000000000000000");
        assert_eq!(transfer["receiver"], "drain.aunova-guard.testnet");
    }
}
