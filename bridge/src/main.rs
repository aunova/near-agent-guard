//! `guard` command line. Configuration comes from the environment (see `config`); no secret is
//! ever taken from argv or printed, except the fresh key `guard keygen` exists to print.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use guard_bridge::audit::{self, AttemptContent, AuditLog, Origin, ResultContent, Status};
use guard_bridge::chain::{AttackKind, AttackOutcome, Chain, format_near, window_storage_bound};
use guard_bridge::config;
use guard_bridge::gate::Gate;
use guard_bridge::screen::{self, Screen};
use guard_bridge::serve;
use guard_bridge::verify::{self, Mismatch, NamedLog};
use near_api::{AccountId, Signer};
use nostr::{Keys, ToBech32};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "guard",
    version,
    about = "Bridge between a sandboxed AI agent and the NEAR vault: screen, sign the audit log, then spend"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a fresh GUARD_AUDIT_NSEC=nsec1... line and its npub.
    Keygen,
    /// Serve the agent's wallet socket: one JSON request line per connection, one response line.
    Serve {
        /// Socket path; created with mode 0600, a stale socket is replaced.
        #[arg(long)]
        socket: PathBuf,
    },
    /// Feed each non-empty line of a JSONL file through the same gate and print the responses.
    Replay {
        /// One raw agent request per line.
        file: PathBuf,
    },
    /// Verify the audit log; unless --offline, also cross-check it against the on-chain ledger.
    Verify {
        /// Log to verify (default: GUARD_AUDIT_LOG, else ./audit.jsonl). Repeat to verify several
        /// runs on the same vault together: one signer, attempt ids unique across files.
        #[arg(long)]
        log: Vec<PathBuf>,
        /// Check ids, signatures and the prev chains only; no network.
        #[arg(long, conflicts_with = "complete")]
        offline: bool,
        /// Also require every ledger entry for the agent from the anchor to the end of the ledger
        /// to have a logged result. Anchor: the first logged ledger index, or the first entry for
        /// the agent stamped at most 120 s (clock-skew allowance) before the earliest log event,
        /// whichever is smaller. Catches logs whose last attempts were cut off.
        #[arg(long)]
        complete: bool,
    },
    /// Print vault ledger entries.
    Ledger {
        #[arg(long, default_value_t = 0)]
        from: u64,
        /// At most 100 (the contract's cap).
        #[arg(long, default_value_t = 20)]
        limit: u64,
    },
    /// Print the agent's policy and the vault's available balance.
    Policy,
    /// Sign a breakout attempt with the agent's function-call key; expect NEAR to refuse it.
    Attack {
        #[command(subcommand)]
        kind: AttackCommand,
    },
    /// Internal: run the screen wasm inside WasmBox on this process's stdin/stdout.
    #[command(name = screen::SANDBOX_SUBCOMMAND, hide = true)]
    SandboxExec { wasm: PathBuf },
}

#[derive(Subcommand)]
enum AttackCommand {
    /// Call set_policy on the vault to raise the agent's own limits.
    Escalate {
        /// Receiver the escalated policy would allow (default: northwind.<owner> for
        /// GUARD_CONTRACT_ID=vault.<owner>).
        #[arg(long)]
        to: Option<String>,
    },
    /// Transfer 0.1 NEAR from the agent account straight to the attacker.
    Transfer {
        /// Receiver of the transfer (default: northwind.<owner> for GUARD_CONTRACT_ID=vault.<owner>).
        #[arg(long)]
        to: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::SandboxExec { wasm } => return screen::sandbox_exec(&wasm),
        Command::Keygen => Ok(keygen()),
        Command::Serve { socket } => gate_from_env().and_then(|gate| serve::serve(&socket, &gate)).map(|()| ExitCode::SUCCESS),
        Command::Replay { file } => gate_from_env().and_then(|gate| serve::replay(&file, &gate)).map(|()| ExitCode::SUCCESS),
        Command::Verify { log, offline, complete } => verify(log, offline, complete),
        Command::Ledger { from, limit } => ledger(from, limit),
        Command::Policy => policy(),
        Command::Attack { kind } => match kind {
            AttackCommand::Escalate { to } => attack(&[AttackKind::Escalate, AttackKind::EscalateWithDeposit], to),
            AttackCommand::Transfer { to } => attack(&[AttackKind::Transfer], to),
        },
    };
    result.unwrap_or_else(|error| {
        eprintln!("guard: {error:#}");
        ExitCode::FAILURE
    })
}

fn keygen() -> ExitCode {
    let keys = Keys::generate();
    let Ok(nsec) = keys.secret_key().to_bech32();
    let nsec = Zeroizing::new(nsec);
    println!("GUARD_AUDIT_NSEC={}", nsec.as_str());
    println!("# npub: {}", audit::npub(&keys.public_key()));
    ExitCode::SUCCESS
}

fn runtime() -> Result<Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")
}

fn chain_from_env() -> Result<Chain> {
    // The network check comes first, so NEAR_NETWORK=mainnet is refused before anything else.
    let rpc = config::rpc_from_env()?;
    let contract = config::account_from_env("GUARD_CONTRACT_ID")?;
    let agent = config::account_from_env("AGENT_ACCOUNT_ID")?;
    Chain::new(rpc, contract, agent).map_err(|message| anyhow!(message))
}

fn signer_from_env() -> Result<Option<Arc<Signer>>> {
    config::agent_key_from_env()?
        .map(|key| Signer::from_secret_key(key).map_err(|_| anyhow!("AGENT_PRIVATE_KEY has no usable public key")))
        .transpose()
}

fn gate_from_env() -> Result<Gate> {
    let chain = chain_from_env()?;
    let (wasm, pin) = config::screen_pin_from_env()?;
    let exe = std::env::current_exe().context("cannot locate the guard executable for sandbox-exec")?;
    let screen = Screen::new(exe, wasm, pin);
    screen.check_pin().map_err(|message| anyhow!(message))?;
    let log_path = config::audit_log_from_env();
    let log = AuditLog::open(
        &log_path,
        config::audit_keys_from_env()?,
        chain.contract().as_str(),
        chain.agent().as_str(),
    )?;
    let signer = signer_from_env()?;
    eprintln!(
        "guard: screen sha256:{}, audit log {} signed by {}, RPC {}",
        screen.wasm_sha256(),
        log_path.display(),
        log.signer_npub(),
        chain.endpoint()
    );
    if signer.is_none() {
        eprintln!(
            "guard: AGENT_PRIVATE_KEY is not set: screened-in payments are logged and answered with status error; nothing is sent"
        );
    }
    Ok(Gate::new(screen, log, chain, signer, runtime()?))
}

fn verify(logs: Vec<PathBuf>, offline: bool, complete: bool) -> Result<ExitCode> {
    let paths = if logs.is_empty() {
        vec![config::audit_log_from_env()]
    } else {
        logs
    };
    let several = paths.len() > 1;
    let mut verified = Vec::new();
    for path in &paths {
        match audit::verify_log(path) {
            Ok(log) => verified.push(NamedLog {
                name: path.display().to_string(),
                log,
            }),
            Err(bad) => {
                match (bad.line, several) {
                    (0, _) => eprintln!("FAIL {}: {}", path.display(), bad.reason),
                    (line, false) => eprintln!("FAIL line {line}: {}", bad.reason),
                    (line, true) => eprintln!("FAIL {} line {line}: {}", path.display(), bad.reason),
                }
                return Ok(ExitCode::FAILURE);
            }
        }
    }
    for named in &verified {
        if several {
            println!("== {}", named.name);
        }
        for row in verify::attempt_rows(&named.log) {
            println!("{row}");
        }
        println!(
            "log      {} events, ids and BIP-340 signatures valid, prev chain intact, contract {}, agent {}",
            named.log.lines.len(),
            named.log.contract,
            named.log.agent
        );
    }
    if let Err(message) = verify::check_union(&verified) {
        eprintln!("FAIL {message}");
        return Ok(ExitCode::FAILURE);
    }
    let first = &verified[0].log;
    println!("signer   {}", audit::npub(&first.signer));
    if offline {
        println!("OK (offline: the on-chain ledger was not consulted)");
        return Ok(ExitCode::SUCCESS);
    }

    let chain = chain_from_env()?;
    let agent = chain.agent().clone();
    if chain.contract().as_str() != first.contract || agent.as_str() != first.agent {
        eprintln!(
            "FAIL the logs are for contract {} / agent {}, but GUARD_CONTRACT_ID / AGENT_ACCOUNT_ID are {} / {agent}",
            first.contract,
            first.agent,
            chain.contract()
        );
        return Ok(ExitCode::FAILURE);
    }
    let ledger = runtime()?
        .block_on(chain.full_ledger())
        .map_err(|message| anyhow!(message))?;
    println!("chain    {} ledger entries read from {}", ledger.len(), chain.endpoint());
    match verify::cross_check(&verified, agent.as_str(), &ledger, complete) {
        Ok(check) => {
            for line in verify::summary_lines(&check, agent.as_str()) {
                println!("{line}");
            }
            println!("OK");
            Ok(ExitCode::SUCCESS)
        }
        Err(Mismatch::Line { file, line, reason }) if several => {
            eprintln!("FAIL {file} line {line}: {reason}");
            Ok(ExitCode::FAILURE)
        }
        Err(Mismatch::Line { line, reason, .. }) => {
            eprintln!("FAIL line {line}: {reason}");
            Ok(ExitCode::FAILURE)
        }
        Err(Mismatch::LedgerIndex { index, reason }) => {
            eprintln!("FAIL ledger index {index}: {reason}");
            Ok(ExitCode::FAILURE)
        }
    }
}

fn ledger(from: u64, limit: u64) -> Result<ExitCode> {
    let chain = chain_from_env()?;
    let runtime = runtime()?;
    let total = runtime.block_on(chain.ledger_len()).map_err(|message| anyhow!(message))?;
    let entries = runtime
        .block_on(chain.get_ledger(from, limit))
        .map_err(|message| anyhow!(message))?;
    println!("ledger_len {total}");
    println!(
        "{:<6} {:<9} {:<30} {:>12} {:<14} {:<14} reasons",
        "index", "decision", "receiver", "NEAR", "transfer", "attempt"
    );
    for entry in entries {
        println!(
            "{:<6} {:<9} {:<30} {:>12} {:<14} {:<14} {}",
            entry.index,
            if entry.approved { "approved" } else { "denied" },
            entry.receiver,
            format_near(entry.amount),
            entry.transfer,
            entry.attempt_id.get(..12).unwrap_or(&entry.attempt_id),
            entry.reasons.join(",")
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn policy() -> Result<ExitCode> {
    let chain = chain_from_env()?;
    let agent = chain.agent();
    let runtime = runtime()?;
    let policy = runtime.block_on(chain.policy()).map_err(|message| anyhow!(message))?;
    let available = runtime
        .block_on(chain.vault_available())
        .map_err(|message| anyhow!(message))?;
    match policy {
        None => println!("agent {agent}: no policy (unknown agent)"),
        Some(policy) => {
            let entry_bytes = runtime
                .block_on(chain.max_entry_storage_bytes())
                .map_err(|message| anyhow!(message))?;
            let bound = window_storage_bound(policy.max_entries_per_window, entry_bytes)
                .map_or_else(|| "beyond u128 (the RPC's values overflow)".to_owned(), |yocto| format!("{} NEAR", format_near(yocto)));
            println!("agent              {agent}");
            println!("per_tx_max         {} NEAR", format_near(policy.per_tx_max));
            println!(
                "window_limit       {} NEAR per {} s",
                format_near(policy.window_limit),
                policy.window_secs
            );
            println!("window_spent       {} NEAR", format_near(policy.window_spent));
            println!(
                "window_entries     {} of {} used",
                policy.window_entries, policy.max_entries_per_window
            );
            println!(
                "storage_bound      {bound} per window ({} entries x {entry_bytes} B x 10^19 yoctoNEAR/B)",
                policy.max_entries_per_window
            );
            println!("window_start_ms    {}", policy.window_start_ms);
            println!("allowed_receivers  {}", policy.allowed_receivers.join(", "));
            println!("revoked            {}", policy.revoked);
        }
    }
    println!("vault_available    {} NEAR", format_near(available));
    Ok(ExitCode::SUCCESS)
}

/// Runs each attack in turn, logging an attempt and a result for every one. Exit 0 only if
/// every attack was refused with the kind a correctly scoped key produces; the kind printed is
/// always whatever NEAR actually answered.
fn attack(kinds: &[AttackKind], to: Option<String>) -> Result<ExitCode> {
    let chain = chain_from_env()?;
    let (contract, agent) = (chain.contract(), chain.agent());
    // The demo's attacker account sits beside the vault: vault.<owner> -> northwind.<owner>.
    let to = match to {
        Some(to) => to,
        None => contract
            .as_str()
            .strip_prefix("vault.")
            .map(|owner| format!("northwind.{owner}"))
            .with_context(|| format!("cannot derive the attacker from {contract} (not vault.<owner>); pass --to"))?,
    };
    let attacker: AccountId = to.parse().with_context(|| format!("{to} is not a valid NEAR account id"))?;
    let signer = signer_from_env()?.context("AGENT_PRIVATE_KEY is required: the attack signs with it")?;
    let log_path = config::audit_log_from_env();
    let log = AuditLog::open(&log_path, config::audit_keys_from_env()?, contract.as_str(), agent.as_str())?;
    let runtime = runtime()?;
    let mut all_as_expected = true;

    for &kind in kinds {
        let request = guard_bridge::chain::attack_request(kind, agent, contract, &attacker);
        let raw = serde_json::to_vec(&request)?;
        let (raw_request_sha256, raw_request) = audit::describe_raw_request(&raw);
        let attempt = AttemptContent {
            origin: Origin::Attack,
            raw_request_sha256,
            raw_request,
            screen: None,
        };
        let attempt_id = log.append_attempt(&attempt)?;
        println!("attack {}: {agent} signs {request} with its function-call key", kind.name());

        let result = match runtime.block_on(chain.attack(&signer, kind, &attacker)) {
            AttackOutcome::Rejected(rejection) => {
                println!("  protocol_rejected: {} {}", rejection.kind, rejection.detail);
                if rejection.kind != kind.expected_rejection() {
                    all_as_expected = false;
                    eprintln!(
                        "guard: refused, but with {} rather than the expected {}; check how the key is scoped",
                        rejection.kind,
                        kind.expected_rejection()
                    );
                }
                ResultContent {
                    status: Status::ProtocolRejected,
                    ledger_index: None,
                    tx_hash: None,
                    transfer: None,
                    reasons: vec![rejection.kind],
                    message: (!rejection.detail.is_empty()).then_some(rejection.detail),
                }
            }
            AttackOutcome::Accepted { tx_hash, detail } => {
                all_as_expected = false;
                eprintln!("guard: PROTOCOL ACCEPTED the attack ({detail}); tx {tx_hash}. The function-call key is not scoped as it must be.");
                ResultContent {
                    status: Status::ProtocolAccepted,
                    ledger_index: None,
                    tx_hash: Some(tx_hash),
                    transfer: None,
                    reasons: Vec::new(),
                    message: Some(detail),
                }
            }
            AttackOutcome::Error(message) => {
                all_as_expected = false;
                eprintln!("guard: the attack could not be run: {message}");
                ResultContent::error(None, message)
            }
        };
        log.append_result(&attempt_id, &result)?;
        println!("  logged attempt {} and its result to {}", attempt_id.to_hex(), log_path.display());
    }
    Ok(if all_as_expected { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}
