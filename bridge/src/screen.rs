//! Runs `spend-screen.wasm` on one raw agent request, in a child process inside WasmBox.
//!
//! The key-holding process never parses agent output. It verifies the wasm's sha256 before every
//! run, starts `current_exe sandbox-exec <wasm>` with an empty environment (so the child holds
//! neither the agent key nor the audit key), writes the request to the child's stdin, and reads
//! back one verdict line under a size cap and a wall-clock deadline.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use near_api::AccountId;
use serde::Deserialize;
use serde_json::Value;
use wasmbox_runtime::{RunConfig, run_tool};
use wasmbox_shared::Capability;
use wasmbox_verify::VerifyError;

/// The hidden subcommand the child runs.
pub const SANDBOX_SUBCOMMAND: &str = "sandbox-exec";
/// Wall-clock limit for one screen run, wasm compilation included.
const SCREEN_TIMEOUT: Duration = Duration::from_secs(5);
/// Fuel (roughly one unit per wasm instruction) for one run; the deadline backs it up.
const SCREEN_FUEL: u64 = 500_000_000;
/// A verdict is one short line; more than this is a broken screen.
const MAX_VERDICT_BYTES: usize = 8 * 1024;
/// Kept for the operator's log only, never sent back to the agent.
const MAX_STDERR_BYTES: usize = 4 * 1024;
/// Must match spend-screen's memo limit; re-checked here so a broken screen fails closed.
const MAX_MEMO_BYTES: usize = 256;

/// A screened payment, re-validated on this side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayIntent {
    pub receiver: AccountId,
    pub amount_yocto: u128,
    pub memo: Option<String>,
}

/// What one screen run decided. `verdict` is the screen's line as JSON, for the audit log.
#[derive(Debug)]
pub enum ScreenOutcome {
    Allowed { intent: PayIntent, verdict: Value },
    Rejected { reasons: Vec<String>, verdict: Value },
    /// No usable verdict: hash mismatch, crash, timeout or malformed output. Fails closed.
    Failed(String),
}

impl ScreenOutcome {
    /// The verdict line as JSON, or `None` when the screen produced no usable verdict.
    pub fn verdict(&self) -> Option<&Value> {
        match self {
            Self::Allowed { verdict, .. } | Self::Rejected { verdict, .. } => Some(verdict),
            Self::Failed(_) => None,
        }
    }
}

/// The pinned screen and the executable that hosts its sandbox.
pub struct Screen {
    exe: PathBuf,
    wasm: PathBuf,
    sha256: String,
}

impl Screen {
    /// `sha256` is 64 lowercase hex chars (see `config::parse_sha256_pin`).
    pub fn new(exe: PathBuf, wasm: PathBuf, sha256: String) -> Self {
        Self { exe, wasm, sha256 }
    }

    /// The pinned hash, as recorded in every attempt event.
    pub fn wasm_sha256(&self) -> &str {
        &self.sha256
    }

    /// Verifies the pin, then fails fast at startup instead of on the first request.
    pub fn check_pin(&self) -> Result<(), String> {
        wasmbox_verify::verify_file(&self.wasm, &format!("sha256:{}", self.sha256)).map_err(|error| {
            match error {
                VerifyError::HashMismatch { actual, .. } => format!(
                    "screen wasm {} has {actual}, but GUARD_SCREEN_SHA256 pins sha256:{}; refusing to run it",
                    self.wasm.display(),
                    self.sha256
                ),
                VerifyError::InvalidFormat(_) => "GUARD_SCREEN_SHA256 is not a valid sha256 pin".to_owned(),
                VerifyError::Io(error) => {
                    format!("cannot read screen wasm {}: {}", self.wasm.display(), error.kind())
                }
            }
        })
    }

    /// Screens one raw request. The pin is re-verified before every run.
    pub fn run(&self, raw: &[u8]) -> ScreenOutcome {
        if let Err(message) = self.check_pin() {
            return ScreenOutcome::Failed(message);
        }
        match self.run_child(raw) {
            Ok(stdout) => parse_verdict(&stdout),
            Err(message) => ScreenOutcome::Failed(message),
        }
    }

    fn run_child(&self, raw: &[u8]) -> Result<Vec<u8>, String> {
        let mut child = spawn_sandbox(&self.exe, &self.wasm)
            .map_err(|error| format!("cannot start the screen sandbox: {}", error.kind()))?;
        let (Some(mut stdin), Some(stdout), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            kill_and_reap(&mut child);
            return Err("screen sandbox started without its pipes".to_owned());
        };

        let request = raw.to_vec();
        let writer = thread::spawn(move || {
            // A screen that stops reading early (oversized request) closes the pipe, so a
            // failed write here is expected; the verdict line decides the outcome.
            let _ = stdin.write_all(&request);
        });
        let stdout_reader = thread::spawn(move || read_capped(stdout, MAX_VERDICT_BYTES));
        let stderr_reader = thread::spawn(move || read_capped(stderr, MAX_STDERR_BYTES));

        // On timeout the reader threads are left to finish on their own when the pipes close:
        // joining them could block past the deadline.
        let status = wait_with_deadline(&mut child, SCREEN_TIMEOUT)?;
        let _ = writer.join();
        let stdout = stdout_reader
            .join()
            .map_err(|_| "screen stdout reader panicked".to_owned())?
            .map_err(|error| format!("reading the screen verdict failed: {}", error.kind()))?;
        let stderr = stderr_reader.join().ok().and_then(Result::ok).unwrap_or_default();

        if !status.success() {
            report_stderr(&stderr);
            return Err(match status.code() {
                Some(code) => format!("screen sandbox exited with status {code}"),
                None => "screen sandbox was killed by a signal".to_owned(),
            });
        }
        if stdout.len() > MAX_VERDICT_BYTES {
            return Err(format!("screen verdict exceeded {MAX_VERDICT_BYTES} bytes"));
        }
        Ok(stdout)
    }
}

/// Starts `exe sandbox-exec <wasm>` with piped stdio and NO environment: the child parses
/// untrusted agent output, so it must not inherit `AGENT_PRIVATE_KEY` or `GUARD_AUDIT_NSEC`.
pub fn spawn_sandbox(exe: &Path, wasm: &Path) -> io::Result<Child> {
    Command::new(exe)
        .arg(SANDBOX_SUBCOMMAND)
        .arg(wasm)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
}

/// Reads at most `cap + 1` bytes, so overflow is detected rather than silently truncated.
fn read_capped(reader: impl Read, cap: usize) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.take(cap as u64 + 1).read_to_end(&mut buf)?;
    Ok(buf)
}

fn wait_with_deadline(child: &mut Child, timeout: Duration) -> Result<ExitStatus, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() >= deadline => {
                kill_and_reap(child);
                return Err(format!("screen did not answer within {} s", timeout.as_secs()));
            }
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(error) => {
                kill_and_reap(child);
                return Err(format!("waiting for the screen failed: {}", error.kind()));
            }
        }
    }
}

fn kill_and_reap(child: &mut Child) {
    // Both fail only if the child already exited, which is the state we want.
    let _ = child.kill();
    let _ = child.wait();
}

fn report_stderr(stderr: &[u8]) {
    if !stderr.is_empty() {
        let text = String::from_utf8_lossy(stderr);
        eprintln!("guard: screen stderr: {}", text.trim_end());
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerdictWire {
    ok: bool,
    intent: Option<IntentWire>,
    reasons: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentWire {
    kind: String,
    receiver: String,
    amount_yocto: String,
    memo: Option<String>,
}

/// Parses the screen's stdout: exactly one newline-terminated JSON line, strictly shaped.
fn parse_verdict(stdout: &[u8]) -> ScreenOutcome {
    let Some(line) = stdout.strip_suffix(b"\n") else {
        return ScreenOutcome::Failed("screen output is not one newline-terminated line".to_owned());
    };
    if line.contains(&b'\n') {
        return ScreenOutcome::Failed("screen printed more than one line".to_owned());
    }
    let Ok(verdict) = serde_json::from_slice::<Value>(line) else {
        return ScreenOutcome::Failed("screen verdict is not JSON".to_owned());
    };
    let Ok(wire) = serde_json::from_value::<VerdictWire>(verdict.clone()) else {
        return ScreenOutcome::Failed("screen verdict has an unexpected shape".to_owned());
    };
    match wire {
        VerdictWire {
            ok: true,
            intent: Some(intent),
            reasons: None,
        } => match validate_intent(intent) {
            Ok(intent) => ScreenOutcome::Allowed { intent, verdict },
            Err(message) => ScreenOutcome::Failed(message.to_owned()),
        },
        VerdictWire {
            ok: false,
            intent: None,
            reasons: Some(reasons),
        } if !reasons.is_empty() => ScreenOutcome::Rejected { reasons, verdict },
        _ => ScreenOutcome::Failed("screen verdict is inconsistent".to_owned()),
    }
}

fn validate_intent(intent: IntentWire) -> Result<PayIntent, &'static str> {
    if intent.kind != "pay" {
        return Err("screen allowed an intent that is not a payment");
    }
    let receiver = intent
        .receiver
        .parse::<AccountId>()
        .map_err(|_| "screen allowed an invalid receiver")?;
    let amount_yocto = parse_yocto(&intent.amount_yocto)
        .filter(|amount| *amount > 0)
        .ok_or("screen allowed an invalid amount")?;
    if intent.memo.as_ref().is_some_and(|memo| memo.len() > MAX_MEMO_BYTES) {
        return Err("screen allowed an over-long memo");
    }
    Ok(PayIntent {
        receiver,
        amount_yocto,
        memo: intent.memo,
    })
}

/// Decimal digits only. `u128::from_str` alone would also accept a leading `+`.
pub fn parse_yocto(digits: &str) -> Option<u128> {
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Body of the hidden `sandbox-exec` subcommand: run the wasm with stdin/stdout only (WasmBox
/// also wires stderr with stdout), under a fuel limit. No filesystem, env, or network.
pub fn sandbox_exec(wasm: &Path) -> ExitCode {
    let config = RunConfig {
        wasm_path: wasm.to_path_buf(),
        capabilities: vec![Capability::Stdin, Capability::Stdout],
        fuel_limit: Some(SCREEN_FUEL),
        args: Vec::new(),
    };
    match run_tool(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sandbox-exec: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: &[u8] = br#"{"ok":true,"intent":{"kind":"pay","receiver":"vendor.aunova-guard.testnet","amount_yocto":"500000000000000000000000","memo":"INV-2026-11-001"}}
"#;

    #[test]
    fn allow_verdict_is_parsed_and_revalidated() {
        let ScreenOutcome::Allowed { intent, verdict } = parse_verdict(ALLOW) else {
            panic!("expected an allow");
        };
        assert_eq!(intent.receiver.as_str(), "vendor.aunova-guard.testnet");
        assert_eq!(intent.amount_yocto, 500_000_000_000_000_000_000_000);
        assert_eq!(intent.memo.as_deref(), Some("INV-2026-11-001"));
        assert_eq!(verdict["intent"]["amount_yocto"], "500000000000000000000000");
    }

    #[test]
    fn reject_verdict_keeps_reasons() {
        let outcome = parse_verdict(b"{\"ok\":false,\"reasons\":[\"tool_not_allowed:call\"]}\n");
        let ScreenOutcome::Rejected { reasons, .. } = outcome else {
            panic!("expected a rejection, got {outcome:?}");
        };
        assert_eq!(reasons, ["tool_not_allowed:call"]);
    }

    #[test]
    fn malformed_or_inconsistent_verdicts_fail_closed() {
        for stdout in [
            &b""[..],
            b"{\"ok\":false,\"reasons\":[\"x\"]}",
            b"{\"ok\":false,\"reasons\":[\"x\"]}\n{\"ok\":true}\n",
            b"not json\n",
            b"{\"ok\":false,\"reasons\":[]}\n",
            b"{\"ok\":true,\"reasons\":[\"x\"]}\n",
            b"{\"ok\":false,\"reasons\":[\"x\"],\"extra\":1}\n",
            b"{\"ok\":true,\"intent\":{\"kind\":\"call\",\"receiver\":\"a.testnet\",\"amount_yocto\":\"1\",\"memo\":null}}\n",
            b"{\"ok\":true,\"intent\":{\"kind\":\"pay\",\"receiver\":\"A..b\",\"amount_yocto\":\"1\",\"memo\":null}}\n",
            b"{\"ok\":true,\"intent\":{\"kind\":\"pay\",\"receiver\":\"a.testnet\",\"amount_yocto\":\"0\",\"memo\":null}}\n",
            b"{\"ok\":true,\"intent\":{\"kind\":\"pay\",\"receiver\":\"a.testnet\",\"amount_yocto\":\"+5\",\"memo\":null}}\n",
        ] {
            let outcome = parse_verdict(stdout);
            assert!(
                matches!(outcome, ScreenOutcome::Failed(_)),
                "{:?} gave {outcome:?}",
                String::from_utf8_lossy(stdout)
            );
        }
    }

    #[test]
    fn over_long_memo_in_an_allow_fails_closed() {
        let verdict = serde_json::json!({
            "ok": true,
            "intent": { "kind": "pay", "receiver": "a.testnet", "amount_yocto": "1", "memo": "m".repeat(257) }
        });
        let mut line = serde_json::to_vec(&verdict).unwrap();
        line.push(b'\n');
        assert!(matches!(parse_verdict(&line), ScreenOutcome::Failed(_)));
    }

    #[test]
    fn yocto_parsing_is_digits_only() {
        assert_eq!(parse_yocto("500000000000000000000000"), Some(500_000_000_000_000_000_000_000));
        assert_eq!(parse_yocto(&u128::MAX.to_string()), Some(u128::MAX));
        assert_eq!(parse_yocto("340282366920938463463374607431768211456"), None);
        for bad in ["", "+1", "-1", "1.0", " 1", "0x1"] {
            assert_eq!(parse_yocto(bad), None, "{bad:?}");
        }
    }
}
