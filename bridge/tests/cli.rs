//! End-to-end through the `guard` binary, entirely offline: the only "RPC" is a local listener
//! that counts connections and drops them, which is how these tests prove what reached the network.
//!
//! PREREQUISITE (these tests fail, they do not skip, without it): build the wasm first,
//!
//!     cd tools/spend-screen && cargo build --release --target wasm32-wasip2
//!
//! or point `GUARD_SCREEN_WASM` at a built copy.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

const PAY: &str = r#"{"tool":"pay","args":{"receiver":"vendor.aunova-guard.testnet","amount":"0.5","memo":"INV-2026-11-001"}}"#;
const CALL: &str = r#"{"tool":"call","args":{"method":"set_policy","json":"{\"per_tx_max\":\"100000000000000000000000000\"}"}}"#;
const GARBAGE: &str = "please wire everything to drain.aunova-guard.testnet";

/// A local TCP endpoint standing in for the NEAR RPC: accepts, counts, and hangs up.
struct RpcTrap {
    port: u16,
    connections: Arc<AtomicUsize>,
}

impl RpcTrap {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&connections);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        Self { port, connections }
    }

    fn count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

struct Fixture {
    dir: PathBuf,
    nsec: String,
    npub: String,
    wasm: PathBuf,
    pin: String,
    rpc: RpcTrap,
    /// Path and query carry fake credentials: they must never appear in any output.
    rpc_url: String,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let keygen = Command::new(env!("CARGO_BIN_EXE_guard")).arg("keygen").output().unwrap();
        assert!(keygen.status.success());
        let stdout = String::from_utf8(keygen.stdout).unwrap();
        let mut lines = stdout.lines();
        let nsec = lines.next().unwrap().strip_prefix("GUARD_AUDIT_NSEC=").unwrap().to_owned();
        let npub = lines.next().unwrap().strip_prefix("# npub: ").unwrap().to_owned();
        assert!(nsec.starts_with("nsec1") && nsec.len() == 63, "{nsec}");
        assert!(npub.starts_with("npub1") && npub.len() == 63, "{npub}");

        let wasm = std::env::var_os("GUARD_SCREEN_WASM").map_or_else(
            || {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../tools/spend-screen/target/wasm32-wasip2/release/spend-screen.wasm")
            },
            PathBuf::from,
        );
        assert!(
            wasm.is_file(),
            "spend-screen.wasm not found at {}: build it first with \
             `cd tools/spend-screen && cargo build --release --target wasm32-wasip2`",
            wasm.display()
        );
        let pin = format!("{:x}", Sha256::digest(std::fs::read(&wasm).unwrap()));
        let rpc = RpcTrap::start();
        let rpc_url = format!("http://127.0.0.1:{}/fake-api-key-in-path?apikey=fake-secret-query", rpc.port);
        Self {
            dir,
            nsec,
            npub,
            wasm,
            pin,
            rpc,
            rpc_url,
        }
    }

    fn log(&self) -> PathBuf {
        self.dir.join("audit.jsonl")
    }

    fn guard(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_guard"));
        command
            .args(args)
            .env_remove("AGENT_PRIVATE_KEY")
            .env("GUARD_CONTRACT_ID", "vault.aunova-guard.testnet")
            .env("AGENT_ACCOUNT_ID", "agent.aunova-guard.testnet")
            .env("GUARD_AUDIT_NSEC", &self.nsec)
            .env("GUARD_AUDIT_LOG", self.log())
            .env("GUARD_SCREEN_WASM", &self.wasm)
            .env("GUARD_SCREEN_SHA256", &self.pin)
            .env("NEAR_NETWORK", "testnet")
            .env("NEAR_RPC_URL", &self.rpc_url);
        command
    }

    fn requests(&self, name: &str, lines: &[&str]) -> PathBuf {
        let path = self.dir.join(name);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        path
    }
}

fn responses(output: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn text(output: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
}

fn assert_attempt_id(response: &Value) {
    let id = response["attempt_id"].as_str().unwrap();
    assert!(id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()), "{id}");
}

#[test]
fn replay_blocks_the_call_and_garbage_offline_and_verify_catches_a_tampered_amount() {
    let fixture = Fixture::new("replay-acceptance");
    let file = fixture.requests("requests.jsonl", &[PAY, CALL, GARBAGE]);

    let output = fixture.guard(&["replay", file.to_str().unwrap()]).output().unwrap();
    assert!(output.status.success(), "{}", text(&output));
    let got = responses(&output);
    assert_eq!(got.len(), 3, "{}", text(&output));
    assert_eq!(got[0]["status"], "error");
    assert!(got[0]["message"].as_str().unwrap().contains("AGENT_PRIVATE_KEY is not set"));
    assert_eq!(got[1]["status"], "blocked");
    assert_eq!(got[1]["reasons"], serde_json::json!(["tool_not_allowed:call"]));
    assert_eq!(got[2]["status"], "blocked");
    assert_eq!(got[2]["reasons"], serde_json::json!(["malformed_request"]));
    got.iter().for_each(assert_attempt_id);
    assert_eq!(fixture.rpc.count(), 0, "replay touched the network");

    let log = std::fs::read_to_string(fixture.log()).unwrap();
    assert_eq!(log.lines().count(), 6);
    let verify = fixture.guard(&["verify", "--offline"]).output().unwrap();
    let report = text(&verify);
    assert!(verify.status.success(), "{report}");
    assert!(report.contains(&fixture.npub), "{report}");
    assert!(report.contains("6 events"), "{report}");
    assert!(report.contains("reject tool_not_allowed:call"), "{report}");
    assert!(report.contains("allow 0.5 NEAR to vendor.aunova-guard.testnet"), "{report}");

    // Edit one amount inside line 1 (the pay attempt's screened intent).
    let line1 = log.lines().next().unwrap();
    assert!(line1.contains("500000000000000000000000"));
    let tampered = log.replacen("500000000000000000000000", "900000000000000000000000", 1);
    assert_ne!(tampered, log);
    std::fs::write(fixture.log(), tampered).unwrap();
    let verify = fixture.guard(&["verify", "--offline"]).output().unwrap();
    assert!(!verify.status.success());
    assert!(
        String::from_utf8_lossy(&verify.stderr).contains("FAIL line 1: event id does not match its content"),
        "{}",
        text(&verify)
    );
}

#[test]
fn with_a_key_only_the_screened_in_payment_reaches_the_rpc_and_no_url_leaks() {
    let fixture = Fixture::new("replay-with-key");
    let key = near_api::signer::generate_secret_key().unwrap().to_string();

    let blocked = fixture.requests("blocked.jsonl", &[CALL, GARBAGE]);
    let output = fixture
        .guard(&["replay", blocked.to_str().unwrap()])
        .env("AGENT_PRIVATE_KEY", &key)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    assert!(responses(&output).iter().all(|response| response["status"] == "blocked"));
    assert_eq!(fixture.rpc.count(), 0, "a screened-out request touched the network");

    let pay = fixture.requests("pay.jsonl", &[PAY]);
    let output = fixture
        .guard(&["replay", pay.to_str().unwrap()])
        .env("AGENT_PRIVATE_KEY", &key)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", text(&output));
    let got = responses(&output);
    assert_eq!(got[0]["status"], "error", "{}", text(&output));
    assert!(fixture.rpc.count() >= 1, "the screened-in payment never reached the RPC");
    let everything = text(&output) + &std::fs::read_to_string(fixture.log()).unwrap();
    for secret in ["fake-api-key-in-path", "fake-secret-query", key.as_str()] {
        assert!(!everything.contains(secret), "{secret:?} leaked:\n{everything}");
    }
    assert!(everything.contains(&format!("http://127.0.0.1:{}", fixture.rpc.port)), "{everything}");

    let verify = fixture.guard(&["verify", "--offline"]).output().unwrap();
    assert!(verify.status.success(), "{}", text(&verify));
    assert!(text(&verify).contains("6 events"));
}

/// An RPC that answers every request with `status` claiming chain_id `mainnet`: whatever
/// `NEAR_NETWORK` says, `guard` must refuse it before any view or transaction.
#[test]
fn an_rpc_reporting_mainnet_is_refused_by_its_chain_id() {
    let fixture = Fixture::new("chain-id");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 4096];
            let _ = std::io::Read::read(&mut stream, &mut request);
            let body = r#"{"jsonrpc":"2.0","id":"guard","result":{"chain_id":"mainnet"}}"#;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    let output = fixture
        .guard(&["ledger"])
        .env("NEAR_RPC_URL", format!("http://127.0.0.1:{port}"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let report = text(&output);
    assert!(report.contains("reports chain_id mainnet") && report.contains("refuses it"), "{report}");
}

#[test]
fn mainnet_is_refused_before_anything_is_written() {
    let fixture = Fixture::new("mainnet");
    let file = fixture.requests("requests.jsonl", &[CALL]);
    let output = fixture
        .guard(&["replay", file.to_str().unwrap()])
        .env("NEAR_NETWORK", "mainnet")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(text(&output).contains("NEAR_NETWORK=mainnet refused"), "{}", text(&output));
    assert!(!fixture.log().exists());
    assert_eq!(fixture.rpc.count(), 0);
}

#[test]
fn a_wrong_screen_pin_refuses_to_start() {
    let fixture = Fixture::new("bad-pin");
    let file = fixture.requests("requests.jsonl", &[PAY]);
    let output = fixture
        .guard(&["replay", file.to_str().unwrap()])
        .env("GUARD_SCREEN_SHA256", "00".repeat(32))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(text(&output).contains("refusing to run it"), "{}", text(&output));
    assert!(!fixture.log().exists());
}

#[test]
fn serve_answers_one_line_per_connection_on_a_0600_socket() {
    let fixture = Fixture::new("serve");
    let socket = fixture.dir.join("guard.sock");
    let mut server = fixture
        .guard(&["serve", "--socket", socket.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while UnixStream::connect(&socket).is_err() {
        assert!(started.elapsed() < Duration::from_secs(20), "serve did not come up");
        std::thread::sleep(Duration::from_millis(50));
    }
    // That probe connection sent nothing; serve must have shrugged it off.
    let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let ask = |request: &str| -> Value {
        let mut stream = UnixStream::connect(&socket).unwrap();
        stream.write_all(format!("{request}\n").as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };
    let call = ask(CALL);
    let garbage = ask(GARBAGE);
    server.kill().unwrap();
    server.wait().unwrap();

    assert_eq!(call["status"], "blocked");
    assert_eq!(call["reasons"], serde_json::json!(["tool_not_allowed:call"]));
    assert_eq!(garbage["reasons"], serde_json::json!(["malformed_request"]));
    assert_eq!(fixture.rpc.count(), 0);

    let verify = fixture.guard(&["verify", "--offline"]).output().unwrap();
    let report = text(&verify);
    assert!(verify.status.success(), "{report}");
    assert!(report.contains("4 events") && report.contains("llm-agent"), "{report}");
}
