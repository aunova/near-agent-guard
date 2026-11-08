//! Hash-chained, signed audit log: one NIP-01 event (kind 4242, BIP-340 signature) per line.
//!
//! Events reuse the Nostr format only so `nak verify` can check them; they are never published
//! to a relay. Each event carries `["prev", <id of the line before>]`, so editing, deleting or
//! reordering a line breaks the chain at that line even for someone who does not hold the key.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use nostr::{Event, EventBuilder, EventId, JsonUtil, Keys, Kind, PublicKey, Tag, TagKind, ToBech32};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Event kind for every audit event.
const AUDIT_KIND: u16 = 4242;
/// Value of the `t` tag.
const TOPIC: &str = "near-agent-guard";
/// `prev` of the first event in a file.
const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// `raw_request` keeps at most this many bytes; `raw_request_sha256` covers all of it.
const RAW_REQUEST_EXCERPT_BYTES: usize = 2048;
/// Longest line `verify_log` reads. Our events stay far below it (the excerpt and the verdict are
/// both capped), and a tampered log cannot make the verifier buffer an unbounded line.
const MAX_LINE_BYTES: usize = 256 * 1024;
/// The last line of a log always fits in this tail window, for the same reason.
const TAIL_WINDOW_BYTES: u64 = MAX_LINE_BYTES as u64;

/// Who produced the raw request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    LlmAgent,
    Replay,
    Attack,
}

/// Content of a `phase=attempt` event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptContent {
    pub origin: Origin,
    pub raw_request_sha256: String,
    pub raw_request: String,
    /// `None` only for attacks, which model a stolen key and bypass the screen by design.
    pub screen: Option<ScreenRecord>,
}

/// What the screen saw and said. `verdict` is `None` when it produced no usable verdict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScreenRecord {
    pub wasm_sha256: String,
    pub verdict: Option<Value>,
}

/// Final status of one attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Approved,
    Denied,
    Blocked,
    Error,
    /// Attack transaction refused by NEAR before execution (the expected outcome).
    ProtocolRejected,
    /// Attack transaction accepted by NEAR: the key's permissions did not hold.
    ProtocolAccepted,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Blocked => "blocked",
            Self::Error => "error",
            Self::ProtocolRejected => "protocol_rejected",
            Self::ProtocolAccepted => "protocol_accepted",
        }
    }
}

/// Content of a `phase=result` event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultContent {
    pub status: Status,
    pub ledger_index: Option<u64>,
    pub tx_hash: Option<String>,
    pub transfer: Option<String>,
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ResultContent {
    pub fn blocked(reasons: Vec<String>) -> Self {
        Self {
            status: Status::Blocked,
            ledger_index: None,
            tx_hash: None,
            transfer: None,
            reasons,
            message: None,
        }
    }

    pub fn error(tx_hash: Option<String>, message: String) -> Self {
        Self {
            status: Status::Error,
            ledger_index: None,
            tx_hash,
            transfer: None,
            reasons: Vec::new(),
            message: Some(message),
        }
    }
}

/// `raw_request_sha256` and the `raw_request` excerpt for one raw request.
pub fn describe_raw_request(raw: &[u8]) -> (String, String) {
    let sha256 = format!("{:x}", Sha256::digest(raw));
    // Lossy so garbage bytes still log; the sha256 above pins the exact bytes.
    let text = String::from_utf8_lossy(raw);
    (sha256, clip_to_bytes(&text, RAW_REQUEST_EXCERPT_BYTES).to_owned())
}

/// The longest prefix of `text` that fits in `max` bytes without splitting a char.
fn clip_to_bytes(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.get(..end).unwrap_or_default()
}

/// Appends signed events to the log file. Every append takes an exclusive lock on the file and
/// re-reads the last line, so separate `guard` processes sharing one log keep one chain.
pub struct AuditLog {
    path: std::path::PathBuf,
    keys: Keys,
    contract: String,
    agent: String,
}

impl AuditLog {
    /// Opens (or prepares to create) the log, refusing a tail that is not one of our events.
    pub fn open(path: &Path, keys: Keys, contract: &str, agent: &str) -> Result<Self> {
        if let Some(last) = read_last_event(path)?
            && last.pubkey != keys.public_key()
        {
            bail!(
                "audit log {} is signed by {}, but GUARD_AUDIT_NSEC is {}; refusing to mix signers",
                path.display(),
                npub(&last.pubkey),
                npub(&keys.public_key())
            );
        }
        Ok(Self {
            path: path.to_path_buf(),
            keys,
            contract: contract.to_owned(),
            agent: agent.to_owned(),
        })
    }

    pub fn signer_npub(&self) -> String {
        npub(&self.keys.public_key())
    }

    /// Signs and appends an attempt; returns its event id (the on-chain `attempt_id`).
    pub fn append_attempt(&self, content: &AttemptContent) -> Result<EventId> {
        self.append("attempt", serde_json::to_string(content)?, Vec::new())
    }

    /// Signs and appends the result for `attempt`.
    pub fn append_result(&self, attempt: &EventId, content: &ResultContent) -> Result<EventId> {
        let mut extra = vec![tag("e", attempt.to_hex())];
        if let Some(tx_hash) = &content.tx_hash {
            extra.push(tag("near_tx", tx_hash.clone()));
        }
        if let Some(index) = content.ledger_index {
            extra.push(tag("ledger", index.to_string()));
        }
        self.append("result", serde_json::to_string(content)?, extra)
    }

    fn append(&self, phase: &str, content: String, extra: Vec<Tag>) -> Result<EventId> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&self.path)
            .with_context(|| format!("cannot open audit log {}", self.path.display()))?;
        file.lock()
            .with_context(|| format!("cannot lock audit log {}", self.path.display()))?;
        let prev = match last_event_in(&mut file)
            .with_context(|| format!("audit log {} has a corrupt last line; run `guard verify`", self.path.display()))?
        {
            Some(last) if last.pubkey != self.keys.public_key() => {
                bail!("audit log {} gained events from another signer", self.path.display())
            }
            Some(last) => last.id.to_hex(),
            None => GENESIS_PREV.to_owned(),
        };
        let mut tags = vec![
            tag("t", TOPIC),
            tag("phase", phase),
            tag("prev", prev),
            tag("contract", self.contract.as_str()),
            tag("agent", self.agent.as_str()),
        ];
        tags.extend(extra);
        let event = EventBuilder::new(Kind::Custom(AUDIT_KIND), content)
            .tags(tags)
            .sign_with_keys(&self.keys)
            .map_err(|_| anyhow!("signing the audit event failed"))?;
        let mut line = event
            .try_as_json()
            .map_err(|_| anyhow!("serialising the audit event failed"))?;
        line.push('\n');
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_data())
            .with_context(|| format!("cannot write audit log {}", self.path.display()))?;
        Ok(event.id)
    }
}

fn tag(kind: &str, value: impl Into<String>) -> Tag {
    Tag::custom(TagKind::custom(kind.to_owned()), [value.into()])
}

pub fn npub(public_key: &PublicKey) -> String {
    let Ok(npub) = public_key.to_bech32();
    npub
}

/// The last event of the log at `path`, or `None` if the file is missing or empty.
fn read_last_event(path: &Path) -> Result<Option<Event>> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot open audit log {}", path.display()));
        }
    };
    last_event_in(&mut file)
        .with_context(|| format!("audit log {} has a corrupt last line; run `guard verify`", path.display()))
}

fn last_event_in(file: &mut std::fs::File) -> Result<Option<Event>> {
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(len.saturating_sub(TAIL_WINDOW_BYTES)))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)?;
    let Some(body) = tail.strip_suffix(b"\n") else {
        bail!("the last line is not newline-terminated (interrupted write?)");
    };
    let last = body.rsplit(|b| *b == b'\n').next().unwrap_or(body);
    let event = Event::from_json(last).map_err(|_| anyhow!("the last line is not an event"))?;
    if !event.verify_id() || !event.verify_signature() {
        bail!("the last line's id or signature does not verify");
    }
    Ok(Some(event))
}

/// One verified line.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub line: usize,
    pub event: Event,
    pub body: Body,
}

#[derive(Debug, Clone)]
pub enum Body {
    Attempt(AttemptContent),
    Result { attempt: EventId, content: ResultContent },
}

/// A log whose every line passed the offline checks.
#[derive(Debug)]
pub struct VerifiedLog {
    pub signer: PublicKey,
    pub contract: String,
    pub agent: String,
    pub lines: Vec<LogLine>,
}

impl VerifiedLog {
    /// The result logged for `attempt`, if any.
    pub fn result_for(&self, attempt: &EventId) -> Option<&LogLine> {
        self.lines.iter().find(|line| matches!(&line.body, Body::Result { attempt: a, .. } if a == attempt))
    }
}

/// Why verification stopped. `line` is 1-based; 0 means the file as a whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadLine {
    pub line: usize,
    pub reason: String,
}

impl BadLine {
    fn at(line: usize, reason: impl Into<String>) -> Self {
        Self {
            line,
            reason: reason.into(),
        }
    }
}

/// Offline verification: per line, the event id, the BIP-340 signature, a single signer, the
/// `prev` chain, consistent `contract`/`agent` tags, well-formed content, and every result
/// referencing an earlier attempt that has no other result. Stops at the first bad line.
pub fn verify_log(path: &Path) -> Result<VerifiedLog, BadLine> {
    let file = std::fs::File::open(path)
        .map_err(|error| BadLine::at(0, format!("cannot open {}: {}", path.display(), error.kind())))?;
    let mut lines = Vec::new();
    let mut header: Option<(PublicKey, String, String)> = None;
    let mut prev = GENESIS_PREV.to_owned();
    let mut attempts: HashSet<EventId> = HashSet::new();
    let mut answered: HashSet<EventId> = HashSet::new();
    let mut reader = BufReader::new(file);
    let mut number = 0;
    loop {
        let mut raw = Vec::new();
        let read = reader
            .by_ref()
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut raw)
            .map_err(|error| BadLine::at(number + 1, format!("unreadable: {}", error.kind())))?;
        if read == 0 {
            break;
        }
        number += 1;
        if raw.last() == Some(&b'\n') {
            raw.pop();
        } else if raw.len() > MAX_LINE_BYTES {
            return Err(BadLine::at(number, format!("longer than {MAX_LINE_BYTES} bytes")));
        }
        let event = Event::from_json(&raw).map_err(|_| BadLine::at(number, "not a NIP-01 event"))?;
        if !event.verify_id() {
            return Err(BadLine::at(number, "event id does not match its content (edited after signing)"));
        }
        if !event.verify_signature() {
            return Err(BadLine::at(number, "BIP-340 signature does not verify"));
        }
        if event.kind.as_u16() != AUDIT_KIND {
            return Err(BadLine::at(number, format!("kind {} is not {AUDIT_KIND}", event.kind.as_u16())));
        }
        let tags = single_value_tags(&event).map_err(|reason| BadLine::at(number, reason))?;
        let get = |name: &str| tags.get(name).map(String::as_str);
        if get("t") != Some(TOPIC) {
            return Err(BadLine::at(number, format!("missing [\"t\",\"{TOPIC}\"]")));
        }
        if get("prev") != Some(prev.as_str()) {
            return Err(BadLine::at(number, format!("prev does not point at the line before ({prev})")));
        }
        let (Some(contract), Some(agent)) = (get("contract"), get("agent")) else {
            return Err(BadLine::at(number, "missing contract or agent tag"));
        };
        match &header {
            None => header = Some((event.pubkey, contract.to_owned(), agent.to_owned())),
            Some((signer, _, _)) if *signer != event.pubkey => {
                return Err(BadLine::at(
                    number,
                    format!("signed by {}, but line 1 is signed by {}", npub(&event.pubkey), npub(signer)),
                ));
            }
            Some((_, first_contract, first_agent)) if first_contract != contract || first_agent != agent => {
                return Err(BadLine::at(number, "contract or agent differs from line 1"));
            }
            Some(_) => {}
        }

        let body = match get("phase") {
            Some("attempt") => {
                let content: AttemptContent = serde_json::from_str(&event.content)
                    .map_err(|_| BadLine::at(number, "attempt content is not the expected JSON"))?;
                attempts.insert(event.id);
                Body::Attempt(content)
            }
            Some("result") => {
                let content: ResultContent = serde_json::from_str(&event.content)
                    .map_err(|_| BadLine::at(number, "result content is not the expected JSON"))?;
                let attempt = get("e")
                    .and_then(|hex| EventId::from_hex(hex).ok())
                    .ok_or_else(|| BadLine::at(number, "result has no valid e tag"))?;
                if !attempts.contains(&attempt) {
                    return Err(BadLine::at(number, "result does not reference an earlier attempt in this log"));
                }
                if !answered.insert(attempt) {
                    return Err(BadLine::at(number, "second result for the same attempt"));
                }
                if get("ledger") != content.ledger_index.map(|index| index.to_string()).as_deref() {
                    return Err(BadLine::at(number, "ledger tag disagrees with the content"));
                }
                if get("near_tx") != content.tx_hash.as_deref() {
                    return Err(BadLine::at(number, "near_tx tag disagrees with the content"));
                }
                Body::Result { attempt, content }
            }
            _ => return Err(BadLine::at(number, "phase is neither attempt nor result")),
        };
        prev = event.id.to_hex();
        lines.push(LogLine {
            line: number,
            event,
            body,
        });
    }

    let Some((signer, contract, agent)) = header else {
        return Err(BadLine::at(0, "the log is empty"));
    };
    Ok(VerifiedLog {
        signer,
        contract,
        agent,
        lines,
    })
}

/// Tag name to value, for tags that must appear exactly once with exactly one value.
fn single_value_tags(event: &Event) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    for tag in event.tags.iter() {
        let [name, value] = tag.as_slice() else {
            return Err(format!("tag {:?} is not a [name, value] pair", tag.as_slice()));
        };
        if map.insert(name.clone(), value.clone()).is_some() {
            return Err(format!("tag {name} appears twice"));
        }
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> std::path::PathBuf {
        // Inside the crate's gitignored target/, never the system temp dir.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/unit-tmp")
            .join(format!("audit-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        path
    }

    fn attempt(raw: &str) -> AttemptContent {
        let (raw_request_sha256, raw_request) = describe_raw_request(raw.as_bytes());
        AttemptContent {
            origin: Origin::Replay,
            raw_request_sha256,
            raw_request,
            screen: Some(ScreenRecord {
                wasm_sha256: "ab".repeat(32),
                verdict: Some(serde_json::json!({"ok": true, "intent": {"kind": "pay", "receiver": "vendor.testnet", "amount_yocto": "500000000000000000000000", "memo": null}})),
            }),
        }
    }

    fn write_sample(path: &Path, keys: &Keys) -> (EventId, EventId) {
        let log = AuditLog::open(path, keys.clone(), "vault.testnet", "agent.testnet").unwrap();
        let first = log.append_attempt(&attempt(r#"{"tool":"pay"}"#)).unwrap();
        log.append_result(&first, &ResultContent::error(None, "no key".to_owned())).unwrap();
        let second = log.append_attempt(&attempt("garbage")).unwrap();
        log.append_result(&second, &ResultContent::blocked(vec!["malformed_request".to_owned()]))
            .unwrap();
        (first, second)
    }

    fn rewrite_line(path: &Path, number: usize, edit: impl Fn(&str) -> String) {
        let text = std::fs::read_to_string(path).unwrap();
        let lines: Vec<String> = text
            .lines()
            .enumerate()
            .map(|(index, line)| if index + 1 == number { edit(line) } else { line.to_owned() })
            .collect();
        std::fs::write(path, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn sign_verify_chain_round_trip() {
        let path = temp_log("round-trip");
        let keys = Keys::generate();
        let (first, second) = write_sample(&path, &keys);

        let log = verify_log(&path).unwrap();
        assert_eq!(log.signer, keys.public_key());
        assert_eq!(log.lines.len(), 4);
        assert_eq!((log.contract.as_str(), log.agent.as_str()), ("vault.testnet", "agent.testnet"));
        assert!(matches!(log.result_for(&first).unwrap().body, Body::Result { ref content, .. } if content.status == Status::Error));
        assert!(matches!(log.result_for(&second).unwrap().body, Body::Result { ref content, .. } if content.status == Status::Blocked));

        // Each line's prev is the previous line's id; the first is the genesis value.
        let text = std::fs::read_to_string(&path).unwrap();
        let events: Vec<Event> = text.lines().map(|line| Event::from_json(line).unwrap()).collect();
        let prev_of = |event: &Event| {
            event.tags.iter().find(|t| t.as_slice()[0] == "prev").unwrap().as_slice()[1].clone()
        };
        assert_eq!(prev_of(&events[0]), GENESIS_PREV);
        for pair in events.windows(2) {
            assert_eq!(prev_of(&pair[1]), pair[0].id.to_hex());
        }
        // A reopened log continues the same chain.
        let reopened = AuditLog::open(&path, keys.clone(), "vault.testnet", "agent.testnet").unwrap();
        reopened.append_attempt(&attempt("third")).unwrap();
        assert_eq!(verify_log(&path).unwrap().lines.len(), 5);
    }

    #[test]
    fn tampered_amount_fails_at_exactly_that_line() {
        let path = temp_log("tamper");
        let keys = Keys::generate();
        write_sample(&path, &keys);
        let original = std::fs::read_to_string(&path).unwrap();
        assert!(original.lines().next().unwrap().contains("500000000000000000000000"));

        rewrite_line(&path, 1, |line| line.replace("500000000000000000000000", "900000000000000000000000"));
        assert_eq!(
            verify_log(&path).unwrap_err(),
            BadLine::at(1, "event id does not match its content (edited after signing)")
        );

        std::fs::write(&path, &original).unwrap();
        rewrite_line(&path, 3, |line| line.replace("garbage", "GARBAGE"));
        assert_eq!(verify_log(&path).unwrap_err().line, 3);
    }

    #[test]
    fn deleted_or_reordered_lines_break_the_chain() {
        let path = temp_log("delete");
        let keys = Keys::generate();
        write_sample(&path, &keys);
        let original = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = original.lines().collect();

        std::fs::write(&path, format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3])).unwrap();
        let bad = verify_log(&path).unwrap_err();
        assert_eq!(bad.line, 2);
        assert!(bad.reason.starts_with("prev does not point at the line before"), "{}", bad.reason);

        std::fs::write(&path, format!("{}\n{}\n{}\n{}\n", lines[1], lines[0], lines[2], lines[3])).unwrap();
        assert_eq!(verify_log(&path).unwrap_err().line, 1);
    }

    #[test]
    fn a_second_signer_is_refused_on_append_and_on_verify() {
        let path = temp_log("signer");
        let keys = Keys::generate();
        write_sample(&path, &keys);

        let intruder = Keys::generate();
        let error = AuditLog::open(&path, intruder.clone(), "vault.testnet", "agent.testnet")
            .err()
            .unwrap();
        assert!(error.to_string().contains("refusing to mix signers"), "{error}");

        // Forge a correctly chained line signed by someone else.
        let last = read_last_event(&path).unwrap().unwrap();
        let forged = EventBuilder::new(Kind::Custom(AUDIT_KIND), serde_json::to_string(&attempt("x")).unwrap())
            .tags([
                tag("t", TOPIC),
                tag("phase", "attempt"),
                tag("prev", last.id.to_hex()),
                tag("contract", "vault.testnet"),
                tag("agent", "agent.testnet"),
            ])
            .sign_with_keys(&intruder)
            .unwrap();
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str(&forged.as_json());
        text.push('\n');
        std::fs::write(&path, text).unwrap();
        let bad = verify_log(&path).unwrap_err();
        assert_eq!(bad.line, 5);
        assert!(bad.reason.contains("but line 1 is signed by"), "{}", bad.reason);
    }

    #[test]
    fn result_must_reference_an_earlier_unanswered_attempt() {
        let path = temp_log("orphan");
        let keys = Keys::generate();
        let log = AuditLog::open(&path, keys, "vault.testnet", "agent.testnet").unwrap();
        let first = log.append_attempt(&attempt("a")).unwrap();
        log.append_result(&first, &ResultContent::blocked(vec!["x".to_owned()])).unwrap();
        log.append_result(&first, &ResultContent::blocked(vec!["x".to_owned()])).unwrap();
        assert_eq!(verify_log(&path).unwrap_err(), BadLine::at(3, "second result for the same attempt"));

        let path = temp_log("orphan-unknown");
        let keys = Keys::generate();
        let log = AuditLog::open(&path, keys, "vault.testnet", "agent.testnet").unwrap();
        let unknown = EventId::from_hex(&"11".repeat(32)).unwrap();
        log.append_result(&unknown, &ResultContent::blocked(vec!["x".to_owned()])).unwrap();
        assert_eq!(
            verify_log(&path).unwrap_err(),
            BadLine::at(1, "result does not reference an earlier attempt in this log")
        );
    }

    #[test]
    fn truncated_last_line_blocks_further_appends() {
        let path = temp_log("truncated");
        let keys = Keys::generate();
        write_sample(&path, &keys);
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &text[..text.len() - 10]).unwrap();
        let log = AuditLog::open(&path, keys.clone(), "vault.testnet", "agent.testnet");
        assert!(log.is_err());
        assert!(verify_log(&path).is_err());
    }

    #[test]
    fn empty_log_does_not_verify() {
        let path = temp_log("empty");
        std::fs::write(&path, "").unwrap();
        assert_eq!(verify_log(&path).unwrap_err(), BadLine::at(0, "the log is empty"));
    }

    #[test]
    fn excerpt_is_clipped_on_a_char_boundary_and_hash_covers_everything() {
        let raw = "é".repeat(2000); // 4000 bytes
        let (sha, excerpt) = describe_raw_request(raw.as_bytes());
        assert_eq!(excerpt.len(), 2048);
        assert_eq!(excerpt, "é".repeat(1024));
        assert_eq!(sha, format!("{:x}", Sha256::digest(raw.as_bytes())));
        let (_, odd) = describe_raw_request(&[b'a'; 2047].iter().copied().chain("é".bytes()).collect::<Vec<u8>>());
        assert_eq!(odd.len(), 2047);
    }
}
