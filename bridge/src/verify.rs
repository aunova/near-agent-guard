//! `guard verify`: the offline log checks (see `audit::verify_log`) plus, online, a cross-check
//! of the log against the vault's on-chain ledger in both directions.

use std::collections::{HashMap, HashSet};

use nostr::EventId;
use serde_json::Value;

use crate::audit::{Body, LogLine, Status, VerifiedLog};
use crate::chain::{LedgerEntry, format_near, index_ledger};
use crate::screen::parse_yocto;

/// What the online cross-check established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCheck {
    /// Results whose ledger entry matched.
    pub matched_results: usize,
    /// Smallest and largest ledger index the log references, if any.
    pub range: Option<(u64, u64)>,
    /// This agent's entries inside the range (all of them are in the log).
    pub agent_entries_in_range: usize,
    /// This agent's entries outside the range: reported, not failed, since other runs can share
    /// the vault.
    pub agent_entries_outside_range: usize,
}

/// Where the log and the chain disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// A result line whose ledger entry is missing or different.
    Line { line: usize, reason: String },
    /// A ledger entry for this agent, inside the logged range, that the log omits.
    LedgerIndex { index: u64, reason: String },
}

/// Forward: every result with a ledger index matches that entry (attempt id, agent, receiver,
/// amount, approved, reasons). Reverse: with lo/hi the smallest/largest referenced index, every
/// entry for `agent` in [lo, hi] carries an attempt id that is in this log. Entries for `agent`
/// outside [lo, hi] are only counted.
pub fn cross_check(log: &VerifiedLog, agent: &str, ledger: &[LedgerEntry]) -> Result<CrossCheck, Mismatch> {
    let by_index = index_ledger(ledger);
    let attempts: HashMap<EventId, &LogLine> = log
        .lines
        .iter()
        .filter(|line| matches!(line.body, Body::Attempt(_)))
        .map(|line| (line.event.id, line))
        .collect();

    let mut matched_results = 0;
    let mut range: Option<(u64, u64)> = None;
    for line in &log.lines {
        let Body::Result { attempt, content } = &line.body else {
            continue;
        };
        let Some(index) = content.ledger_index else {
            continue;
        };
        let fail = |reason: String| Mismatch::Line { line: line.line, reason };
        let entry = by_index
            .get(&index)
            .ok_or_else(|| fail(format!("ledger entry {index} does not exist on-chain")))?;
        if entry.attempt_id != attempt.to_hex() {
            return Err(fail(format!(
                "ledger entry {index} records attempt {}, not {}",
                entry.attempt_id,
                attempt.to_hex()
            )));
        }
        if entry.agent != agent {
            return Err(fail(format!("ledger entry {index} belongs to {}, not {agent}", entry.agent)));
        }
        let (receiver, amount) = attempts
            .get(attempt)
            .and_then(|attempt_line| screened_intent(attempt_line))
            .ok_or_else(|| fail("the result has a ledger index but its attempt was not screened in".to_owned()))?;
        if entry.receiver != receiver || entry.amount != amount {
            return Err(fail(format!(
                "ledger entry {index} pays {} NEAR to {}, the log screened in {} NEAR to {receiver}",
                format_near(entry.amount),
                entry.receiver,
                format_near(amount)
            )));
        }
        let approved = match content.status {
            Status::Approved => true,
            Status::Denied => false,
            other => return Err(fail(format!("status {} cannot carry a ledger index", other.as_str()))),
        };
        if entry.approved != approved {
            return Err(fail(format!(
                "ledger entry {index} says approved={}, the log says {}",
                entry.approved,
                content.status.as_str()
            )));
        }
        if entry.reasons != content.reasons {
            return Err(fail(format!(
                "ledger entry {index} reasons {:?} differ from the log's {:?}",
                entry.reasons, content.reasons
            )));
        }
        matched_results += 1;
        range = Some(range.map_or((index, index), |(lo, hi)| (lo.min(index), hi.max(index))));
    }

    let logged: HashSet<String> = attempts.keys().map(EventId::to_hex).collect();
    let mut agent_entries: Vec<&LedgerEntry> = ledger.iter().filter(|entry| entry.agent == agent).collect();
    agent_entries.sort_by_key(|entry| entry.index);
    let mut in_range = 0;
    let mut outside = 0;
    for entry in agent_entries {
        match range {
            Some((lo, hi)) if (lo..=hi).contains(&entry.index) => {
                if !logged.contains(&entry.attempt_id) {
                    return Err(Mismatch::LedgerIndex {
                        index: entry.index,
                        reason: format!(
                            "{agent} spent under attempt {} ({} NEAR to {}, approved={}), which this log omits",
                            entry.attempt_id,
                            format_near(entry.amount),
                            entry.receiver,
                            entry.approved
                        ),
                    });
                }
                in_range += 1;
            }
            _ => outside += 1,
        }
    }
    Ok(CrossCheck {
        matched_results,
        range,
        agent_entries_in_range: in_range,
        agent_entries_outside_range: outside,
    })
}

/// Receiver and amount of the payment an attempt's screen verdict let through.
fn screened_intent(line: &LogLine) -> Option<(String, u128)> {
    let Body::Attempt(content) = &line.body else {
        return None;
    };
    let verdict = content.screen.as_ref()?.verdict.as_ref()?;
    if verdict.get("ok") != Some(&Value::Bool(true)) {
        return None;
    }
    let intent = verdict.get("intent")?;
    let receiver = intent.get("receiver")?.as_str()?.to_owned();
    let amount = parse_yocto(intent.get("amount_yocto")?.as_str()?)?;
    Some((receiver, amount))
}

/// One table row per attempt: line, attempt id, origin, screen verdict, result.
pub fn attempt_rows(log: &VerifiedLog) -> Vec<String> {
    let mut rows = vec![format!(
        "{:<6} {:<14} {:<10} {:<18} {:<7} {:<12} {}",
        "line", "attempt", "origin", "status", "ledger", "tx", "screen"
    )];
    for line in &log.lines {
        let Body::Attempt(content) = &line.body else {
            continue;
        };
        let id = line.event.id.to_hex();
        let (status, ledger, tx) = match log.result_for(&line.event.id).map(|result| &result.body) {
            Some(Body::Result { content, .. }) => (
                content.status.as_str().to_owned(),
                content.ledger_index.map_or_else(|| "-".to_owned(), |index| index.to_string()),
                content.tx_hash.as_deref().map_or_else(|| "-".to_owned(), short),
            ),
            _ => ("(no result)".to_owned(), "-".to_owned(), "-".to_owned()),
        };
        let origin = match content.origin {
            crate::audit::Origin::LlmAgent => "llm-agent",
            crate::audit::Origin::Replay => "replay",
            crate::audit::Origin::Attack => "attack",
        };
        rows.push(format!(
            "{:<6} {:<14} {:<10} {:<18} {:<7} {:<12} {}",
            line.line,
            short(&id),
            origin,
            status,
            ledger,
            tx,
            describe_screen(line)
        ));
    }
    rows
}

fn describe_screen(line: &LogLine) -> String {
    let Body::Attempt(content) = &line.body else {
        return String::new();
    };
    let Some(screen) = &content.screen else {
        return "bypassed (attack with the raw key)".to_owned();
    };
    let Some(verdict) = &screen.verdict else {
        return "no verdict (screen failed)".to_owned();
    };
    if let Some((receiver, amount)) = screened_intent(line) {
        return format!("allow {} NEAR to {receiver}", format_near(amount));
    }
    let reasons: Vec<&str> = verdict
        .get("reasons")
        .and_then(Value::as_array)
        .map(|reasons| reasons.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    format!("reject {}", reasons.join(","))
}

fn short(text: &str) -> String {
    match text.char_indices().nth(12) {
        Some((end, _)) => format!("{}…", text.get(..end).unwrap_or_default()),
        None => text.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use nostr::Keys;

    use super::*;
    use crate::audit::{AttemptContent, AuditLog, Origin, ResultContent, ScreenRecord, describe_raw_request, verify_log};

    const AGENT: &str = "agent.testnet";
    const HALF: u128 = 500_000_000_000_000_000_000_000;

    fn pay_attempt(receiver: &str, amount: u128) -> AttemptContent {
        let (raw_request_sha256, raw_request) = describe_raw_request(b"{}");
        AttemptContent {
            origin: Origin::Replay,
            raw_request_sha256,
            raw_request,
            screen: Some(ScreenRecord {
                wasm_sha256: "cd".repeat(32),
                verdict: Some(serde_json::json!({"ok": true, "intent": {"kind": "pay", "receiver": receiver, "amount_yocto": amount.to_string(), "memo": null}})),
            }),
        }
    }

    fn decided(status: Status, index: u64, reasons: &[&str]) -> ResultContent {
        ResultContent {
            status,
            ledger_index: Some(index),
            tx_hash: Some(format!("tx{index}")),
            transfer: Some("succeeded".to_owned()),
            reasons: reasons.iter().map(|reason| (*reason).to_owned()).collect(),
            message: None,
        }
    }

    fn entry(index: u64, agent: &str, attempt: &EventId, receiver: &str, amount: u128, approved: bool, reasons: &[&str]) -> LedgerEntry {
        LedgerEntry {
            index,
            agent: agent.to_owned(),
            receiver: receiver.to_owned(),
            amount,
            attempt_id: attempt.to_hex(),
            memo: None,
            approved,
            reasons: reasons.iter().map(|reason| (*reason).to_owned()).collect(),
            transfer: if approved { "succeeded" } else { "not_attempted" }.to_owned(),
            block_height: 1,
            timestamp_ms: 1,
        }
    }

    /// Log: attempt A approved at ledger 1, attempt B denied at ledger 3.
    fn sample(path: &Path) -> (VerifiedLog, EventId, EventId) {
        let _ = std::fs::remove_file(path);
        let log = AuditLog::open(path, Keys::generate(), "vault.testnet", AGENT).unwrap();
        let a = log.append_attempt(&pay_attempt("vendor.testnet", HALF)).unwrap();
        log.append_result(&a, &decided(Status::Approved, 1, &[])).unwrap();
        let b = log.append_attempt(&pay_attempt("drain.testnet", 10 * HALF)).unwrap();
        log.append_result(&b, &decided(Status::Denied, 3, &["receiver_not_allowed"])).unwrap();
        (verify_log(path).unwrap(), a, b)
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/unit-tmp")
            .join(format!("verify-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("audit.jsonl")
    }

    fn other() -> EventId {
        EventId::from_hex(&"ee".repeat(32)).unwrap()
    }

    #[test]
    fn matching_ledger_passes_and_counts_entries_outside_the_range() {
        let (log, a, b) = sample(&temp("pass"));
        let ledger = vec![
            entry(0, AGENT, &other(), "vendor.testnet", HALF, true, &[]), // an earlier run
            entry(1, AGENT, &a, "vendor.testnet", HALF, true, &[]),
            entry(2, "someone-else.testnet", &other(), "x.testnet", 1, true, &[]),
            entry(3, AGENT, &b, "drain.testnet", 10 * HALF, false, &["receiver_not_allowed"]),
            entry(4, AGENT, &other(), "vendor.testnet", HALF, true, &[]), // a later run
        ];
        assert_eq!(
            cross_check(&log, AGENT, &ledger).unwrap(),
            CrossCheck {
                matched_results: 2,
                range: Some((1, 3)),
                agent_entries_in_range: 2,
                agent_entries_outside_range: 2,
            }
        );
    }

    #[test]
    fn a_spend_inside_the_range_that_the_log_omits_fails_naming_its_index() {
        let (log, a, b) = sample(&temp("omitted"));
        let ledger = vec![
            entry(1, AGENT, &a, "vendor.testnet", HALF, true, &[]),
            entry(2, AGENT, &other(), "drain.testnet", HALF, true, &[]),
            entry(3, AGENT, &b, "drain.testnet", 10 * HALF, false, &["receiver_not_allowed"]),
        ];
        let Err(Mismatch::LedgerIndex { index, reason }) = cross_check(&log, AGENT, &ledger) else {
            panic!("expected a ledger mismatch");
        };
        assert_eq!(index, 2);
        assert!(reason.contains("which this log omits"), "{reason}");
    }

    #[test]
    fn forward_mismatches_name_the_result_line() {
        let (log, a, b) = sample(&temp("forward"));
        let good_b = entry(3, AGENT, &b, "drain.testnet", 10 * HALF, false, &["receiver_not_allowed"]);

        let wrong_amount = vec![entry(1, AGENT, &a, "vendor.testnet", 2 * HALF, true, &[]), good_b.clone()];
        assert!(matches!(cross_check(&log, AGENT, &wrong_amount), Err(Mismatch::Line { line: 2, .. })));

        let wrong_attempt = vec![entry(1, AGENT, &other(), "vendor.testnet", HALF, true, &[]), good_b.clone()];
        assert!(matches!(cross_check(&log, AGENT, &wrong_attempt), Err(Mismatch::Line { line: 2, .. })));

        let flipped = vec![entry(1, AGENT, &a, "vendor.testnet", HALF, false, &[]), good_b.clone()];
        assert!(matches!(cross_check(&log, AGENT, &flipped), Err(Mismatch::Line { line: 2, .. })));

        let missing = vec![good_b];
        assert!(matches!(cross_check(&log, AGENT, &missing), Err(Mismatch::Line { line: 2, .. })));

        let other_agent = vec![
            entry(1, "agent2.testnet", &a, "vendor.testnet", HALF, true, &[]),
            entry(3, AGENT, &b, "drain.testnet", 10 * HALF, false, &["receiver_not_allowed"]),
        ];
        assert!(matches!(cross_check(&log, AGENT, &other_agent), Err(Mismatch::Line { line: 2, .. })));
    }

    #[test]
    fn a_log_without_ledger_results_only_counts() {
        let path = temp("no-ledger");
        let _ = std::fs::remove_file(&path);
        let writer = AuditLog::open(&path, Keys::generate(), "vault.testnet", AGENT).unwrap();
        let a = writer.append_attempt(&pay_attempt("vendor.testnet", HALF)).unwrap();
        writer.append_result(&a, &ResultContent::blocked(vec!["x".to_owned()])).unwrap();
        let log = verify_log(&path).unwrap();
        let ledger = vec![entry(0, AGENT, &other(), "vendor.testnet", HALF, true, &[])];
        let check = cross_check(&log, AGENT, &ledger).unwrap();
        assert_eq!((check.range, check.agent_entries_outside_range), (None, 1));
    }

    #[test]
    fn rows_list_one_line_per_attempt() {
        let (log, _, _) = sample(&temp("rows"));
        let rows = attempt_rows(&log);
        assert_eq!(rows.len(), 3);
        assert!(rows[1].contains("approved") && rows[1].contains("allow 0.5 NEAR to vendor.testnet"), "{}", rows[1]);
        assert!(rows[2].contains("denied") && rows[2].contains("allow 5 NEAR to drain.testnet"), "{}", rows[2]);
    }
}
