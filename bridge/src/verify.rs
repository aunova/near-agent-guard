//! `guard verify`: the offline per-file checks (see `audit::verify_log`), the checks across
//! several log files, and, online, the cross-check of the logs against the vault's ledger.

use std::collections::{HashMap, HashSet};

use nostr::EventId;
use serde_json::Value;

use crate::audit::{Body, LogLine, Status, VerifiedLog, npub};
use crate::chain::{LedgerEntry, format_near, index_ledger};
use crate::screen::parse_yocto;

/// One verified log file and the name it is reported under.
#[derive(Debug)]
pub struct NamedLog {
    pub name: String,
    pub log: VerifiedLog,
}

/// Clock-skew allowance for the timestamp anchor: a ledger entry stamped up to this long before
/// the earliest log event still counts as part of the logged run.
const CLOCK_SKEW_MS: u64 = 120_000;

/// What the online cross-check established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCheck {
    /// Results whose ledger entry matched.
    pub matched_results: usize,
    /// Smallest and largest ledger index the logs reference, if any.
    pub range: Option<(u64, u64)>,
    /// Whether every entry from the anchor to the end of the ledger was checked.
    pub complete: bool,
    /// With `complete`: the smaller of the first logged index and the first entry for the agent
    /// stamped no earlier than the earliest log event minus `CLOCK_SKEW_MS`. `None` when neither
    /// exists (the logs made no spends and nothing happened on-chain since).
    pub anchor: Option<u64>,
    /// This agent's entries that were checked and found in the logs.
    pub checked: usize,
    /// This agent's entries before the first checked index (earlier runs): reported only.
    pub before_range: usize,
    /// This agent's entries after the last logged index, not checked (only without `complete`).
    pub tail_unchecked: usize,
}

/// Where the logs and the chain disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// A result line whose ledger entry is missing or different.
    Line { file: String, line: usize, reason: String },
    /// A ledger entry for this agent that the logs do not account for.
    LedgerIndex { index: u64, reason: String },
}

/// Checks across files: one signer, one contract and agent, and no attempt in two files.
pub fn check_union(logs: &[NamedLog]) -> Result<(), String> {
    let Some(first) = logs.first() else {
        return Err("no audit log given".to_owned());
    };
    for named in logs {
        if named.log.signer != first.log.signer {
            return Err(format!(
                "{} is signed by {}, but {} is signed by {}",
                named.name,
                npub(&named.log.signer),
                first.name,
                npub(&first.log.signer)
            ));
        }
        if named.log.contract != first.log.contract || named.log.agent != first.log.agent {
            return Err(format!(
                "{} is for {} / {}, but {} is for {} / {}",
                named.name, named.log.contract, named.log.agent, first.name, first.log.contract, first.log.agent
            ));
        }
    }
    let mut seen: HashMap<EventId, &str> = HashMap::new();
    for named in logs {
        for line in &named.log.lines {
            if matches!(line.body, Body::Attempt(_))
                && let Some(other) = seen.insert(line.event.id, &named.name)
            {
                return Err(format!(
                    "attempt {} appears in both {other} and {}",
                    line.event.id.to_hex(),
                    named.name
                ));
            }
        }
    }
    Ok(())
}

/// Forward: every result with a ledger index matches that entry (attempt id, agent, receiver,
/// amount, approved, reasons). Reverse, with lo/hi the smallest/largest referenced index over all
/// files: every entry for `agent` in [lo, hi] carries an attempt id that is in the logs. With
/// `complete`, every entry for `agent` from the anchor (see `CrossCheck::anchor`) to the end of
/// the ledger must instead be covered by a logged result: that catches a log whose last attempts
/// were cut off, down to a log cut to its first attempt. Earlier entries are only counted.
pub fn cross_check(logs: &[NamedLog], agent: &str, ledger: &[LedgerEntry], complete: bool) -> Result<CrossCheck, Mismatch> {
    let by_index = index_ledger(ledger);
    let mut attempts: HashMap<EventId, &LogLine> = HashMap::new();
    let mut answered: HashSet<String> = HashSet::new();
    for named in logs {
        for line in &named.log.lines {
            match &line.body {
                Body::Attempt(_) => {
                    attempts.insert(line.event.id, line);
                }
                Body::Result { attempt, .. } => {
                    answered.insert(attempt.to_hex());
                }
            }
        }
    }

    let mut matched_results = 0;
    let mut range: Option<(u64, u64)> = None;
    for named in logs {
        for line in &named.log.lines {
            let Body::Result { attempt, content } = &line.body else {
                continue;
            };
            let Some(index) = content.ledger_index else {
                continue;
            };
            let fail = |reason: String| Mismatch::Line {
                file: named.name.clone(),
                line: line.line,
                reason,
            };
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
    }

    let logged: HashSet<String> = attempts.keys().map(EventId::to_hex).collect();
    let mut agent_entries: Vec<&LedgerEntry> = ledger.iter().filter(|entry| entry.agent == agent).collect();
    agent_entries.sort_by_key(|entry| entry.index);
    let anchor = if complete {
        let earliest_ms = logs
            .iter()
            .flat_map(|named| named.log.lines.iter())
            .map(|line| line.event.created_at.as_secs())
            .min()
            .map(|secs| secs.saturating_mul(1000).saturating_sub(CLOCK_SKEW_MS));
        let by_time = earliest_ms.and_then(|threshold| {
            agent_entries
                .iter()
                .find(|entry| entry.timestamp_ms >= threshold)
                .map(|entry| entry.index)
        });
        match (range.map(|(lo, _)| lo), by_time) {
            (Some(logged_first), Some(stamped_first)) => Some(logged_first.min(stamped_first)),
            (logged_first, stamped_first) => logged_first.or(stamped_first),
        }
    } else {
        None
    };
    let mut check = CrossCheck {
        matched_results,
        range,
        complete,
        anchor,
        checked: 0,
        before_range: 0,
        tail_unchecked: 0,
    };
    for entry in agent_entries {
        if complete {
            match anchor {
                Some(anchor) if entry.index >= anchor => {
                    if !answered.contains(&entry.attempt_id) {
                        return Err(Mismatch::LedgerIndex {
                            index: entry.index,
                            reason: format!(
                                "{agent} spent under attempt {} ({} NEAR to {}, approved={}) and no log has its result (truncated?)",
                                entry.attempt_id,
                                format_near(entry.amount),
                                entry.receiver,
                                entry.approved
                            ),
                        });
                    }
                    check.checked += 1;
                }
                _ => check.before_range += 1,
            }
            continue;
        }
        let Some((lo, hi)) = range else {
            check.before_range += 1;
            continue;
        };
        if entry.index < lo {
            check.before_range += 1;
        } else if entry.index <= hi {
            if !logged.contains(&entry.attempt_id) {
                return Err(Mismatch::LedgerIndex {
                    index: entry.index,
                    reason: format!(
                        "{agent} spent under attempt {} ({} NEAR to {}, approved={}), which the logs omit",
                        entry.attempt_id,
                        format_near(entry.amount),
                        entry.receiver,
                        entry.approved
                    ),
                });
            }
            check.checked += 1;
        } else {
            check.tail_unchecked += 1;
        }
    }
    Ok(check)
}

/// The summary `guard verify` prints after a passing cross-check.
pub fn summary_lines(check: &CrossCheck, agent: &str) -> Vec<String> {
    let mut lines = vec![format!("ledger   {} logged results match their entries", check.matched_results)];
    match check.range {
        _ if check.complete => match check.anchor {
            Some(anchor) => {
                lines.push(format!(
                    "         indexes {anchor}.. to the end of the ledger: all {} entries for {agent} are covered by logged results \
                     (complete; anchor = first logged index or first entry stamped at most 120 s before the earliest log event)",
                    check.checked
                ));
                lines.push(format!(
                    "         {} entries for {agent} before index {anchor} (earlier runs): reported, not checked",
                    check.before_range
                ));
            }
            None => lines.push(format!(
                "         complete: these logs made no spends and the ledger has no entry for {agent} stamped later than \
                 120 s before the earliest log event; nothing to check ({} earlier entries reported)",
                check.before_range
            )),
        },
        Some((lo, hi)) => {
            lines.push(format!(
                "         indexes {lo}..={hi}: all {} entries for {agent} are in these logs",
                check.checked
            ));
            lines.push(format!(
                "         {} entries for {agent} before index {lo} (earlier runs): reported, not checked",
                check.before_range
            ));
            lines.push(format!(
                "         {} entries for {agent} after index {hi}: tail not checked; use --complete",
                check.tail_unchecked
            ));
        }
        None => {
            lines.push(format!(
                "         these logs reference no ledger index, so nothing anchors the check: {} entries for {agent} reported, not checked",
                check.before_range
            ));
            if !check.complete {
                lines.push("         tail not checked; use --complete".to_owned());
            }
        }
    }
    lines
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
    use std::path::{Path, PathBuf};

    use nostr::Keys;

    use super::*;
    use crate::audit::{AttemptContent, AuditLog, Origin, ResultContent, ScreenRecord, describe_raw_request, verify_log};

    const AGENT: &str = "agent.testnet";
    const HALF: u128 = 500_000_000_000_000_000_000_000;

    fn pay_attempt(receiver: &str, amount: u128) -> AttemptContent {
        let (raw_request_sha256, raw_request) = describe_raw_request(format!("{receiver}{amount}").as_bytes());
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

    fn temp(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/unit-tmp")
            .join(format!("verify-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");
        let _ = std::fs::remove_file(&path);
        path
    }

    fn named(path: &Path) -> NamedLog {
        NamedLog {
            name: path.display().to_string(),
            log: verify_log(path).unwrap(),
        }
    }

    /// Appends one approved payment logged at `index`; returns its attempt id.
    fn spend(log: &AuditLog, receiver: &str, amount: u128, index: u64) -> EventId {
        let id = log.append_attempt(&pay_attempt(receiver, amount)).unwrap();
        log.append_result(&id, &decided(Status::Approved, index, &[])).unwrap();
        id
    }

    fn other() -> EventId {
        EventId::from_hex(&"ee".repeat(32)).unwrap()
    }

    /// Log: attempt A approved at ledger 1, attempt B denied at ledger 3.
    fn sample(path: &Path) -> (NamedLog, EventId, EventId) {
        let log = AuditLog::open(path, Keys::generate(), "vault.testnet", AGENT).unwrap();
        let a = spend(&log, "vendor.testnet", HALF, 1);
        let b = log.append_attempt(&pay_attempt("drain.testnet", 10 * HALF)).unwrap();
        log.append_result(&b, &decided(Status::Denied, 3, &["receiver_not_allowed"])).unwrap();
        (named(path), a, b)
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
        let check = cross_check(std::slice::from_ref(&log), AGENT, &ledger, false).unwrap();
        assert_eq!((check.matched_results, check.range, check.checked), (2, Some((1, 3)), 2));
        assert_eq!((check.before_range, check.tail_unchecked), (1, 1));
        // With --complete the later run's entry 4 must be covered too, and it is not.
        assert!(matches!(
            cross_check(&[log], AGENT, &ledger, true),
            Err(Mismatch::LedgerIndex { index: 4, .. })
        ));
    }

    #[test]
    fn a_spend_inside_the_range_that_the_logs_omit_fails_naming_its_index() {
        let (log, a, b) = sample(&temp("omitted"));
        let ledger = vec![
            entry(1, AGENT, &a, "vendor.testnet", HALF, true, &[]),
            entry(2, AGENT, &other(), "drain.testnet", HALF, true, &[]),
            entry(3, AGENT, &b, "drain.testnet", 10 * HALF, false, &["receiver_not_allowed"]),
        ];
        let Err(Mismatch::LedgerIndex { index, reason }) = cross_check(&[log], AGENT, &ledger, false) else {
            panic!("expected a ledger mismatch");
        };
        assert_eq!(index, 2);
        assert!(reason.contains("which the logs omit"), "{reason}");
    }

    #[test]
    fn a_truncated_tail_passes_plain_verify_with_a_warning_but_fails_complete() {
        let path = temp("truncated");
        let writer = AuditLog::open(&path, Keys::generate(), "vault.testnet", AGENT).unwrap();
        let a = spend(&writer, "vendor.testnet", HALF, 0);
        let b = spend(&writer, "vendor.testnet", HALF, 1);
        let ledger = vec![
            entry(0, AGENT, &a, "vendor.testnet", HALF, true, &[]),
            entry(1, AGENT, &b, "vendor.testnet", HALF, true, &[]),
        ];
        assert!(cross_check(&[named(&path)], AGENT, &ledger, true).is_ok());

        // Drop the last attempt+result: the remaining prev chain is intact, so the file verifies.
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().take(2).collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
        let truncated = named(&path);

        let plain = cross_check(std::slice::from_ref(&truncated), AGENT, &ledger, false).unwrap();
        assert_eq!(plain.tail_unchecked, 1);
        let summary = summary_lines(&plain, AGENT).join("\n");
        assert!(summary.contains("tail not checked; use --complete"), "{summary}");

        let Err(Mismatch::LedgerIndex { index, reason }) = cross_check(&[truncated], AGENT, &ledger, true) else {
            panic!("--complete must catch the dropped spend");
        };
        assert_eq!(index, 1);
        assert!(reason.contains("no log has its result"), "{reason}");
    }

    #[test]
    fn two_logs_over_one_ledger_verify_together_and_dropping_one_fails() {
        let keys = Keys::generate();
        let first_path = temp("first");
        let second_path = temp("second");
        let first = AuditLog::open(&first_path, keys.clone(), "vault.testnet", AGENT).unwrap();
        let a = spend(&first, "vendor.testnet", HALF, 0);
        let second = AuditLog::open(&second_path, keys, "vault.testnet", AGENT).unwrap();
        // A different request: two files started in the same second with the same request would
        // produce the same attempt id (same key, content, prev and second) and be refused as shared.
        let b = spend(&second, "vendor.testnet", HALF / 2, 1);
        let ledger = vec![
            entry(0, AGENT, &a, "vendor.testnet", HALF, true, &[]),
            entry(1, AGENT, &b, "vendor.testnet", HALF / 2, true, &[]),
        ];
        let both = [named(&first_path), named(&second_path)];
        check_union(&both).unwrap();
        let check = cross_check(&both, AGENT, &ledger, true).unwrap();
        assert_eq!((check.range, check.checked, check.before_range), (Some((0, 1)), 2, 0));

        let Err(Mismatch::LedgerIndex { index, .. }) = cross_check(&[named(&first_path)], AGENT, &ledger, true) else {
            panic!("dropping the second log must fail --complete");
        };
        assert_eq!(index, 1);
    }

    #[test]
    fn logs_from_different_signers_or_sharing_an_attempt_are_refused() {
        let first_path = temp("signer-a");
        let second_path = temp("signer-b");
        let a_keys = Keys::generate();
        let b_keys = Keys::generate();
        spend(&AuditLog::open(&first_path, a_keys.clone(), "vault.testnet", AGENT).unwrap(), "vendor.testnet", HALF, 0);
        spend(&AuditLog::open(&second_path, b_keys.clone(), "vault.testnet", AGENT).unwrap(), "vendor.testnet", HALF, 1);
        let message = check_union(&[named(&first_path), named(&second_path)]).unwrap_err();
        assert!(
            message.contains(&npub(&a_keys.public_key())) && message.contains(&npub(&b_keys.public_key())),
            "{message}"
        );

        let copy_path = temp("copy");
        std::fs::copy(&first_path, &copy_path).unwrap();
        let message = check_union(&[named(&first_path), named(&copy_path)]).unwrap_err();
        assert!(message.contains("appears in both"), "{message}");
    }

    #[test]
    fn forward_mismatches_name_the_result_line() {
        let (log, a, b) = sample(&temp("forward"));
        let logs = [log];
        let good_b = entry(3, AGENT, &b, "drain.testnet", 10 * HALF, false, &["receiver_not_allowed"]);
        for ledger in [
            vec![entry(1, AGENT, &a, "vendor.testnet", 2 * HALF, true, &[]), good_b.clone()],
            vec![entry(1, AGENT, &other(), "vendor.testnet", HALF, true, &[]), good_b.clone()],
            vec![entry(1, AGENT, &a, "vendor.testnet", HALF, false, &[]), good_b.clone()],
            vec![good_b.clone()],
            vec![entry(1, "agent2.testnet", &a, "vendor.testnet", HALF, true, &[]), good_b.clone()],
        ] {
            assert!(matches!(cross_check(&logs, AGENT, &ledger, false), Err(Mismatch::Line { line: 2, .. })));
        }
    }

    #[test]
    fn logs_without_ledger_results_only_count_and_say_so() {
        let path = temp("no-ledger");
        let writer = AuditLog::open(&path, Keys::generate(), "vault.testnet", AGENT).unwrap();
        let a = writer.append_attempt(&pay_attempt("vendor.testnet", HALF)).unwrap();
        writer.append_result(&a, &ResultContent::blocked(vec!["x".to_owned()])).unwrap();
        let ledger = vec![entry(0, AGENT, &other(), "vendor.testnet", HALF, true, &[])];
        let check = cross_check(&[named(&path)], AGENT, &ledger, false).unwrap();
        assert_eq!((check.range, check.before_range), (None, 1));
        assert!(summary_lines(&check, AGENT).join("\n").contains("nothing anchors the check"));

        // --complete with no spend logged and nothing stamped since: passes, and says why.
        let complete = cross_check(&[named(&path)], AGENT, &ledger, true).unwrap();
        assert_eq!((complete.anchor, complete.before_range), (None, 1));
        assert!(summary_lines(&complete, AGENT).join("\n").contains("these logs made no spends"));
    }

    #[test]
    fn a_log_cut_to_before_its_first_result_fails_complete_via_the_timestamp_anchor() {
        let path = temp("cut-to-first-attempt");
        let writer = AuditLog::open(&path, Keys::generate(), "vault.testnet", AGENT).unwrap();
        let a = spend(&writer, "vendor.testnet", HALF, 1);
        // Keep only the first line (the attempt): no result, so no logged ledger index at all.
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{}\n", text.lines().next().unwrap())).unwrap();
        let truncated = named(&path);
        let started_ms = truncated.log.lines[0].event.created_at.as_secs() * 1000;

        let mut earlier_run = entry(0, AGENT, &other(), "vendor.testnet", HALF, true, &[]);
        earlier_run.timestamp_ms = started_ms - CLOCK_SKEW_MS - 1_000; // outside the allowance
        let mut this_run = entry(1, AGENT, &a, "vendor.testnet", HALF, true, &[]);
        this_run.timestamp_ms = started_ms + 2_000;
        let ledger = vec![earlier_run, this_run];

        let Err(Mismatch::LedgerIndex { index, reason }) = cross_check(&[truncated], AGENT, &ledger, true) else {
            panic!("--complete must not pass a log cut down to its first attempt");
        };
        assert_eq!(index, 1);
        assert!(reason.contains("no log has its result"), "{reason}");
    }

    #[test]
    fn rows_list_one_line_per_attempt() {
        let (log, _, _) = sample(&temp("rows"));
        let rows = attempt_rows(&log.log);
        assert_eq!(rows.len(), 3);
        assert!(rows[1].contains("approved") && rows[1].contains("allow 0.5 NEAR to vendor.testnet"), "{}", rows[1]);
        assert!(rows[2].contains("denied") && rows[2].contains("allow 5 NEAR to drain.testnet"), "{}", rows[2]);
    }
}
