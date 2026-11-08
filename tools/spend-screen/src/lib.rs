//! Spend screen: the only code that parses an agent's raw wallet request.
//!
//! The bridge runs this crate's binary as a `wasm32-wasip2` component inside WasmBox with
//! stdin/stdout only, so the process holding the NEAR key never parses agent output itself.
//! Input is one untrusted JSON request; output is one verdict line (shared contract, section 2).

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;

/// Largest request accepted, in bytes. [`read_request`] reads one byte more so an oversized
/// request is detected instead of being silently truncated.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Longest memo accepted, in UTF-8 bytes (the contract's own limit).
pub const MAX_MEMO_BYTES: usize = 256;
/// The only tool an agent may use.
pub const ALLOWED_TOOL: &str = "pay";
/// NEAR has 24 decimal places.
const NEAR_DECIMALS: usize = 24;
/// 10^24: yoctoNEAR per NEAR.
const YOCTO_PER_NEAR: u128 = 1_000_000_000_000_000_000_000_000;
/// The tool name is untrusted input; only this many chars of it are echoed back.
const MAX_ECHOED_TOOL_CHARS: usize = 64;

/// Why a request was rejected. `Display` gives the wire code from the shared contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    MalformedRequest,
    RequestTooLarge,
    ToolNotAllowed(String),
    BadReceiver,
    BadAmount,
    MemoTooLong,
    MemoContainsSecret,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRequest => f.write_str("malformed_request"),
            Self::RequestTooLarge => f.write_str("request_too_large"),
            Self::ToolNotAllowed(name) => write!(f, "tool_not_allowed:{name}"),
            Self::BadReceiver => f.write_str("bad_receiver"),
            Self::BadAmount => f.write_str("bad_amount"),
            Self::MemoTooLong => f.write_str("memo_too_long"),
            Self::MemoContainsSecret => f.write_str("memo_contains_secret"),
        }
    }
}

/// A screened payment: the only thing the bridge will ever turn into a chain call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayIntent {
    pub receiver: String,
    pub amount_yocto: u128,
    pub memo: Option<String>,
}

/// The screen's decision on one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow(PayIntent),
    /// Every reason that applies, in the order the shared contract lists them.
    Reject(Vec<Reason>),
}

#[derive(Serialize)]
struct AllowWire<'a> {
    ok: bool,
    intent: IntentWire<'a>,
}

#[derive(Serialize)]
struct IntentWire<'a> {
    kind: &'static str,
    receiver: &'a str,
    /// Decimal digits: a JSON number cannot carry a u128 exactly.
    amount_yocto: String,
    memo: Option<&'a str>,
}

#[derive(Serialize)]
struct RejectWire {
    ok: bool,
    reasons: Vec<String>,
}

impl Verdict {
    /// The verdict as the single JSON line the bridge expects (no trailing newline).
    pub fn to_json_line(&self) -> serde_json::Result<String> {
        match self {
            Self::Allow(intent) => serde_json::to_string(&AllowWire {
                ok: true,
                intent: IntentWire {
                    kind: ALLOWED_TOOL,
                    receiver: &intent.receiver,
                    amount_yocto: intent.amount_yocto.to_string(),
                    memo: intent.memo.as_deref(),
                },
            }),
            Self::Reject(reasons) => serde_json::to_string(&RejectWire {
                ok: false,
                reasons: reasons.iter().map(ToString::to_string).collect(),
            }),
        }
    }
}

/// Reads at most `MAX_REQUEST_BYTES + 1` bytes: enough to tell a full request from an oversized one.
pub fn read_request<R: Read>(reader: R) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut buf)?;
    Ok(buf)
}

/// Top-level request. Derive (not a `Value` walk) so a duplicated `tool` key is an error rather
/// than "last one wins".
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    tool: String,
    /// Left unparsed until the tool is known: a disallowed tool's args are never inspected.
    args: Option<Box<RawValue>>,
}

/// `pay` arguments. Each field stays a `Value` so a wrong type maps to that field's own reason.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayArgs {
    receiver: Option<Value>,
    amount: Option<Value>,
    memo: Option<Value>,
}

/// Screens one raw request.
pub fn screen(raw: &[u8]) -> Verdict {
    if raw.len() > MAX_REQUEST_BYTES {
        return Verdict::Reject(vec![Reason::RequestTooLarge]);
    }
    let Ok(envelope) = serde_json::from_slice::<Envelope>(raw) else {
        return Verdict::Reject(vec![Reason::MalformedRequest]);
    };
    if envelope.tool != ALLOWED_TOOL {
        let echoed: String = envelope.tool.chars().take(MAX_ECHOED_TOOL_CHARS).collect();
        return Verdict::Reject(vec![Reason::ToolNotAllowed(echoed)]);
    }
    let Some(args) = envelope.args else {
        return Verdict::Reject(vec![Reason::MalformedRequest]);
    };
    match serde_json::from_str::<PayArgs>(args.get()) {
        Ok(args) => screen_pay(args),
        Err(_) => Verdict::Reject(vec![Reason::MalformedRequest]),
    }
}

fn screen_pay(args: PayArgs) -> Verdict {
    let receiver = match args.receiver {
        Some(Value::String(receiver)) if is_valid_account_id(&receiver) => Some(receiver),
        _ => None,
    };
    let amount = match &args.amount {
        Some(Value::String(amount)) => parse_near_amount(amount),
        _ => None,
    };

    let mut malformed = false;
    let mut memo_too_long = false;
    let mut memo_secret = false;
    let memo = match args.memo {
        None => None,
        Some(Value::String(memo)) => {
            memo_too_long = memo.len() > MAX_MEMO_BYTES;
            malformed = memo.chars().any(is_forbidden_memo_char);
            memo_secret = contains_secret(&memo);
            Some(memo)
        }
        Some(_) => {
            malformed = true;
            None
        }
    };

    let mut reasons = Vec::new();
    if malformed {
        reasons.push(Reason::MalformedRequest);
    }
    if receiver.is_none() {
        reasons.push(Reason::BadReceiver);
    }
    if amount.is_none() {
        reasons.push(Reason::BadAmount);
    }
    if memo_too_long {
        reasons.push(Reason::MemoTooLong);
    }
    if memo_secret {
        reasons.push(Reason::MemoContainsSecret);
    }

    match (receiver, amount) {
        (Some(receiver), Some(amount_yocto)) if reasons.is_empty() => Verdict::Allow(PayIntent {
            receiver,
            amount_yocto,
            memo,
        }),
        _ => Verdict::Reject(reasons),
    }
}

/// Converts a decimal NEAR string to yoctoNEAR exactly, with no float anywhere.
///
/// Accepts ASCII digits, optionally followed by `.` and 1 to 24 more digits. No sign, exponent,
/// whitespace or separators. Returns `None` for zero or anything that would overflow `u128`.
pub fn parse_near_amount(text: &str) -> Option<u128> {
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => {
            if fraction.is_empty()
                || fraction.len() > NEAR_DECIMALS
                || !fraction.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            (whole, fraction)
        }
        None => (text, ""),
    };
    if whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let mut whole_value: u128 = 0;
    for digit in whole.bytes() {
        whole_value = whole_value
            .checked_mul(10)?
            .checked_add(u128::from(digit - b'0'))?;
    }

    // At most 24 digits, so this stays below 10^24 and cannot overflow.
    let mut fraction_value: u128 = 0;
    for digit in fraction.bytes() {
        fraction_value = fraction_value * 10 + u128::from(digit - b'0');
    }
    let missing_places = u32::try_from(NEAR_DECIMALS.checked_sub(fraction.len())?).ok()?;
    let fraction_yocto = fraction_value * 10u128.pow(missing_places);

    let yocto = whole_value
        .checked_mul(YOCTO_PER_NEAR)?
        .checked_add(fraction_yocto)?;
    (yocto > 0).then_some(yocto)
}

/// NEAR account-id rules: 2 to 64 chars matching
/// `^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$`, checked by hand.
pub fn is_valid_account_id(id: &str) -> bool {
    (2..=64).contains(&id.len()) && id.split('.').all(is_valid_account_part)
}

/// One dot-separated part: `([a-z\d]+[-_])*[a-z\d]+`.
fn is_valid_account_part(part: &str) -> bool {
    // True at the start and after a separator: a separator may not follow either.
    let mut after_separator = true;
    for byte in part.bytes() {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => after_separator = false,
            b'-' | b'_' if !after_separator => after_separator = true,
            _ => return false,
        }
    }
    // An empty part, or one ending in a separator, is invalid.
    !after_separator
}

/// Control characters (Unicode `Cc`) plus the `Bidi_Control` set, which can reorder how a memo
/// displays in an explorer (Trojan Source, CVE-2021-42574).
fn is_forbidden_memo_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH32_ALPHABET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn is_base58(byte: u8) -> bool {
    BASE58_ALPHABET.contains(&byte)
}

/// Bech32 is case-insensitive (all-uppercase is valid), so compare lowercased.
fn is_bech32(byte: u8) -> bool {
    BECH32_ALPHABET.contains(&byte.to_ascii_lowercase())
}

/// Characters that appear in `sk-` style API keys (`sk-proj-...`, `sk-ant-...`).
fn is_api_key_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Secret scan for the memo, which is public once on-chain: an injected agent could try to
/// exfiltrate a key through it. Prefixes match ASCII case-insensitively; every run count stops
/// at its threshold, so the scan stays linear in the memo length.
pub fn contains_secret(text: &str) -> bool {
    let bytes = text.as_bytes();
    (0..bytes.len()).any(|start| {
        let rest = bytes.get(start..).unwrap_or_default();
        count_after(rest, b"ed25519:", 43, is_base58) >= 43
            || count_after(rest, b"secp256k1:", 43, is_base58) >= 43
            || count_after(rest, b"nsec1", 58, is_bech32) >= 58
            || strip_prefix_ignore_case(rest, b"-----begin").is_some()
            || api_key_alnum_after(rest) >= 20
    })
}

fn strip_prefix_ignore_case<'a>(hay: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let head = hay.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        hay.get(prefix.len()..)
    } else {
        None
    }
}

/// How many bytes of `class` directly follow `prefix`, counting at most `limit`.
fn count_after(hay: &[u8], prefix: &[u8], limit: usize, class: fn(u8) -> bool) -> usize {
    strip_prefix_ignore_case(hay, prefix).map_or(0, |rest| {
        rest.iter().take(limit).take_while(|&&b| class(b)).count()
    })
}

/// Alphanumerics in the API-key run right after `sk-`, counting at most 20.
fn api_key_alnum_after(hay: &[u8]) -> usize {
    strip_prefix_ignore_case(hay, b"sk-").map_or(0, |rest| {
        rest.iter()
            .take_while(|b| is_api_key_char(**b))
            .filter(|b| b.is_ascii_alphanumeric())
            .take(20)
            .count()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VENDOR: &str = "vendor.aunova-guard.testnet";

    fn pay(receiver: &str, amount: &str, memo: Option<&str>) -> Vec<u8> {
        let mut args = serde_json::json!({ "receiver": receiver, "amount": amount });
        if let Some(memo) = memo {
            args["memo"] = Value::String(memo.to_owned());
        }
        serde_json::to_vec(&serde_json::json!({ "tool": "pay", "args": args })).unwrap()
    }

    fn reasons(raw: &[u8]) -> Vec<String> {
        match screen(raw) {
            Verdict::Reject(reasons) => reasons.iter().map(ToString::to_string).collect(),
            Verdict::Allow(intent) => panic!("expected a rejection, got {intent:?}"),
        }
    }

    fn allowed(raw: &[u8]) -> PayIntent {
        match screen(raw) {
            Verdict::Allow(intent) => intent,
            Verdict::Reject(reasons) => panic!("expected an allow, got {reasons:?}"),
        }
    }

    #[test]
    fn spec_example_pay_request_yields_the_spec_verdict_line() {
        let raw = br#"{"tool":"pay","args":{"receiver":"vendor.aunova-guard.testnet","amount":"0.5","memo":"INV-2026-11-001"}}"#;
        assert_eq!(
            screen(raw).to_json_line().unwrap(),
            r#"{"ok":true,"intent":{"kind":"pay","receiver":"vendor.aunova-guard.testnet","amount_yocto":"500000000000000000000000","memo":"INV-2026-11-001"}}"#
        );
    }

    #[test]
    fn spec_example_call_request_yields_the_spec_verdict_line() {
        let raw = br#"{"tool":"call","args":{"method":"set_policy","json":"{\"per_tx_max\":\"100000000000000000000000000\"}"}}"#;
        assert_eq!(
            screen(raw).to_json_line().unwrap(),
            r#"{"ok":false,"reasons":["tool_not_allowed:call"]}"#
        );
    }

    #[test]
    fn absent_and_null_memo_serialise_as_null() {
        let expected = r#"{"ok":true,"intent":{"kind":"pay","receiver":"vendor.aunova-guard.testnet","amount_yocto":"1000000000000000000000000","memo":null}}"#;
        assert_eq!(screen(&pay(VENDOR, "1", None)).to_json_line().unwrap(), expected);
        let with_null = br#"{"tool":"pay","args":{"receiver":"vendor.aunova-guard.testnet","amount":"1","memo":null}}"#;
        assert_eq!(screen(with_null).to_json_line().unwrap(), expected);
    }

    #[test]
    fn malformed_request_covers_garbage_and_wrong_shapes() {
        for raw in [
            &b"garbage"[..],
            b"",
            b"[]",
            b"null",
            b"{}",
            br#"{"tool":1,"args":{}}"#,
            br#"{"tool":"pay"}"#,
            br#"{"tool":"pay","args":null}"#,
            br#"{"tool":"pay","args":[]}"#,
            br#"{"tool":"pay","args":{"receiver":"vendor.testnet","amount":"1"},"extra":1}"#,
            br#"{"tool":"pay","args":{"receiver":"vendor.testnet","amount":"1"}} trailing"#,
            b"\xff\xfe{}",
        ] {
            assert_eq!(reasons(raw), ["malformed_request"], "input: {:?}", String::from_utf8_lossy(raw));
        }
    }

    #[test]
    fn duplicate_keys_are_malformed_not_last_one_wins() {
        let duplicate_tool = br#"{"tool":"call","tool":"pay","args":{"receiver":"vendor.testnet","amount":"1"}}"#;
        assert_eq!(reasons(duplicate_tool), ["malformed_request"]);
        let duplicate_receiver = br#"{"tool":"pay","args":{"receiver":"vendor.testnet","receiver":"drain.testnet","amount":"1"}}"#;
        assert_eq!(reasons(duplicate_receiver), ["malformed_request"]);
    }

    #[test]
    fn unknown_pay_argument_is_malformed() {
        let raw = br#"{"tool":"pay","args":{"receiver":"vendor.testnet","amount":"1","deposit":"5"}}"#;
        assert_eq!(reasons(raw), ["malformed_request"]);
    }

    #[test]
    fn memo_of_the_wrong_type_or_with_control_chars_is_malformed() {
        let numeric_memo = br#"{"tool":"pay","args":{"receiver":"vendor.testnet","amount":"1","memo":7}}"#;
        assert_eq!(reasons(numeric_memo), ["malformed_request"]);
        assert_eq!(reasons(&pay(VENDOR, "1", Some("line\nbreak"))), ["malformed_request"]);
        assert_eq!(reasons(&pay(VENDOR, "1", Some("bell\u{7}"))), ["malformed_request"]);
        assert_eq!(reasons(&pay(VENDOR, "1", Some("INV-1\u{202E}100-VNI"))), ["malformed_request"]);
        assert_eq!(reasons(&pay(VENDOR, "1", Some("isolate\u{2066}x\u{2069}"))), ["malformed_request"]);
    }

    #[test]
    fn request_too_large_boundary() {
        let filler_for = |total: usize| {
            // Pad with whitespace after the object: still valid JSON, exactly `total` bytes.
            let mut raw = pay(VENDOR, "1", Some(""));
            raw.resize(total, b' ');
            raw
        };
        let at_limit = filler_for(MAX_REQUEST_BYTES);
        assert_eq!(at_limit.len(), MAX_REQUEST_BYTES);
        assert_eq!(allowed(&at_limit).amount_yocto, YOCTO_PER_NEAR);

        let over_limit = filler_for(MAX_REQUEST_BYTES + 1);
        assert_eq!(reasons(&over_limit), ["request_too_large"]);
    }

    #[test]
    fn read_request_reads_one_byte_past_the_limit_and_no_more() {
        let input = vec![b'x'; MAX_REQUEST_BYTES * 3];
        assert_eq!(read_request(&input[..]).unwrap().len(), MAX_REQUEST_BYTES + 1);
        let small = b"{}".to_vec();
        assert_eq!(read_request(&small[..]).unwrap(), small);
    }

    #[test]
    fn tool_not_allowed_names_the_tool_and_clips_it() {
        assert_eq!(reasons(br#"{"tool":"transfer","args":{}}"#), ["tool_not_allowed:transfer"]);
        assert_eq!(reasons(br#"{"tool":"Pay","args":{}}"#), ["tool_not_allowed:Pay"]);
        // A disallowed tool's args are never inspected, so even absent args give only this reason.
        assert_eq!(reasons(br#"{"tool":"call"}"#), ["tool_not_allowed:call"]);

        let long = "é".repeat(100);
        let raw = serde_json::to_vec(&serde_json::json!({ "tool": long, "args": {} })).unwrap();
        assert_eq!(reasons(&raw), [format!("tool_not_allowed:{}", "é".repeat(64))]);
    }

    #[test]
    fn bad_receiver_cases() {
        for receiver in [
            "", "a", "Vendor.testnet", "vendor..testnet", ".vendor", "vendor.", "-vendor", "vendor-",
            "ven--dor", "ven-_dor", "vendor testnet", "vendör.testnet", "vendor.testnet\n",
        ] {
            assert_eq!(reasons(&pay(receiver, "1", None)), ["bad_receiver"], "receiver: {receiver:?}");
        }
        assert_eq!(reasons(&pay(&"a".repeat(65), "1", None)), ["bad_receiver"]);
        let missing = br#"{"tool":"pay","args":{"amount":"1"}}"#;
        assert_eq!(reasons(missing), ["bad_receiver"]);
        let numeric = br#"{"tool":"pay","args":{"receiver":5,"amount":"1"}}"#;
        assert_eq!(reasons(numeric), ["bad_receiver"]);
    }

    #[test]
    fn valid_receivers_pass() {
        let receivers = [
            "ab".to_owned(),
            "vendor.aunova-guard.testnet".to_owned(),
            "a_b-c.d0".to_owned(),
            "0x1234567890abcdef1234567890abcdef12345678".to_owned(),
            "f".repeat(64),
        ];
        for receiver in &receivers {
            assert_eq!(&allowed(&pay(receiver, "1", None)).receiver, receiver);
        }
    }

    #[test]
    fn bad_amount_cases() {
        for amount in [
            "", "0", "00", "0.0", "0.000000000000000000000000", ".5", "5.", ".", "+1", "-1", "1e3",
            " 1", "1 ", "1,5", "1_000", "0x10", "1.2.3", "١", "NaN", "inf",
        ] {
            assert_eq!(reasons(&pay(VENDOR, amount, None)), ["bad_amount"], "amount: {amount:?}");
        }
        let numeric = br#"{"tool":"pay","args":{"receiver":"vendor.testnet","amount":0.5}}"#;
        assert_eq!(reasons(numeric), ["bad_amount"]);
        let missing = br#"{"tool":"pay","args":{"receiver":"vendor.testnet"}}"#;
        assert_eq!(reasons(missing), ["bad_amount"]);
    }

    #[test]
    fn twenty_four_fractional_digits_is_the_boundary() {
        assert_eq!(parse_near_amount("0.000000000000000000000001"), Some(1));
        assert_eq!(parse_near_amount("1.000000000000000000000001"), Some(YOCTO_PER_NEAR + 1));
        assert_eq!(parse_near_amount("0.999999999999999999999999"), Some(YOCTO_PER_NEAR - 1));
        assert_eq!(parse_near_amount("0.5"), Some(YOCTO_PER_NEAR / 2));
        assert_eq!(parse_near_amount("007.25"), Some(7 * YOCTO_PER_NEAR + YOCTO_PER_NEAR / 4));
        // 25 fractional digits is refused even when the extra digit is a zero.
        assert_eq!(parse_near_amount("0.0000000000000000000000010"), None);
        assert_eq!(parse_near_amount("1.0000000000000000000000000"), None);
    }

    #[test]
    fn u128_overflow_is_refused_exactly_at_the_edge() {
        let max = u128::MAX.to_string(); // 340282366920938463463374607431768211455
        let (whole, fraction) = max.split_at(max.len() - NEAR_DECIMALS);
        assert_eq!(parse_near_amount(&format!("{whole}.{fraction}")), Some(u128::MAX));

        // One yoctoNEAR past u128::MAX, written as NEAR.
        assert_eq!(parse_near_amount("340282366920938.463463374607431768211456"), None);
        assert_eq!(parse_near_amount("340282366920939"), None);
        assert_eq!(parse_near_amount(&"9".repeat(16_000)), None);
    }

    #[test]
    fn memo_length_boundary_counts_utf8_bytes() {
        assert!(allowed(&pay(VENDOR, "1", Some(&"x".repeat(256)))).memo.is_some());
        assert_eq!(reasons(&pay(VENDOR, "1", Some(&"x".repeat(257)))), ["memo_too_long"]);
        // "é" is two bytes: 128 of them is exactly 256 bytes, 129 is over.
        assert!(allowed(&pay(VENDOR, "1", Some(&"é".repeat(128)))).memo.is_some());
        assert_eq!(reasons(&pay(VENDOR, "1", Some(&"é".repeat(129)))), ["memo_too_long"]);
    }

    #[test]
    fn memo_secret_patterns_are_caught() {
        let memos = [
            format!("ed25519:{}", "3tgdk2wPraJzT4nsTuf86UX41xgPNk3MHnq8epARMdBNs29AFEztAuaQ7iHddDfXG9F2RzV1XNQYgJyAyoW51UBB"),
            format!("pay me, key ED25519:{}", "A".repeat(43)),
            format!("secp256k1:{}", "5".repeat(43)),
            format!("nsec1{}", "q".repeat(58)),
            format!("NSEC1{}", "Q".repeat(58)),
            "-----BEGIN PRIVATE KEY-----".to_owned(),
            "-----begin openssh".to_owned(),
            format!("sk-{}", "a1".repeat(10)),
            format!("key=sk-proj-{}", "Ab3_".repeat(6)),
            format!("sk-ant-api03-{}", "x".repeat(20)),
        ];
        for memo in &memos {
            assert_eq!(reasons(&pay(VENDOR, "1", Some(memo))), ["memo_contains_secret"], "memo: {memo:?}");
        }
    }

    #[test]
    fn memo_secret_near_misses_pass() {
        for memo in [
            "INV-2026-11-001".to_owned(),
            format!("ed25519:{}", "A".repeat(42)),
            format!("ed25519:{}", "0".repeat(60)), // '0' is not base58
            format!("secp256k1:{}", "l".repeat(60)), // 'l' is not base58
            format!("nsec1{}", "q".repeat(57)),
            format!("nsec1{}", "b".repeat(58)), // 'b' is not bech32
            "-----BEGI".to_owned(),
            format!("sk-{}", "a".repeat(19)),
            format!("sk-{}", "-".repeat(40)),
        ] {
            assert!(allowed(&pay(VENDOR, "1", Some(&memo))).memo.is_some(), "memo: {memo:?}");
        }
    }

    #[test]
    fn secret_scan_decides_hostile_memos() {
        // Memos built to restart prefix matches at every position.
        let hostile = "sk-".repeat(5_000) + &"ed25519:".repeat(1_000) + &"nsec1".repeat(1_000);
        assert!(contains_secret(&hostile));
        let dashes = format!("sk-{}", "-".repeat(MAX_REQUEST_BYTES));
        assert!(!contains_secret(&dashes));
    }

    #[test]
    fn every_reason_that_applies_is_reported_in_contract_order() {
        let memo = format!("{}nsec1{}", "x".repeat(300), "q".repeat(58));
        assert_eq!(
            reasons(&pay("BAD", "0", Some(&memo))),
            ["bad_receiver", "bad_amount", "memo_too_long", "memo_contains_secret"]
        );
        let raw = br#"{"tool":"pay","args":{"receiver":"BAD","amount":"x","memo":{"k":1}}}"#;
        assert_eq!(reasons(raw), ["malformed_request", "bad_receiver", "bad_amount"]);
    }
}
