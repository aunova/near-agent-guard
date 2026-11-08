//! `gate(raw, origin)`: screen, log the attempt, then (only if screened in) spend, log the result.

use std::sync::Arc;

use near_api::Signer;
use nostr::EventId;
use serde::Serialize;
use tokio::runtime::Runtime;

use crate::audit::{
    AttemptContent, AuditLog, Origin, ResultContent, ScreenRecord, Status, describe_raw_request,
};
use crate::chain::{Chain, SpendOutcome};
use crate::screen::{PayIntent, Screen, ScreenOutcome};

/// One response line on the socket (or one printed line in replay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Response {
    pub status: Status,
    pub attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ledger_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Response {
    fn bare(status: Status, attempt_id: Option<String>) -> Self {
        Self {
            status,
            attempt_id,
            ledger_index: None,
            tx: None,
            transfer: None,
            reasons: None,
            message: None,
        }
    }

    /// The response shape the shared contract gives for `result`'s status.
    fn for_result(attempt_id: &EventId, result: &ResultContent) -> Self {
        let mut response = Self::bare(result.status, Some(attempt_id.to_hex()));
        match result.status {
            Status::Approved => {
                response.ledger_index = result.ledger_index;
                response.tx = result.tx_hash.clone();
                response.transfer = Some(result.transfer.clone().unwrap_or_else(|| "unknown".to_owned()));
            }
            Status::Denied => {
                response.ledger_index = result.ledger_index;
                response.tx = result.tx_hash.clone();
                response.reasons = Some(result.reasons.clone());
            }
            Status::Blocked => response.reasons = Some(result.reasons.clone()),
            Status::Error | Status::ProtocolRejected | Status::ProtocolAccepted => {
                response.message = result.message.clone();
            }
        }
        response
    }

    /// The attempt could not be logged, so nothing else happened either.
    fn unlogged() -> Self {
        let mut response = Self::bare(Status::Error, None);
        response.message = Some("audit log write failed; nothing was sent".to_owned());
        response
    }
}

/// Everything one gate needs. Holds the only copy of the agent's signing key.
pub struct Gate {
    screen: Screen,
    log: AuditLog,
    chain: Chain,
    signer: Option<Arc<Signer>>,
    runtime: Runtime,
}

impl Gate {
    pub fn new(screen: Screen, log: AuditLog, chain: Chain, signer: Option<Arc<Signer>>, runtime: Runtime) -> Self {
        Self {
            screen,
            log,
            chain,
            signer,
            runtime,
        }
    }

    /// Screens `raw`, appends the signed attempt (always, before anything is sent), spends only a
    /// screened-in payment, appends the signed result, and returns the response.
    pub fn gate(&self, raw: &[u8], origin: Origin) -> Response {
        let outcome = self.screen.run(raw);
        let (raw_request_sha256, raw_request) = describe_raw_request(raw);
        let attempt = AttemptContent {
            origin,
            raw_request_sha256,
            raw_request,
            screen: Some(ScreenRecord {
                wasm_sha256: self.screen.wasm_sha256().to_owned(),
                verdict: outcome.verdict().cloned(),
            }),
        };
        let attempt_id = match self.log.append_attempt(&attempt) {
            Ok(id) => id,
            Err(error) => {
                eprintln!("guard: {error:#}");
                return Response::unlogged();
            }
        };

        let result = match outcome {
            ScreenOutcome::Rejected { reasons, .. } => ResultContent::blocked(reasons),
            ScreenOutcome::Failed(message) => {
                ResultContent::error(None, format!("screen failed ({message}); nothing was sent"))
            }
            ScreenOutcome::Allowed { intent, .. } => self.spend(&intent, &attempt_id),
        };
        if let Err(error) = self.log.append_result(&attempt_id, &result) {
            eprintln!("guard: logging the result of attempt {}: {error:#}", attempt_id.to_hex());
        }
        Response::for_result(&attempt_id, &result)
    }

    fn spend(&self, intent: &PayIntent, attempt_id: &EventId) -> ResultContent {
        let Some(signer) = &self.signer else {
            return ResultContent::error(None, "AGENT_PRIVATE_KEY is not set; nothing was sent".to_owned());
        };
        match self
            .runtime
            .block_on(self.chain.request_spend(signer, intent, &attempt_id.to_hex()))
        {
            SpendOutcome::Decided {
                tx_hash,
                receipt,
                transfer,
            } => ResultContent {
                status: if receipt.approved {
                    Status::Approved
                } else {
                    Status::Denied
                },
                ledger_index: Some(receipt.ledger_index),
                tx_hash: Some(tx_hash),
                transfer,
                reasons: receipt.reasons,
                message: None,
            },
            SpendOutcome::Failed {
                tx_hash,
                reasons,
                message,
            } => ResultContent {
                reasons,
                ..ResultContent::error(tx_hash, message)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> EventId {
        EventId::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn json(response: &Response) -> String {
        serde_json::to_string(response).unwrap()
    }

    #[test]
    fn response_shapes_match_the_contract() {
        let attempt = "ab".repeat(32);
        let approved = ResultContent {
            status: Status::Approved,
            ledger_index: Some(0),
            tx_hash: Some("Tx1".to_owned()),
            transfer: Some("succeeded".to_owned()),
            reasons: Vec::new(),
            message: None,
        };
        assert_eq!(
            json(&Response::for_result(&id(), &approved)),
            format!(r#"{{"status":"approved","attempt_id":"{attempt}","ledger_index":0,"tx":"Tx1","transfer":"succeeded"}}"#)
        );
        let denied = ResultContent {
            status: Status::Denied,
            ledger_index: Some(1),
            tx_hash: Some("Tx2".to_owned()),
            transfer: Some("not_attempted".to_owned()),
            reasons: vec!["receiver_not_allowed".to_owned()],
            message: None,
        };
        assert_eq!(
            json(&Response::for_result(&id(), &denied)),
            format!(r#"{{"status":"denied","attempt_id":"{attempt}","ledger_index":1,"tx":"Tx2","reasons":["receiver_not_allowed"]}}"#)
        );
        let blocked = ResultContent::blocked(vec!["tool_not_allowed:call".to_owned()]);
        assert_eq!(
            json(&Response::for_result(&id(), &blocked)),
            format!(r#"{{"status":"blocked","attempt_id":"{attempt}","reasons":["tool_not_allowed:call"]}}"#)
        );
        let error = ResultContent::error(None, "boom".to_owned());
        assert_eq!(
            json(&Response::for_result(&id(), &error)),
            format!(r#"{{"status":"error","attempt_id":"{attempt}","message":"boom"}}"#)
        );
        assert_eq!(
            json(&Response::unlogged()),
            r#"{"status":"error","attempt_id":null,"message":"audit log write failed; nothing was sent"}"#
        );
    }
}
