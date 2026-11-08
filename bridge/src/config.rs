//! Environment configuration. Secrets arrive only through env vars and are never echoed: every
//! parse error for a secret is replaced by a fixed message.

use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use near_api::{AccountId, SecretKey};
use nostr::Keys;
use url::Url;
use zeroize::Zeroizing;

/// Audit log used when `GUARD_AUDIT_LOG` is unset.
const DEFAULT_AUDIT_LOG: &str = "./audit.jsonl";
/// near-api 0.8.7's own testnet default (`RPCEndpoint::testnet`).
const TESTNET_RPC: &str = "https://test.rpc.fastnear.com";
const MAINNET_REFUSAL: &str = "NEAR_NETWORK=mainnet refused: near-agent-guard is a testnet demo and never signs for mainnet";

/// The RPC endpoint, plus the only part of it that may appear in a message: an override URL can
/// carry an API key in its path, query or userinfo.
#[derive(Clone, Debug)]
pub struct Rpc {
    pub url: Url,
    pub label: String,
}

/// Reads `NEAR_NETWORK` (refusing mainnet) and `NEAR_RPC_URL`.
pub fn rpc_from_env() -> Result<Rpc> {
    match env::var("NEAR_NETWORK") {
        Ok(network) => check_network(&network)?,
        Err(env::VarError::NotPresent) => {}
        Err(env::VarError::NotUnicode(_)) => bail!("NEAR_NETWORK is not valid UTF-8"),
    }
    let url = match env::var("NEAR_RPC_URL") {
        Ok(raw) if !raw.is_empty() => {
            Url::parse(&raw).map_err(|_| anyhow!("NEAR_RPC_URL is not a valid URL"))?
        }
        Ok(_) | Err(env::VarError::NotPresent) => Url::parse(TESTNET_RPC)?,
        Err(env::VarError::NotUnicode(_)) => bail!("NEAR_RPC_URL is not valid UTF-8"),
    };
    if !matches!(url.scheme(), "http" | "https") {
        bail!("NEAR_RPC_URL must be an http or https URL");
    }
    Ok(Rpc {
        label: endpoint_label(&url),
        url,
    })
}

/// Only `testnet` (the default) is accepted.
fn check_network(name: &str) -> Result<()> {
    if name.eq_ignore_ascii_case("mainnet") {
        bail!(MAINNET_REFUSAL);
    }
    if name.is_empty() || name.eq_ignore_ascii_case("testnet") {
        return Ok(());
    }
    bail!("NEAR_NETWORK={name} is not supported: this demo runs on testnet only")
}

/// `scheme://host[:port]`, never the path, query or userinfo.
fn endpoint_label(url: &Url) -> String {
    let host = url.host_str().unwrap_or("unknown-host");
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

fn required(name: &str) -> Result<String> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) | Err(env::VarError::NotPresent) => bail!("{name} is not set"),
        Err(env::VarError::NotUnicode(_)) => bail!("{name} is not valid UTF-8"),
    }
}

/// A required NEAR account id from the environment.
pub fn account_from_env(name: &str) -> Result<AccountId> {
    required(name)?
        .parse::<AccountId>()
        .with_context(|| format!("{name} is not a valid NEAR account id"))
}

/// `AGENT_PRIVATE_KEY`, the agent's function-call key. Absent means nothing can be signed: the
/// gate still screens and logs, and answers screen-approved requests with an error.
pub fn agent_key_from_env() -> Result<Option<SecretKey>> {
    let raw = match env::var("AGENT_PRIVATE_KEY") {
        Ok(value) => Zeroizing::new(value),
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(env::VarError::NotUnicode(_)) => bail!("AGENT_PRIVATE_KEY is not valid UTF-8"),
    };
    if raw.is_empty() {
        return Ok(None);
    }
    if !raw.starts_with("ed25519:") {
        bail!("AGENT_PRIVATE_KEY must be an ed25519:<base58> function-call key");
    }
    raw.parse::<SecretKey>()
        .map(Some)
        .map_err(|_| anyhow!("AGENT_PRIVATE_KEY is not a valid ed25519 secret key"))
}

/// `GUARD_AUDIT_NSEC`, the key that signs every audit event.
pub fn audit_keys_from_env() -> Result<Keys> {
    let raw = Zeroizing::new(required("GUARD_AUDIT_NSEC")?);
    Keys::parse(&raw).map_err(|_| anyhow!("GUARD_AUDIT_NSEC is not a valid nsec1 (or hex) secret key"))
}

/// `GUARD_AUDIT_LOG`, defaulting to `./audit.jsonl`.
pub fn audit_log_from_env() -> PathBuf {
    env::var_os("GUARD_AUDIT_LOG")
        .filter(|path| !path.is_empty())
        .map_or_else(|| PathBuf::from(DEFAULT_AUDIT_LOG), PathBuf::from)
}

/// `GUARD_SCREEN_WASM` and its pinned `GUARD_SCREEN_SHA256` (64 hex chars, `sha256:` prefix
/// optional). The path is made absolute so the sandbox child does not depend on its cwd.
pub fn screen_pin_from_env() -> Result<(PathBuf, String)> {
    let wasm = PathBuf::from(required("GUARD_SCREEN_WASM")?);
    let wasm = std::path::absolute(&wasm)
        .with_context(|| format!("cannot resolve GUARD_SCREEN_WASM={}", wasm.display()))?;
    let pin = parse_sha256_pin(&required("GUARD_SCREEN_SHA256")?)?;
    Ok((wasm, pin))
}

/// Normalises a sha256 pin to 64 lowercase hex chars.
fn parse_sha256_pin(raw: &str) -> Result<String> {
    let hex = raw.strip_prefix("sha256:").unwrap_or(raw).to_ascii_lowercase();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("GUARD_SCREEN_SHA256 must be 64 hex characters (optionally prefixed sha256:)");
    }
    Ok(hex)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_is_refused_in_any_case() {
        for name in ["mainnet", "MAINNET", "Mainnet"] {
            let message = check_network(name).unwrap_err().to_string();
            assert!(message.contains("mainnet refused"), "{message}");
        }
    }

    #[test]
    fn testnet_and_empty_are_accepted_others_refused() {
        check_network("testnet").unwrap();
        check_network("TESTNET").unwrap();
        check_network("").unwrap();
        assert!(check_network("localnet").is_err());
        assert!(check_network("betanet").is_err());
    }

    #[test]
    fn endpoint_label_drops_path_query_and_userinfo() {
        let url = Url::parse("https://user:secret@rpc.example.com:8443/key/abc123?apikey=zzz").unwrap();
        assert_eq!(endpoint_label(&url), "https://rpc.example.com:8443");
        let url = Url::parse("https://test.rpc.fastnear.com").unwrap();
        assert_eq!(endpoint_label(&url), "https://test.rpc.fastnear.com");
    }

    #[test]
    fn sha256_pin_is_normalised_and_validated() {
        let hex = "7906AA6945F1C01D4E068C9F7C896534AA0363CCD7277D6CD70E9763FC075D32";
        assert_eq!(parse_sha256_pin(hex).unwrap(), hex.to_ascii_lowercase());
        assert_eq!(parse_sha256_pin(&format!("sha256:{hex}")).unwrap(), hex.to_ascii_lowercase());
        assert!(parse_sha256_pin("abc").is_err());
        assert!(parse_sha256_pin(&"g".repeat(64)).is_err());
        assert!(parse_sha256_pin(&format!("{hex}0")).is_err());
    }
}
