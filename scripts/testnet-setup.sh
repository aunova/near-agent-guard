#!/usr/bin/env bash
# Create your own near-agent-guard deployment on NEAR TESTNET (free faucet funds).
#
#   scripts/testnet-setup.sh <owner>.testnet
#
# Creates <owner>.testnet via the faucet, plus vault./agent./vendor./northwind. sub-accounts
# (northwind plays the unknown supplier behind the fake invoice), deploys the contract to
# vault.<owner>, sets the demo policy, gives the agent account a FUNCTION-CALL key
# (vault.request_spend only), and writes the env file: ./.env, or $GUARD_ENV_FILE if set
# (both gitignored; a second deployment such as a lab one goes in its own file).
# Accounts that already exist are reused, so a half-finished run can be re-run.
#
# Key custody: the owner's and the agent's FULL-ACCESS keys go to ~/.near-credentials
# (near CLI legacy keychain) and stay there. Only the function-call key and the audit
# signing key are written to ./.env, which is what the bridge reads. Nothing is printed.
# Testnet only: this script never touches mainnet.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

owner="${1:-}"
[[ "$owner" =~ ^[a-z0-9]([a-z0-9_-]*[a-z0-9])?\.testnet$ ]] || {
  echo "usage: scripts/testnet-setup.sh <new-name>.testnet   (top-level testnet name, not yet taken)" >&2
  exit 2
}
env_file="${GUARD_ENV_FILE:-.env}"
[[ ! -e "$env_file" ]] || { echo "refusing: $env_file already exists; move it aside or set GUARD_ENV_FILE" >&2; exit 1; }
for bin in near cargo jq; do
  command -v "$bin" >/dev/null || { echo "missing: $bin (see README, Prerequisites)" >&2; exit 1; }
done
cargo near --version >/dev/null 2>&1 || { echo "missing: cargo-near (see README, Prerequisites)" >&2; exit 1; }

vault="vault.$owner" agent="agent.$owner" vendor="vendor.$owner" attacker="northwind.$owner"
net=(network-config testnet)
rpc="${NEAR_RPC_URL:-https://rpc.testnet.near.org}"

exists() {
  curl -s -m 15 "$rpc" -H 'Content-Type: application/json' -d \
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"view_account\",\"finality\":\"final\",\"account_id\":\"$1\"}}" \
    | jq -e '.result.amount' >/dev/null
}

step() { printf '\n== %s\n' "$*"; }

step "owner $owner (faucet)"
if exists "$owner"; then echo "exists, reusing"; else
  near account create-account sponsor-by-faucet-service "$owner" autogenerate-new-keypair \
    save-to-legacy-keychain "${net[@]}" create >/dev/null
  echo "created"
fi

sub() { # name amount
  if exists "$1"; then echo "$1 exists, reusing"; return; fi
  near account create-account fund-myself "$1" "$2" autogenerate-new-keypair save-to-legacy-keychain \
    sign-as "$owner" "${net[@]}" sign-with-legacy-keychain send >/dev/null
  echo "$1 created with $2"
}
step "sub-accounts"
sub "$vault" '5 NEAR'
sub "$agent" '1 NEAR'
sub "$vendor" '0.1 NEAR'
sub "$attacker" '0.1 NEAR'

step "build contract"
(cd contract && cargo near build non-reproducible-wasm >/dev/null)
wasm="contract/target/near/agent_guard.wasm"
ls -l "$wasm"

step "deploy + init on $vault"
near contract deploy "$vault" use-file "$wasm" with-init-call new json-args "{\"owner\":\"$owner\"}" \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' "${net[@]}" sign-with-legacy-keychain send >/dev/null
echo "deployed"

step "policy for $agent: 1 NEAR per tx, 2 NEAR per 24 h, receiver $vendor only"
near contract call-function as-transaction "$vault" set_policy json-args \
  "{\"agent\":\"$agent\",\"per_tx_max\":\"1000000000000000000000000\",\"window_limit\":\"2000000000000000000000000\",\"window_secs\":86400,\"allowed_receivers\":[\"$vendor\"]}" \
  prepaid-gas '30 Tgas' attached-deposit '1 yoctoNEAR' sign-as "$owner" "${net[@]}" sign-with-legacy-keychain send >/dev/null
echo "policy set"

step "function-call key for the bridge"
keydir="$HOME/.near-credentials/near-agent-guard-fc-$owner"
mkdir -p "$keydir" && chmod 700 "$keydir"
near account create-account fund-later use-auto-generation save-to-folder "$keydir" >/dev/null
keyfile="$(ls -t "$keydir"/*.json | head -1)"
pub="$(jq -r .public_key "$keyfile")"
near account add-key "$agent" grant-function-call-access --allowance '0.5 NEAR' \
  --contract-account-id "$vault" --function-names request_spend use-manually-provided-public-key "$pub" \
  "${net[@]}" sign-with-legacy-keychain send >/dev/null
echo "added $pub: only request_spend on $vault, 0.5 NEAR gas allowance"

step "spend-screen.wasm + bridge"
(cd tools/spend-screen && cargo build --release --target wasm32-wasip2 >/dev/null)
screen="$here/tools/spend-screen/target/wasm32-wasip2/release/spend_screen.wasm"
screen_sha="$(sha256sum "$screen" | cut -d' ' -f1)"
(cd bridge && cargo build --release >/dev/null)
guard="$here/bridge/target/release/guard"

step "write $env_file (mode 600)"
umask 077
nsec_line="$("$guard" keygen | grep -m1 '^GUARD_AUDIT_NSEC=')"
{
  echo "# Local demo config written by scripts/testnet-setup.sh. Gitignored. Never commit."
  echo "NEAR_NETWORK=testnet"
  echo "GUARD_CONTRACT_ID=$vault"
  echo "AGENT_ACCOUNT_ID=$agent"
  echo "AGENT_PRIVATE_KEY=$(jq -r .private_key "$keyfile")"
  echo "$nsec_line"
  echo "GUARD_SCREEN_WASM=$screen"
  echo "GUARD_SCREEN_SHA256=$screen_sha"
} > "$env_file"
unset nsec_line
echo "done. Next: GUARD_ENV_FILE=$env_file demo/run-demo.sh    (then optionally scripts/lock-vault.sh)"
