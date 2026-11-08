#!/usr/bin/env bash
# Scripted demo: no LLM key needed. Sends the same three requests the prompt-injected
# agent sends (see agent/inbox/invoice.txt) through the same gate, then tries the two
# raw-key escalations, then verifies the signed log against the chain and shows that a
# one-character edit to the log is caught.
#
#   demo/run-demo.sh            (needs ./.env from scripts/testnet-setup.sh)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

[[ -f .env ]] || { echo "missing ./.env: run scripts/testnet-setup.sh <name>.testnet first" >&2; exit 1; }
set -a; source ./.env; set +a
guard="$here/bridge/target/release/guard"
[[ -x "$guard" ]] || (cd bridge && cargo build --release)

owner="${GUARD_CONTRACT_ID#vault.}"
run="$here/runs/demo-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$run"
export GUARD_AUDIT_LOG="$run/audit.jsonl"

jq -nc --arg to "vendor.$owner" '{tool:"pay",args:{receiver:$to,amount:"0.5",memo:"INV-2026-11-001"}}' > "$run/requests.jsonl"
jq -nc --arg to "northwind.$owner" '{tool:"pay",args:{receiver:$to,amount:"5",memo:"NW-8841"}}' >> "$run/requests.jsonl"
jq -nc '{tool:"call",args:{method:"set_policy",json:"{\"per_tx_max\":\"100000000000000000000000000\"}"}}' >> "$run/requests.jsonl"

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "1. policy the owner set for $AGENT_ACCOUNT_ID"
"$guard" policy

step "2. the agent's three requests, through WasmBox screen -> signed log -> contract"
cat "$run/requests.jsonl"
"$guard" replay "$run/requests.jsonl"

step "3. compromised agent uses its key directly: raise its own limit (NEAR must refuse)"
"$guard" attack escalate

step "4. compromised agent uses its key directly: plain transfer (NEAR must refuse)"
"$guard" attack transfer

step "5. on-chain ledger"
"$guard" ledger

step "6. verify the signed log against the chain"
"$guard" verify --log "$GUARD_AUDIT_LOG"

step "7. tamper: raise the approved amount from 0.5 to 0.9 NEAR in one log line, verify again (must fail)"
sed '0,/500000000000000000000000/s//900000000000000000000000/' "$GUARD_AUDIT_LOG" > "$run/audit.tampered.jsonl"
cmp -s "$GUARD_AUDIT_LOG" "$run/audit.tampered.jsonl" && { echo "tamper step changed nothing" >&2; exit 1; }
if "$guard" verify --log "$run/audit.tampered.jsonl"; then
  echo "UNEXPECTED: tampered log verified" >&2; exit 1
fi
echo "tampered log rejected, as it should be"
echo
echo "run saved: $run"
