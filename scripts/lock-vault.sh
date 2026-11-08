#!/usr/bin/env bash
# Lock a vault account on NEAR TESTNET: delete every access key it has, so nobody can transfer
# from it or redeploy it. Afterwards funds leave only through contract code: an agent's
# request_spend that passes the policy, or the owner's withdraw (1 yoctoNEAR, so a full-access
# key on the OWNER account). This is irreversible: a locked account can never be redeployed.
#
#   scripts/lock-vault.sh vault.<owner>.testnet contract/target/near/agent_guard.wasm --yes
#
# Before deleting anything it proves two things, and refuses if either fails:
#   1. the code on-chain is exactly the given wasm (code_hash = base58(sha256(wasm)));
#   2. the owner's recovery path works on that code: a 0.01 NEAR withdraw to the owner.
# Signs with the vault's and the owner's full-access keys from the near CLI legacy keychain.
set -euo pipefail

vault="${1:-}" wasm="${2:-}" confirm="${3:-}"
[[ "$vault" =~ ^vault\.([a-z0-9._-]+\.testnet)$ && -f "$wasm" && "$confirm" == "--yes" ]] || {
  echo "usage: scripts/lock-vault.sh vault.<owner>.testnet <path/to/agent_guard.wasm> --yes   (irreversible)" >&2
  exit 2
}
owner="${BASH_REMATCH[1]}"
rpc="${NEAR_RPC_URL:-https://rpc.testnet.near.org}"
net=(network-config testnet)

query() { # request_type -> .result JSON, or exit non-zero on any RPC error
  curl -sS -m 20 "$rpc" -H 'Content-Type: application/json' -d \
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"query\",\"params\":{\"request_type\":\"$1\",\"finality\":\"final\",\"account_id\":\"$vault\"}}" \
    | jq -ec '.result // error("rpc error: \(.error // "no result")")'
}
key_count() {
  local r; r="$(query view_access_key_list)" || { echo "rpc failure reading keys" >&2; return 1; }
  jq -e '.keys | if type == "array" then length else error("keys is not an array") end' <<<"$r"
}
public_keys() {
  local r; r="$(query view_access_key_list)" || return 1
  jq -er '.keys[].public_key' <<<"$r"
}

expected="$(python3 -c 'import hashlib,sys
a="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
n=int.from_bytes(hashlib.sha256(open(sys.argv[1],"rb").read()).digest(),"big"); s=""
while n: n,r=divmod(n,58); s=a[r]+s
print(s)' "$wasm")"
acct="$(query view_account)" || { echo "refusing: rpc failure reading $vault" >&2; exit 1; }
onchain="$(jq -r .code_hash <<<"$acct")"
echo "vault:          $vault"
echo "expected code:  $expected  ($wasm)"
echo "on-chain code:  $onchain"
[[ "$onchain" == "$expected" ]] || { echo "refusing: on-chain code is not this wasm" >&2; exit 1; }

before="$(key_count)" || { echo "refusing: cannot read access keys" >&2; exit 1; }
echo "access keys now: $before"
(( before > 0 )) || { echo "$vault already has 0 access keys (checked over RPC): locked."; exit 0; }

echo "proving the owner recovery path on this code: withdraw 0.01 NEAR to $owner"
out="$(near contract call-function as-transaction "$vault" withdraw json-args '{"amount":"10000000000000000000000"}' \
  prepaid-gas '30 Tgas' attached-deposit '1 yoctoNEAR' sign-as "$owner" "${net[@]}" sign-with-legacy-keychain send 2>&1 || true)"
grep -E 'Transaction ID|owner_withdraw|panicked|Error' <<<"$out" || true
grep -q '"event":"owner_withdraw"' <<<"$out" || { echo "refusing: withdraw did not emit owner_withdraw" >&2; exit 1; }

mapfile -t pubs < <(public_keys)
(( ${#pubs[@]} == before )) || { echo "refusing: key list changed or unreadable (${#pubs[@]} vs $before)" >&2; exit 1; }
printf 'deleting:        %s\n' "${pubs[@]}"
near account delete-keys "$vault" public-keys "$(IFS=,; echo "${pubs[*]}")" \
  "${net[@]}" sign-with-legacy-keychain send 2>&1 | grep -E 'Transaction ID|successfully|Error' || true

after="$(key_count)" || { echo "lock UNVERIFIED: rpc failure reading keys after delete" >&2; exit 1; }
echo "access keys left on $vault (checked over RPC): $after"
(( after == 0 )) || { echo "lock FAILED: keys remain" >&2; exit 1; }
echo "locked."
