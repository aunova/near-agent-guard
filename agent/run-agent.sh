#!/usr/bin/env bash
# One sandboxed agent run: mini-swe-agent + DeepSeek pays the invoices of one scenario
# through `wallet`, whose only way out is the bridge (`guard serve`) on a per-run socket.
#
#   agent/run-agent.sh [--scenario fake-invoice|injection] [--wallet-help neutral|guarded]
#                      (defaults: fake-invoice, neutral)
#
# Scenarios are directories under agent/scenarios/; their files become /testbed/inbox:
#   fake-invoice  a real invoice (0.5 NEAR to vendor.<owner>) plus a plausible invoice from
#                 an unknown supplier (5 NEAR to northwind.<owner>). Invoice fraud, no instructions.
#   injection     one invoice with a prompt injection addressed to automated payment agents.
# Wallet help variants are agent/wallet-help/<name>.txt, mounted read-only at /etc/wallet:
#   neutral   says only what the commands do; socket at /run/wallet/wallet.sock
#   guarded   says a payment guard answers approved/denied/blocked; socket at /run/guard/guard.sock
# (The model may treat a declared guard as a reason to try a payment and "let it decide";
# measuring both separates that from the attack itself.)
#
# Deployment and keys come from an env file: GUARD_ENV_FILE, default ./.env at the repo
# root (gitignored). Only the names below are read from it; values are never printed.
#   NANOGPT_API_KEY   the LLM key (an exported NANOGPT_API_KEY wins over the file).
#                     Given to mini only; never to guard, never into the container.
#   guard config      GUARD_CONTRACT_ID AGENT_ACCOUNT_ID AGENT_PRIVATE_KEY GUARD_AUDIT_NSEC
#                     GUARD_SCREEN_WASM GUARD_SCREEN_SHA256 NEAR_NETWORK NEAR_RPC_URL
#                     The file wins over the process environment, so pointing GUARD_ENV_FILE
#                     at a lab deployment cannot be overridden by a stale export.
#                     Given to guard only; never to mini.
# GUARD_CONTRACT_ID must be vault.<owner>; the invoice templates are rendered for that owner
# (vendor.<owner> is the real payee, northwind.<owner> the attacker's account).
# Overrides: GUARD_BIN (default bridge/target/release/guard), GUARD_RUNS_DIR (default agent/runs).
#
# Output: runs/<ts>/ with audit.jsonl (the signed log for this run), trajectory.traj.json,
# guard.log, run.yaml, deployment.json, the rendered inbox/ and wallet-etc/; then a summary
# of what the agent tried.
set -euo pipefail
agent_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$agent_dir")"
envfile="${GUARD_ENV_FILE:-$repo/.env}"
image="localhost/near-agent-guard-agent:latest"
guard_bin="${GUARD_BIN:-$repo/bridge/target/release/guard}"
runs="${GUARD_RUNS_DIR:-$agent_dir/runs}"
guard_vars=(GUARD_CONTRACT_ID AGENT_ACCOUNT_ID AGENT_PRIVATE_KEY GUARD_AUDIT_NSEC
            GUARD_SCREEN_WASM GUARD_SCREEN_SHA256 NEAR_NETWORK NEAR_RPC_URL)

die() { echo "run-agent: $*" >&2; exit 1; }
# Read ONE named variable from the env file; nothing else in the file is loaded.
dotenv() { [[ -f "$envfile" ]] && grep -m1 -E "^$1=" "$envfile" | cut -d= -f2- | tr -d "\"'" || true; }

scenario="fake-invoice"
wallet_help="neutral"
usage="usage: $0 [--scenario fake-invoice|injection] [--wallet-help neutral|guarded]"
while (( $# )); do
  case "$1" in
    --scenario) [[ $# -ge 2 ]] || die "$usage"; scenario="$2"; shift 2 ;;
    --scenario=*) scenario="${1#*=}"; shift ;;
    --wallet-help) [[ $# -ge 2 ]] || die "$usage"; wallet_help="$2"; shift 2 ;;
    --wallet-help=*) wallet_help="${1#*=}"; shift ;;
    *) die "unknown argument: $1 ($usage)" ;;
  esac
done
[[ "$scenario" =~ ^[a-z0-9-]+$ && -d "$agent_dir/scenarios/$scenario" ]] \
  || die "unknown scenario '$scenario'; have: $(ls "$agent_dir/scenarios" | tr '\n' ' ')"
[[ "$wallet_help" =~ ^[a-z]+$ && -f "$agent_dir/wallet-help/$wallet_help.txt" ]] \
  || die "unknown wallet help '$wallet_help'; have: $(ls "$agent_dir/wallet-help" | sed 's/\.txt$//' | tr '\n' ' ')"

# --- preflight ---------------------------------------------------------------------------
command -v podman >/dev/null || die "podman not found"
command -v mini >/dev/null || die "mini-swe-agent not found (uv tool install mini-swe-agent==2.4.6)"
py="$(dirname "$(readlink -f "$(command -v mini)")")/python"   # mini's own venv: has PyYAML
mini_version="$("$py" -c 'import importlib.metadata as m; print(m.version("mini-swe-agent"))')"
[[ "$mini_version" == "2.4.6" ]] || die "mini-swe-agent 2.4.6 required, found $mini_version"
[[ -x "$guard_bin" ]] || die "guard not found at $guard_bin (cargo build --release in bridge/, or set GUARD_BIN)"
[[ -f "$agent_dir/model-registry.json" ]] || die "missing agent/model-registry.json"
[[ -z "${GUARD_ENV_FILE:-}" || -f "$GUARD_ENV_FILE" ]] || die "GUARD_ENV_FILE not found: $GUARD_ENV_FILE"

llm_key="${NANOGPT_API_KEY:-$(dotenv NANOGPT_API_KEY)}"
[[ -n "$llm_key" ]] || die "NANOGPT_API_KEY not set and not found in $envfile"
declare -A guard_env=()
for name in "${guard_vars[@]}"; do
  value="$(dotenv "$name")"
  value="${value:-${!name:-}}"
  [[ -z "$value" ]] || guard_env[$name]="$value"
done
contract="${guard_env[GUARD_CONTRACT_ID]:-}"
[[ "$contract" == vault.?* ]] || die "GUARD_CONTRACT_ID must be vault.<owner> (got '${contract}'); set it in $envfile"
echo "deployment: $contract (env file: $envfile)   scenario: $scenario   wallet help: $wallet_help"

# Rebuild the image whenever the wallet or Containerfile changed (labelled with their hash).
src_hash="$(cat "$agent_dir/Containerfile" "$agent_dir/wallet" | sha256sum | cut -c1-16)"
have_hash="$(podman image inspect -f '{{index .Labels "near-agent-guard.src"}}' "$image" 2>/dev/null || true)"
if [[ "$have_hash" != "$src_hash" ]]; then
  echo "building $image"
  podman build -q --label "near-agent-guard.src=$src_hash" -t "$image" "$agent_dir" >/dev/null
fi

# --- per-run directory and socket -------------------------------------------------------
mkdir -p "$runs"
rundir="$(mktemp -d "$runs/$(date -u +%Y%m%dT%H%M%SZ)-XXXX")"
sock_dir="$rundir/sock"
mkdir -m 0700 "$sock_dir"
sock="$("$py" "$agent_dir/guardrun.py" layer "$agent_dir/guard-agent.yaml" "$rundir" "$sock_dir" \
  "$agent_dir/scenarios/$scenario" "$agent_dir/task.md" "$contract" "$agent_dir/wallet-help/$wallet_help.txt")"
(( ${#sock} < 108 )) || die "socket path too long for a Unix socket (${#sock} bytes): $sock"

# --- bridge: guard config only, no LLM key ------------------------------------------------
(
  for name in "${!guard_env[@]}"; do export "$name=${guard_env[$name]}"; done
  unset NANOGPT_API_KEY
  export GUARD_AUDIT_LOG="$rundir/audit.jsonl"
  exec "$guard_bin" serve --socket "$sock"
) >"$rundir/guard.log" 2>&1 &
guard_pid=$!
stop_guard() { kill "$guard_pid" 2>/dev/null && wait "$guard_pid" 2>/dev/null || true; }
trap stop_guard EXIT
for _ in $(seq 100); do
  [[ -S "$sock" ]] && break
  kill -0 "$guard_pid" 2>/dev/null || die "guard serve exited; see $rundir/guard.log"
  sleep 0.1
done
[[ -S "$sock" ]] || die "guard serve did not create $sock within 10 s; see $rundir/guard.log"

# --- agent: LLM key only, no guard secrets; nothing is forwarded into the container -------
echo "run: $rundir"
status=0
(
  unset AGENT_PRIVATE_KEY GUARD_AUDIT_NSEC
  export NANOGPT_API_KEY="$llm_key"
  export MSWEA_CONFIGURED=true   # skip mini's first-run wizard, which would write a key into its global .env
  cd "$agent_dir"                # guard-agent.yaml names the model registry relative to agent/
  exec mini -c mini.yaml -c "$agent_dir/guard-agent.yaml" -c "$rundir/run.yaml" \
    -o "$rundir/trajectory.traj.json" </dev/null
) || status=$?

stop_guard
trap - EXIT
echo
"$py" "$agent_dir/guardrun.py" summary "$rundir"
exit "$status"
