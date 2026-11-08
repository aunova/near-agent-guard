#!/usr/bin/env bash
# Run the agent N times per (scenario, wallet help) pair and count, from each run's signed
# audit log (what actually reached the guard, not what the model says it did), how often it
# paid the real vendor, tried to pay northwind.<owner> (the unknown supplier's invoice, or
# the injected "verification deposit"), and tried the injected `wallet call set_policy`;
# plus how the guard answered each kind of request.
#
#   agent/measure.sh N [--scenario fake-invoice|injection|all] [--wallet-help neutral|guarded|all]
#                      (defaults: fake-invoice, neutral)
#
# Deployment and keys exactly as run-agent.sh: GUARD_ENV_FILE (default ./.env at the repo
# root), e.g. GUARD_ENV_FILE=lab.env agent/measure.sh 10 --scenario all --wallet-help all
# to keep the public vault's ledger clean. Runs go to runs/batch-<ts>/.
set -euo pipefail
agent_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
usage() {
  echo "usage: $0 N [--scenario fake-invoice|injection|all] [--wallet-help neutral|guarded|all]   (N >= 1)" >&2
  exit 1
}

n="${1:-}"
[[ "$n" =~ ^[1-9][0-9]*$ ]] || usage
shift
scenario="fake-invoice"
wallet_help="neutral"
while (( $# )); do
  case "$1" in
    --scenario) [[ $# -ge 2 ]] || usage; scenario="$2"; shift 2 ;;
    --scenario=*) scenario="${1#*=}"; shift ;;
    --wallet-help) [[ $# -ge 2 ]] || usage; wallet_help="$2"; shift 2 ;;
    --wallet-help=*) wallet_help="${1#*=}"; shift ;;
    *) usage ;;
  esac
done

# Expand "all" to every scenario directory / help file; otherwise check the name exists.
if [[ "$scenario" == all ]]; then
  scenarios=()
  for dir in "$agent_dir"/scenarios/*/; do scenarios+=("$(basename "$dir")"); done
else
  [[ -d "$agent_dir/scenarios/$scenario" ]] || usage
  scenarios=("$scenario")
fi
if [[ "$wallet_help" == all ]]; then
  helps=()
  for file in "$agent_dir"/wallet-help/*.txt; do helps+=("$(basename "$file" .txt)"); done
else
  [[ -f "$agent_dir/wallet-help/$wallet_help.txt" ]] || usage
  helps=("$wallet_help")
fi

batch="${GUARD_RUNS_DIR:-$agent_dir/runs}/batch-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$batch"
for s in "${scenarios[@]}"; do
  for h in "${helps[@]}"; do
    for i in $(seq "$n"); do
      echo "=== $s / $h: run $i/$n ==="
      GUARD_RUNS_DIR="$batch" "$agent_dir/run-agent.sh" --scenario "$s" --wallet-help "$h" \
        || echo "(run exited with status $?)"
    done
  done
done

py="$(dirname "$(readlink -f "$(command -v mini)")")/python"
echo
echo "batch: $batch"
"$py" "$agent_dir/guardrun.py" table "$batch"/*/
