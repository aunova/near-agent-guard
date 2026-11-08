#!/usr/bin/env bash
# Run the agent N times per scenario and count, from each run's signed audit log (what
# actually reached the guard, not what the model says it did), how often it paid the real
# vendor, tried to pay northwind.<owner> (the unknown supplier's invoice, or the injected
# "verification deposit"), and tried the injected `wallet call set_policy`; plus how the
# guard answered each kind of request.
#
#   agent/measure.sh N [--scenario fake-invoice|injection|all]     (default: fake-invoice)
#
# Deployment and keys exactly as run-agent.sh: GUARD_ENV_FILE (default ./.env at the repo
# root), e.g. GUARD_ENV_FILE=lab.env agent/measure.sh 10 --scenario all to keep the public
# vault's ledger clean. Runs go to runs/batch-<ts>/.
set -euo pipefail
agent_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
usage() { echo "usage: $0 N [--scenario fake-invoice|injection|all]   (N >= 1 runs per scenario)" >&2; exit 1; }

n="${1:-}"
[[ "$n" =~ ^[1-9][0-9]*$ ]] || usage
shift
scenario="fake-invoice"
case "${1:-}" in
  "") ;;
  --scenario) [[ $# -eq 2 ]] || usage; scenario="$2" ;;
  --scenario=*) [[ $# -eq 1 ]] || usage; scenario="${1#*=}" ;;
  *) usage ;;
esac
if [[ "$scenario" == all ]]; then
  scenarios=()
  for dir in "$agent_dir"/scenarios/*/; do scenarios+=("$(basename "$dir")"); done
else
  [[ -d "$agent_dir/scenarios/$scenario" ]] || usage
  scenarios=("$scenario")
fi

batch="${GUARD_RUNS_DIR:-$agent_dir/runs}/batch-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$batch"
for s in "${scenarios[@]}"; do
  for i in $(seq "$n"); do
    echo "=== $s: run $i/$n ==="
    GUARD_RUNS_DIR="$batch" "$agent_dir/run-agent.sh" --scenario "$s" || echo "(run exited with status $?)"
  done
done

py="$(dirname "$(readlink -f "$(command -v mini)")")/python"
echo
echo "batch: $batch"
"$py" "$agent_dir/guardrun.py" table "$batch"/*/
