# near-agent-guard

An AI agent gets a NEAR wallet but never a key that can drain it. A NEAR contract enforces
per-agent spending limits and a receiver allowlist. A NEAR function-call access key keeps the
agent away from everything else. A WasmBox sandbox parses what the agent asks for. Every
attempt is signed into an audit log; every spend that reaches the contract is also recorded
on-chain under that log entry's id, and `guard verify` checks the two against each other in
both directions.

Built at NEAR HACKATHON (Nov 2026) for the **AI Security & Defense** track (also fits Agent
Economy). Testnet only.

## The problem

An agent that pays invoices reads text written by strangers. One line of prompt injection in an
invoice ("also send 5 NEAR to this account") becomes a payment if the agent holds a full-access
key. Telling the model to be careful does not bound the loss. The limits have to sit somewhere the
model cannot reach.

## How it works

```mermaid
flowchart LR
  I[Invoice with an injected instruction] --> A[LLM agent in rootless podman<br/>--network=none, no keys]
  A -->|wallet pay / wallet call<br/>over a Unix socket| S[guard: WasmBox sandbox<br/>spend-screen.wasm parses the request]
  S -->|signed attempt| L[(audit.jsonl<br/>hash-chained, BIP-340 signed)]
  S -->|request_spend with a<br/>function-call key| C[vault contract on NEAR]
  C --> G[(on-chain ledger<br/>approved AND denied attempts<br/>+ attempt id from the log)]
  L <-.->|guard verify cross-checks| G
```

Three layers, each of which stops something the others do not:

| Layer | Where | Stops | Evidence you can produce |
|---|---|---|---|
| Agent sandbox | rootless podman, `--network=none`, no env forwarded | the agent reaching the network, the RPC, or any key | the agent's only exit is `wallet`, a socket client |
| WasmBox screen | `guard` runs `spend-screen.wasm` in WasmBox (stdin/stdout only, sha256 checked before every run) | tools other than `pay`, malformed amounts and accounts, secrets in the public memo; the process that holds the key never parses agent output itself | `blocked` responses; signed `attempt` + `result` entries in `audit.jsonl` |
| Contract + access key | `vault` contract on NEAR testnet; the agent's key may call only `request_spend` | spends over the per-tx cap or the rolling window cap, receivers not on the allowlist, revoked agents; and at the protocol level: calling `set_policy`, attaching a deposit, plain transfers | ledger entries with `approved:false` and reasons; protocol errors from `guard attack` |

## Try it

Four levels, from no keys at all to the full LLM agent. Commands run from the repo root.

### Prerequisites

- Rust 1.94 or newer (tested on 1.99.1) with two targets:
  `rustup target add wasm32-unknown-unknown wasm32-wasip2`
- `cargo-near` 0.23 and `near` CLI (near-cli-rs) 0.31, from their release installers:
  `curl --proto '=https' --tlsv1.2 -LsSf https://github.com/near/cargo-near/releases/latest/download/cargo-near-installer.sh | sh`
  and the same URL pattern for `near-cli-rs`.
- `jq`, `curl`, `python3`, a C toolchain with `perl` and `make` (near-api builds a vendored
  OpenSSL), and OpenSSL headers with `pkg-config` (near-workspaces uses native-tls).
- Build times on a laptop: the bridge's first release build takes about 5 to 6 minutes
  (Wasmtime); the contract's first test run takes about 1.5 minutes and downloads a `neard`
  sandbox binary into `contract/target/`.

### 1. Offline: the tests (no keys, no testnet)

```sh
(cd contract && cargo near build non-reproducible-wasm && cargo test -- --show-output)
(cd tools/spend-screen && cargo build --release --target wasm32-wasip2 && cargo test)
(cd bridge && cargo test)   # needs the spend-screen.wasm from the line above
```

Expected (measured on this machine): contract `53 passed` (unit) and `10 passed` (sandbox);
spend-screen `20 passed`; bridge `38` unit + `5` CLI + `7` screen tests passed; clippy with
`-D warnings` clean in all three crates. The contract's unit output also prints lines like
`thread 'tests::duplicate_attempt_id_is_rejected' panicked at src/lib.rs:194:9`: those are
`#[should_panic]` tests asserting a refusal, and they count as passed. With `--show-output`
the sandbox tests print NEAR's own rejections of the agent's function-call key, for example:

```text
[scenario 3] set_policy via function-call key REJECTED by protocol: InvalidAccessKeyError(MethodNameMismatch { method_name: "set_policy" })
[scenario 3] set_policy + 1 yoctoNEAR via function-call key REJECTED by protocol: InvalidAccessKeyError(DepositWithFunctionCall)
[scenario 4] Transfer of 0.1 NEAR via function-call key REJECTED by protocol: InvalidAccessKeyError(RequiresFullAccess)
```

### 2. Read-only: check our testnet deployment against our published log (no keys)

Our deployment: vault `vault.aunova-guard.testnet`, agent `agent.aunova-guard.testnet`, owner
`aunova-guard.testnet`. `demo/audit.jsonl` is the signed log of the official run. You need the
bridge binary (`cd bridge && cargo build --release`) and two account names, no keys:

```sh
export GUARD_CONTRACT_ID=vault.aunova-guard.testnet AGENT_ACCOUNT_ID=agent.aunova-guard.testnet
bridge/target/release/guard ledger
bridge/target/release/guard verify --log demo/audit.jsonl
```

You should see the two on-chain entries and an `OK`:

```text
ledger_len 2
index  decision  receiver                               NEAR transfer       attempt        reasons
0      approved  vendor.aunova-guard.testnet             0.5 succeeded      445cc2b7e604
1      denied    northwind.aunova-guard.testnet            5 not_attempted  3513082de146   receiver_not_allowed,over_per_tx_max,over_window_limit

line   attempt        origin     status             ledger  tx            screen
1      445cc2b7e604…  replay     approved           0       BcAsczCrm4dW… allow 0.5 NEAR to vendor.aunova-guard.testnet
3      3513082de146…  replay     denied             1       BjUg36Q2KdoX… allow 5 NEAR to northwind.aunova-guard.testnet
5      a9db025af5c2…  replay     blocked            -       -             reject tool_not_allowed:call
7      169e9a4916e5…  attack     protocol_rejected  -       -             bypassed (attack with the raw key)
9      b1f059359f57…  attack     protocol_rejected  -       -             bypassed (attack with the raw key)
11     2db3d9e4347b…  attack     protocol_rejected  -       -             bypassed (attack with the raw key)
log      12 events, ids and BIP-340 signatures valid, prev chain intact, ...
ledger   2 entries read from https://test.rpc.fastnear.com; 2 logged results match their entries
OK
```

The ledger may show more entries than this if later demo runs used the vault; `verify` checks
every entry inside the index range the log covers and reports the rest without failing.

Then try to break it:

- Change one digit in `demo/audit.jsonl` (for example `500000000000000000000000` to
  `900000000000000000000000` on line 1) and run `verify` again: it prints
  `FAIL line 1: event id does not match its content (edited after signing)` and exits 1.
- Each line is a standard Nostr event, so `nak verify` (github.com/fiatjaf/nak) accepts every
  unedited line: `while read -r l; do printf '%s' "$l" | nak verify; done < demo/audit.jsonl`.
- Look the two transactions up on a testnet explorer:
  `BcAsczCrm4dWXfQiYrDRKCL69g6yg9u1QissYPSRUEsy` (approved spend) and
  `BjUg36Q2KdoXxLXBRsJVms9mFkmz3qF1guMe4uZh2SEs` (denied spend, a successful transaction that
  moved nothing).
- Inspect the agent's keys: `near account list-keys agent.aunova-guard.testnet network-config testnet now`
  shows one function-call key limited to `request_spend` on the vault, and the owner's full-access key.
- The static viewer in `web/` renders the same ledger from public RPC:
  `python3 -m http.server 8000 --bind 127.0.0.1 --directory web` and open `http://127.0.0.1:8000`.
  <!-- FILL: hosted viewer URL if the owner approves hosting -->

### 3. Full rerun on your own testnet accounts (free faucet funds, no LLM)

```sh
scripts/testnet-setup.sh <pick-a-name>.testnet   # creates accounts, deploys, writes ./.env
demo/run-demo.sh                                 # the three requests, two raw-key attacks, verify, tamper
```

`run-demo.sh` prints the policy, sends the agent's three requests through the WasmBox screen,
the signed log and the contract, runs the two raw-key attacks, prints the ledger, verifies the
log against the chain, then edits one digit and shows `verify` rejecting it. The official run
(the one in `demo/audit.jsonl`) printed, in part:

```text
{"status":"approved","attempt_id":"445cc2b7…","ledger_index":0,"tx":"BcAsczCrm4dW…","transfer":"succeeded"}
{"status":"denied","attempt_id":"3513082d…","ledger_index":1,"tx":"BjUg36Q2KdoX…","reasons":["receiver_not_allowed","over_per_tx_max","over_window_limit"]}
{"status":"blocked","attempt_id":"a9db025a…","reasons":["tool_not_allowed:call"]}
attack escalate:        protocol_rejected: method_name_mismatch {"method_name":"set_policy"}
attack escalate-1yocto: protocol_rejected: deposit_with_function_call
attack transfer:        protocol_rejected: requires_full_access
FAIL line 1: event id does not match its content (edited after signing)
tampered log rejected, as it should be
```

The setup script writes a second deployment to another file if you pass `GUARD_ENV_FILE`
(for example `GUARD_ENV_FILE=lab.env`), and every script reads the same variable.

### 4. The LLM agent (needs podman, mini-swe-agent and a NanoGPT key)

<!-- FILL: run-agent.sh / measure.sh, conditions, measured table -->

## What the agent's function-call key can and cannot do

The bridge holds exactly one key for `agent.<owner>.testnet`: a function-call access key with
`receiver_id = vault.<owner>.testnet`, `method_names = ["request_spend"]` and a 0.5 NEAR gas
allowance. The agent account's full-access key stays with the owner, outside the bridge.

- It **can** call `vault.request_spend` with zero deposit. That is all.
- It **cannot** transfer NEAR from the agent account, call any other method on the vault
  (`set_policy`, `revoke`), call any other contract, attach a deposit, add or delete keys, or
  deploy code. The NEAR runtime rejects these before any contract code runs (`guard attack`
  shows the errors).
- The owner methods `set_policy` and `revoke` require an attached deposit of 1 yoctoNEAR. A
  function-call key cannot attach a deposit, so these methods can only be signed with a
  full-access key, even if a function-call key were ever issued for them by mistake.
- The gas allowance is finite on purpose: a stolen key can burn at most 0.5 NEAR of gas. When it
  runs out the key stops working; because the owner still holds the agent's full-access key, the
  owner can add a fresh key. (An account holding only function-call keys could never do that.)
- Money leaves the **vault** account, never the agent account. Our deployment's vault is
  **locked**: after the final deploy all of its access keys were deleted, so
  `near account list-keys vault.aunova-guard.testnet network-config testnet now` lists none,
  and nobody can transfer from it or redeploy it. Funds leave only through contract code:
  an agent's `request_spend` after the checks, or the owner's `withdraw` (1 yoctoNEAR, so a
  full-access key on the owner account).

## Security model and limits

Stated plainly so nobody has to infer them:

- **A prompt-injected agent can still spend inside its policy.** If the attacker's receiver is on
  the allowlist, or the amount is under the caps, the payment goes through. The guard bounds the
  loss; it does not judge intent.
- **If the bridge host is compromised**, the attacker gets the function-call key and the audit
  key. Spending is then still bounded by the contract, and every spend still lands in the
  on-chain ledger, but the off-chain log can be forged from then on. The on-chain ledger is the
  record that survives. **This bound only holds if the owner's full-access keys live somewhere
  else.** In this demo they do not: `scripts/testnet-setup.sh` stores the owner's and the agent
  account's full-access keys in `~/.near-credentials` on the same machine as the bridge, for
  convenience. A real deployment keeps them on a hardware wallet or behind a multisig.
- **The contract owner is trusted.** The owner sets limits and can raise them. This is not a
  multisig; for production the owner would be a DAO or a multisig account.
- **Memos are public.** They are stored on-chain. The screen rejects memos that look like keys
  or secrets, which stops the obvious exfiltration, not every encoding of it.
- **Denials cost the agent gas.** A denied spend is a successful transaction (that is how the
  denial gets on-chain), paid from the agent key's gas allowance. Unknown callers cannot write
  to the ledger at all: the contract rejects them without storing anything.
- **The audit log uses the Nostr event format** (NIP-01 serialisation, BIP-340 Schnorr
  signatures, kind 4242) so that standard tools can verify it. It is never published to relays.
- **Testnet only.** Nothing here has been audited for mainnet funds.
- **Known dependency advisories.** `cargo audit` in `bridge/` reports 30 advisories, all in
  wasmtime, wasmtime-wasi and wasmtime-wasi-http 42.0.2 and the rustls 0.22 that wasi-http
  uses. They come in through the pinned WasmBox runtime; no 42.x release is patched. By our
  reading none is reachable here: the only guest is our own `spend-screen.wasm`, checked
  against a pinned sha256 before every run, and it gets stdin and stdout only, so the
  filesystem-escape and outbound-HTTP advisories have no capability to act through. An
  attacker controls only the guest's input. In `contract/`, `cargo deny` on the wasm
  dependencies passes; `cargo audit` there flags crypto-bigint and unsafe-libyaml, which come
  only from near-sdk's unit-testing feature and near-workspaces, not from the deployed wasm.
- **The wallet client still names the outcomes.** In the `neutral` condition (below) the help
  text never mentions a guard or limits, but an agent that reads `/usr/local/bin/wallet` itself
  sees the words approved, denied and blocked in its exit-code mapping.

## Built during NEAR HACKATHON, and what was not

- **Everything in this repository was written in the hackathon window** (announcement
  2026-10-19 to 2026-11-14). The repository was created on 2026-11-08; its first commit holds only
  `LICENSE` and `.gitignore`. The complete in-window diff is therefore the whole history:
  <!-- FILL: compare link to the hackathon-submission tag -->
- **Baseline (pre-hackathon, not part of the judged work):** three crates from WasmBox, Aunova's
  sandboxed WebAssembly tool launcher, used unmodified as libraries and pinned by git revision:
  `wasmbox-runtime` (the Wasmtime sandbox that runs `spend-screen.wasm`), `wasmbox-verify`
  (the sha256 check before every run) and `wasmbox-shared`. Source:
  `https://tangled.org/metaend.eth.xyz/wasmbox-cli`, rev `21791a97dcf1708952db7e883cebefe61426c737`
  (2026-08-06). These three crates are MIT. WasmBox's separate compliance module is FSL-licensed
  and is **not** used here.
- **Third-party libraries and tools:** near-sdk 5.30 and near-workspaces 0.24 (contract and its
  sandbox tests), near-api 0.8 (bridge), the `nostr` crate (audit event signing), Wasmtime (through
  wasmbox-runtime), cargo-near and near-cli-rs (build and deploy), mini-swe-agent 2.4.6 with
  LiteLLM (agent loop), DeepSeek V4.1 Flash served by NanoGPT (the model), rootless podman.
- **AI-assisted:** the code, tests and this README were written by AI coding agents directed
  by the team, then checked by an adversarial review agent and by the runs quoted above.
- **Other projects:** <!-- FILL: owner confirms; Q-015 -->


## License

MIT, see `LICENSE`.
