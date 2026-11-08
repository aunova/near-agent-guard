"use strict";

// ---- config -------------------------------------------------------------------------------
// Edit these, or override per visit with ?contract=…&agent=…&rpc=…  (?audit=<url> auto-loads a log).
const CONFIG = {
  contractId: "vault.aunova-agent-guard.testnet",
  agentId: "agent.aunova-agent-guard.testnet",
  rpcUrl: "https://rpc.testnet.near.org",
  explorer: "https://testnet.nearblocks.io",
  auditLog: "./audit.jsonl",
};
// -------------------------------------------------------------------------------------------

const params = new URLSearchParams(location.search);
const cfg = {
  ...CONFIG,
  contractId: params.get("contract") || CONFIG.contractId,
  agentId: params.get("agent") || CONFIG.agentId,
  rpcUrl: params.get("rpc") || CONFIG.rpcUrl,
};
const PAGE = 100; // get_ledger caps limit at 100
const YOCTO = 10n ** 24n;
const ZERO_ID = "0".repeat(64);

let ledger = []; // LedgerEntry[] indexed by entry.index
let audit = null; // parsed audit log, kept so a ledger refresh re-runs the cross-check

// ---- DOM helpers ----------------------------------------------------------------------------
// Every ledger and audit field (receiver, memo, reasons, raw_request, ...) is written or
// influenced by the agent, so it is attacker-controlled: render with DOM nodes and textContent
// only, never innerHTML or HTML strings.
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "text") node.textContent = String(value);
    else if (key === "class") node.className = value;
    else node.setAttribute(key, String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
const $ = (id) => document.getElementById(id);

function setStatus(text, kind = "") {
  const node = $("status");
  node.textContent = text;
  node.className = `status ${kind}`;
}

function accountLink(account) {
  const name = String(account);
  return el("a", { href: `${cfg.explorer}/address/${encodeURIComponent(name)}`, target: "_blank", rel: "noopener", text: name });
}

function txLink(hash) {
  const value = String(hash);
  return el("a", { href: `${cfg.explorer}/txns/${encodeURIComponent(value)}`, target: "_blank", rel: "noopener", class: "mono", text: `${value.slice(0, 8)}…` });
}

function badge(text, kind) {
  return el("span", { class: `badge ${kind}`, text });
}

const shortId = (id) => `${String(id).slice(0, 10)}…`;

// ---- formatting (integers only: amounts are yoctoNEAR decimal strings) ---------------------
const SHOWN_DECIMALS = 4;
const DISPLAY_STEP = 10n ** BigInt(24 - SHOWN_DECIMALS);

// NEAR rounded DOWN to SHOWN_DECIMALS (BigInt only, no float); the exact yocto value is in `title`.
function near(yocto) {
  let value;
  try {
    value = BigInt(yocto);
  } catch {
    return el("span", { text: `${yocto} (not an integer)` });
  }
  const shown = value / DISPLAY_STEP; // u128 amounts are never negative, so truncation is floor
  const whole = shown / 10n ** BigInt(SHOWN_DECIMALS);
  const frac = (shown % 10n ** BigInt(SHOWN_DECIMALS)).toString().padStart(SHOWN_DECIMALS, "0").replace(/0+$/, "");
  return el("span", { title: `${value} yoctoNEAR`, text: `${whole}${frac ? "." + frac : ""} NEAR` });
}

function formatTime(ms) {
  const date = new Date(Number(ms));
  return Number.isFinite(date.getTime()) ? date.toISOString().replace("T", " ").slice(0, 19) : String(ms);
}

function formatSecs(secs) {
  const s = Number(secs);
  if (s % 86400 === 0) return `${s / 86400} d`;
  if (s % 3600 === 0) return `${s / 3600} h`;
  return `${s} s`;
}

// ---- NEAR JSON-RPC views ---------------------------------------------------------------------
async function view(method, args) {
  const bytes = new TextEncoder().encode(JSON.stringify(args));
  const body = {
    jsonrpc: "2.0",
    id: method,
    method: "query",
    params: {
      request_type: "call_function",
      finality: "final",
      account_id: cfg.contractId,
      method_name: method,
      args_base64: btoa(String.fromCharCode(...bytes)),
    },
  };
  const response = await fetch(cfg.rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`${method}: RPC HTTP ${response.status}`);
  const json = await response.json();
  if (json.error) {
    const cause = json.error.cause?.name || json.error.name || "error";
    throw new Error(`${method}: ${cause}: ${json.error.data || json.error.message || ""}`.trim());
  }
  if (json.result?.error) throw new Error(`${method}: ${json.result.error}`);
  const text = new TextDecoder().decode(new Uint8Array(json.result.result));
  return JSON.parse(text);
}

// ---- policy card -----------------------------------------------------------------------------
// NEAR protocol storage price: 10^19 yoctoNEAR per byte (1 NEAR per 100 kB).
const STORAGE_YOCTO_PER_BYTE = 10n ** 19n;

function worstCaseStorage(maxEntries, entryBytes) {
  let yocto;
  try {
    yocto = BigInt(maxEntries) * BigInt(entryBytes) * STORAGE_YOCTO_PER_BYTE;
  } catch {
    return "?";
  }
  return el("span", {}, near(yocto), ` (${maxEntries} entries × ${entryBytes} B × 10^19 yoctoNEAR/B)`);
}

function renderPolicy(policy, available, entryBytes) {
  const box = $("policy");
  box.replaceChildren();
  if (policy === null) {
    box.append(el("p", { class: "muted" }, "No policy for ", accountLink(cfg.agentId), " on this vault."));
    return;
  }
  const windowEnd = Number(policy.window_start_ms) + Number(policy.window_secs) * 1000;
  const rows = [
    ["State", policy.revoked ? badge("revoked", "bad") : badge("active", "ok")],
    ["Per-transaction cap", near(policy.per_tx_max)],
    ["Window limit", el("span", {}, near(policy.window_limit), ` per ${formatSecs(policy.window_secs)}`)],
    ["Spent this window", el("span", {}, near(policy.window_spent), ` (window ${formatTime(policy.window_start_ms)} → ${formatTime(windowEnd)} UTC)`)],
    ["Allowed receivers", el("span", {}, ...policy.allowed_receivers.flatMap((r, i) => (i ? [", ", accountLink(r)] : [accountLink(r)])))],
    ["Ledger entries this window", `${policy.window_entries ?? "?"} of ${policy.max_entries_per_window ?? "?"}`],
    ["Worst-case storage per window", worstCaseStorage(policy.max_entries_per_window, entryBytes)],
    ["Vault available", available === undefined ? "?" : near(available)],
  ];
  box.append(el("dl", { class: "grid" }, rows.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", {}, v)])));
}

// ---- ledger table ----------------------------------------------------------------------------
function renderLedger() {
  const body = $("ledger").tBodies[0];
  body.replaceChildren();
  $("ledger-count").textContent = `(${ledger.length} entr${ledger.length === 1 ? "y" : "ies"})`;
  if (!ledger.length) {
    body.append(el("tr", {}, el("td", { colspan: 9, class: "muted", text: "No spend requests recorded yet." })));
    return;
  }
  const attemptLines = new Map((audit?.attempts || []).map((a) => [a.id, a]));
  for (const entry of [...ledger].reverse()) {
    const reasons = (entry.reasons || []).map((r) => badge(r, "reason"));
    const attempt = attemptLines.get(entry.attempt_id);
    const attemptCell = attempt
      ? el("a", { href: `#attempt-${entry.attempt_id}`, class: "mono", title: `${entry.attempt_id} (audit line ${attempt.line})`, text: shortId(entry.attempt_id) })
      : el("span", { class: "mono", title: String(entry.attempt_id), text: shortId(entry.attempt_id) });
    body.append(
      el("tr", { id: `ledger-${entry.index}` },
        el("td", { class: "num", text: entry.index }),
        el("td", { class: "nowrap", text: formatTime(entry.timestamp_ms) }),
        el("td", {}, accountLink(entry.receiver)),
        el("td", { class: "num nowrap" }, near(entry.amount)),
        el("td", {}, entry.approved ? badge("approved", "ok") : badge("denied", "bad")),
        el("td", {}, reasons.length ? reasons : el("span", { class: "muted", text: "—" })),
        el("td", {}, badge(entry.transfer, { succeeded: "ok", failed: "bad", pending: "warn" }[entry.transfer] || "muted")),
        el("td", { class: "memo", text: entry.memo ?? "" }),
        el("td", {}, attemptCell),
      ),
    );
  }
}

async function loadChain() {
  setStatus(`Reading ${cfg.contractId} via ${new URL(cfg.rpcUrl, location.href).host}…`);
  try {
    const [policy, available, length, entryBytes] = await Promise.all([
      view("get_policy", { agent: cfg.agentId }),
      view("vault_available", {}),
      view("ledger_len", {}),
      view("max_entry_storage_bytes", {}),
    ]);
    renderPolicy(policy, available, entryBytes);
    const pages = [];
    for (let from = 0; from < Number(length); from += PAGE) pages.push(view("get_ledger", { from_index: from, limit: PAGE }));
    ledger = (await Promise.all(pages)).flat();
    renderLedger();
    if (audit) renderAudit();
    setStatus(`Read at finality "final" from ${cfg.contractId}.`, "ok");
  } catch (error) {
    setStatus(`Could not read the vault: ${error.message}`, "bad");
  }
}

// ---- audit log cross-check -------------------------------------------------------------------
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const tagValue = (event, name) => (event.tags || []).find((t) => Array.isArray(t) && t[0] === name)?.[1];

async function parseAudit(text) {
  const attempts = [];
  const byId = new Map();
  const problems = [];
  const signers = new Set();
  let prev = ZERO_ID;
  let lineNo = 0;
  let events = 0;
  for (const line of text.split("\n")) {
    lineNo += 1;
    if (!line.trim()) continue;
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      problems.push(`line ${lineNo}: not JSON`);
      continue;
    }
    events += 1;
    // NIP-01 id: sha256 of [0, pubkey, created_at, kind, tags, content] serialised without whitespace.
    const serial = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
    const idOk = (await sha256Hex(serial)) === event.id;
    if (!idOk) problems.push(`line ${lineNo}: id does not match its content`);
    const prevOk = tagValue(event, "prev") === prev;
    if (!prevOk) problems.push(`line ${lineNo}: prev does not point at the previous event`);
    prev = event.id;
    signers.add(event.pubkey);
    let content = {};
    try {
      content = JSON.parse(event.content);
    } catch {
      problems.push(`line ${lineNo}: content is not JSON`);
    }
    const phase = tagValue(event, "phase");
    if (phase === "attempt") {
      const row = { id: event.id, line: lineNo, idOk, prevOk, content, result: null };
      attempts.push(row);
      byId.set(event.id, row);
    } else if (phase === "result") {
      const row = byId.get(tagValue(event, "e"));
      if (!row) problems.push(`line ${lineNo}: result references no preceding attempt`);
      else row.result = { line: lineNo, idOk, prevOk, content, tx: tagValue(event, "near_tx"), ledger: tagValue(event, "ledger") };
    }
  }
  return { attempts, problems, signers, events };
}

function chainCheck(attempt) {
  const index = attempt.result?.ledger ?? attempt.result?.content?.ledger_index;
  if (index === undefined || index === null) return el("span", { class: "muted", text: "off-chain" });
  const link = el("a", { href: `#ledger-${index}`, text: `#${index}` });
  const entry = ledger.find((e) => String(e.index) === String(index));
  if (!entry) return el("span", {}, link, " ", badge(ledger.length ? "not on chain" : "ledger not loaded", ledger.length ? "bad" : "muted"));
  return el("span", {}, link, " ", entry.attempt_id === attempt.id ? badge("id matches", "ok") : badge("id MISMATCH", "bad"));
}

function renderAudit() {
  const { attempts, problems, signers, events } = audit;
  const summary = $("audit-summary");
  summary.replaceChildren(
    el("p", {},
      `${events} events, ${attempts.length} attempts, ${signers.size} signing key${signers.size === 1 ? "" : "s"}. `,
      problems.length ? badge(`${problems.length} problem(s)`, "bad") : badge("ids and chain intact", "ok"),
    ),
  );
  if (problems.length) summary.append(el("ul", { class: "problems" }, problems.map((p) => el("li", { text: p }))));
  const table = $("audit");
  const body = table.tBodies[0];
  body.replaceChildren();
  for (const a of attempts) {
    const result = a.result?.content || {};
    const verdict = a.content?.screen?.verdict;
    const verdictText = verdict === undefined || verdict === null ? "—" : typeof verdict === "string" ? verdict : JSON.stringify(verdict);
    const idMark = a.idOk && a.prevOk ? badge("ok", "ok") : badge(a.idOk ? "bad prev" : "bad id", "bad");
    const status = result.status || "no result";
    body.append(
      el("tr", { id: `attempt-${a.id}` },
        el("td", { class: "num", text: a.line }),
        el("td", { class: "nowrap" }, el("span", { class: "mono", title: a.id, text: shortId(a.id) }), " ", idMark),
        el("td", { text: a.content?.origin ?? "" }),
        el("td", {}, el("code", { class: "raw", text: a.content?.raw_request ?? "" })),
        el("td", {}, el("code", { class: "raw verdict", text: verdictText })),
        el("td", {}, badge(status, { approved: "ok", denied: "bad", blocked: "warn", protocol_rejected: "warn" }[status] || "muted")),
        el("td", {}, (result.reasons || []).map((r) => badge(r, "reason"))),
        el("td", { class: "nowrap" }, chainCheck(a)),
        el("td", {}, a.result?.tx ? txLink(a.result.tx) : el("span", { class: "muted", text: "—" })),
      ),
    );
  }
  table.hidden = false;
  renderLedger(); // ledger attempt ids now link to their audit rows
}

async function loadAuditText(text, source) {
  try {
    audit = await parseAudit(text);
    renderAudit();
    setStatus(`Audit log loaded from ${source}.`, "ok");
  } catch (error) {
    setStatus(`Could not read the audit log: ${error.message}`, "bad");
  }
}

async function loadAuditUrl(url) {
  try {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    await loadAuditText(await response.text(), url);
  } catch (error) {
    setStatus(`No audit log at ${url}: ${error.message}`, "bad");
  }
}

// ---- wiring ----------------------------------------------------------------------------------
function init() {
  $("meta").replaceChildren("Vault ", accountLink(cfg.contractId), " · agent ", accountLink(cfg.agentId), " · testnet");
  $("refresh").addEventListener("click", loadChain);
  $("audit-load").addEventListener("click", () => loadAuditUrl(cfg.auditLog));
  $("audit-file").addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (file) await loadAuditText(await file.text(), file.name);
  });
  loadChain().then(() => {
    if (params.has("audit")) loadAuditUrl(params.get("audit") || cfg.auditLog);
  });
}

init();
