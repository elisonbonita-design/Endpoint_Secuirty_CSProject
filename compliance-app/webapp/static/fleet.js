"use strict";

// Fleet views: overview, endpoint map, PC details, findings and asset assignments.
// Reuses el(), $(), textOrNone(), complianceCell(), formatPercent() and meter() from app.js.
// All server data is inserted with textContent / DOM nodes, never innerHTML.

const PC_STATUS = { compliant: "Compliant", noncompliant: "Noncompliant", unknown: "Unknown" };
const CONNECTIVITY = { online: "Online", offline: "Offline", stale: "Stale", unknown: "No agent status" };
const CHECK_STATUS = { passed: "Compliant", failed: "Noncompliant", unknown: "Unknown", not_applicable: "Not applicable" };
const LOCATION_FIELDS = ["department", "building", "floor", "room"];
const VIEWS = ["overview", "map", "floorplan", "pc", "findings", "assets", "report", "admin"];
const SOURCE_LABELS = { sca: "Configuration (SCA)", event: "Security event", inventory: "Inventory",
  vulnerability: "Vulnerability", fim: "File integrity", bitlocker: "BitLocker" };
const FINDING_STATUS = { open: "Open", in_review: "In review", fixed_pending: "Fixed, waiting for verification",
  exception: "Approved exception", cleared: "Cleared by a later assessment", verified: "Verified by a later assessment" };
const APP_HEADER = { "X-Requested-With": "compliance-dashboard" };

const SEAT_TOP = 10; // findings listed in a floor-plan seat panel
const RISK_SORTS = { score: "descending", band: "none", days: "none" };
const ROLE_LABELS = { agent: "Agent", team_lead: "Team lead", it_admin: "IT admin", shared_kiosk: "Shared kiosk" };
const SEAT_LABELS = { critical: "Critical", high: "High", medium: "Medium", low: "Low", clear: "No open findings",
  unknown: "Unknown results only" };

const fleetState = { source: "sample", fleet: null, risk: null, endpoint: null, assignments: [],
  riskSort: { key: "score", dir: "desc" } };
try { if (localStorage.getItem("fleet-source") === "wazuh") fleetState.source = "wazuh"; } catch { /* storage blocked */ }

function formatTime(iso) {
  return iso ? iso.replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC") : null;
}

function timeNode(iso, missing = "Not available") {
  return iso ? el("time", { datetime: iso, text: formatTime(iso) }) : el("span", { class: "none", text: missing });
}

function locationText(loc) {
  const parts = [loc.building, loc.floor && `Floor ${loc.floor}`, loc.room && `Room ${loc.room}`].filter(Boolean);
  return parts.length ? parts.join(" · ") : null;
}

async function fetchJson(url, options) {
  let response;
  try { response = await fetch(url, options); } catch { throw new Error("Could not reach the dashboard server."); }
  if (response.status === 401) { location.href = "/login"; throw new Error("Sign in first."); }
  let body = null;
  try { body = await response.json(); } catch { /* non-JSON error page */ }
  if (!response.ok) throw new Error((body && body.error) || `Request failed (HTTP ${response.status}).`);
  return body;
}

function sourceQuery() { return `source=${encodeURIComponent(fleetState.source)}`; }

function setFleetError(message) {
  $("fleet-error").textContent = message || "";
  $("fleet-error").hidden = !message;
}

function renderSourceMeta(body) {
  const banner = $("source-banner");
  const meta = body.source;
  banner.className = `source-banner ${meta.is_sample ? "is-sample" : "is-live"}`;
  banner.replaceChildren(
    el("span", { class: "source-tag", text: meta.is_sample ? "SAMPLE DATA" : "LIVE WAZUH DATA" }),
    el("span", { text: `${meta.label} · as of ${formatTime(meta.as_of)}` }),
  );
  banner.hidden = false;
  const warnings = body.warnings || [];
  $("fleet-warnings").replaceChildren(...warnings.map((w) => el("li", { text: w })));
  $("fleet-warnings").hidden = warnings.length === 0;
}

async function withLoading(label, task) {
  setFleetError("");
  $("fleet-status").textContent = `Loading ${label}…`;
  try {
    await task();
  } catch (err) {
    $("source-banner").hidden = true;
    setFleetError(`Could not load ${label}: ${err.message}`);
    return false;
  } finally {
    $("fleet-status").textContent = "";
  }
  return true;
}

async function getFleet(force) {
  if (!fleetState.fleet || force) fleetState.fleet = await fetchJson(`/api/fleet?${sourceQuery()}`);
  renderSourceMeta(fleetState.fleet);
  return fleetState.fleet;
}

function invalidateFleet() {
  fleetState.fleet = null;
  fleetState.risk = null;
}

// ---- Risk prioritization (rule-based scores; the optional local AI only explains) ----

async function getRisk(force) {
  if (!fleetState.risk || force) fleetState.risk = await fetchJson(`/api/risk?${sourceQuery()}`);
  return fleetState.risk;
}

function daysText(n) {
  return n === null || n === undefined ? "—" : `${n} day${n === 1 ? "" : "s"}`;
}

function bandBadge(item) {
  return el("span", { class: `badge band-badge band-${item.band_key}`, text: `${item.band} · ${item.score}` });
}

function riskBasis(risk) {
  return `Rule-based risk score 0–100 (weights v${risk.weights_version}, requirement catalogue v${risk.catalogue_version}). `
    + "Priority never comes from AI. Unknown results are not scored; they are listed under Needs data.";
}

function explanationNode(r) {
  const box = el("div", { class: r.ai ? "explain-result explain-ai" : "explain-result" });
  if (r.ai) {
    box.append(el("span", { class: "badge badge-ai", text: r.label }),
      el("p", { class: "explain-text", text: r.explanation }));
    if (r.steps.length) box.append(el("ol", { class: "explain-steps" }, ...r.steps.map((s) => el("li", { text: s }))));
    box.append(el("p", { class: "explain-meta", text: `Local model ${r.model}. Priority (rule-based): ${r.reason}` }));
  } else {
    box.append(el("span", { class: "badge badge-rule", text: "Rule-based explanation" }),
      el("p", { class: "explain-text", text: r.reason }),
      el("h4", { text: "Remediation" }), el("p", {}, textOrNone(r.remediation)),
      el("p", { class: "explain-meta", text: r.note }));
  }
  return box;
}

function explainBox(item) {
  const box = el("div", { class: "explain" });
  const button = el("button", { type: "button", class: "btn btn-secondary btn-small", text: "Explain" });
  const output = el("div", { "aria-live": "polite" });
  button.addEventListener("click", async () => {
    button.disabled = true;
    output.replaceChildren(el("p", { class: "muted", text: "Preparing explanation…" }));
    try {
      const r = await fetchJson(`/api/risk/explain?${sourceQuery()}`, {
        method: "POST", headers: { ...APP_HEADER, "Content-Type": "application/json" },
        body: JSON.stringify({ finding_id: item.id }) });
      output.replaceChildren(explanationNode(r));
    } catch (err) {
      output.replaceChildren(el("p", { class: "alert", text: `Could not explain: ${err.message}` }));
    } finally {
      button.disabled = false;
    }
  });
  box.append(button, output);
  return box;
}

// ---- Review workflow: status, notes and history of one finding ----

function historyList(events) {
  return el("ol", { class: "history" }, ...events.map((ev) => el("li", {},
    el("time", { datetime: ev.at, text: formatTime(ev.at) }),
    document.createTextNode(` · ${ev.actor} · `),
    el("strong", { text: ev.kind === "note" ? "note" : ev.to_status
      ? `${ev.from_status ? FINDING_STATUS[ev.from_status] || ev.from_status : "—"} → ${FINDING_STATUS[ev.to_status] || ev.to_status}`
      : ev.kind }),
    ev.note ? el("span", { class: "history-note", text: ` · ${ev.note}` }) : document.createTextNode(""))));
}

function reviewPanel(data, onChange) {
  const f = data.finding;
  const box = el("div", { class: "review" });
  box.append(el("p", {}, el("strong", { text: "Status: " }), document.createTextNode(FINDING_STATUS[f.status] || f.status),
    document.createTextNode(` · result: ${f.state.replace("_", " ")}`)));
  if (f.verified_at) box.append(el("p", { class: "muted", text: `Verified ${formatTime(f.verified_at)} by a later assessment.` }));
  const note = el("textarea", { rows: "2", maxlength: "1000", placeholder: "Note: what was reviewed, the simulated fix, or the exception justification" });
  const message = el("p", { class: "status", role: "status" });
  const send = async (url, body) => {
    message.textContent = "Saving…";
    try {
      const r = await fetchJson(`${url}?${sourceQuery()}`, { method: "POST",
        headers: { ...APP_HEADER, "Content-Type": "application/json" }, body: JSON.stringify(body) });
      fleetState.risk = null;
      onChange(r);
    } catch (err) {
      message.textContent = `Not saved: ${err.message}`;
    }
  };
  const actions = el("div", { class: "review-actions" });
  if (data.allowed.length) {
    const select = el("select", { "aria-label": "New status" },
      ...data.allowed.map((s) => el("option", { value: s, text: FINDING_STATUS[s] })));
    const change = el("button", { type: "button", class: "btn btn-primary btn-small", text: "Change status" });
    change.addEventListener("click", () => send(`/api/findings/${f.id}/status`, { status: select.value, note: note.value }));
    actions.append(select, change);
  } else {
    actions.append(el("span", { class: "muted", text: ["cleared", "verified"].includes(f.status)
      ? "Closed by an assessment. It reopens automatically if the check fails again."
      : "No status change available for your role." }));
  }
  const addNote = el("button", { type: "button", class: "btn btn-secondary btn-small", text: "Add note" });
  addNote.addEventListener("click", () => send(`/api/findings/${f.id}/notes`, { note: note.value }));
  actions.append(addNote);
  box.append(note, actions, message,
    el("p", { class: "muted review-rule", text: "\"Verified\" is never set by hand: after you mark a fix, the next assessment must confirm it." }),
    el("h4", { text: `History (${data.history.length})` }), historyList(data.history));
  return box;
}

// One collapsed panel per finding: the explanation (rule-based or local AI) and the review workflow with history.
// The review data loads the first time the panel is opened.
function findingDetails(item) {
  const details = el("details", { class: "finding-details" }, el("summary", { text: "Explain, review and history" }));
  const body = el("div", { class: "review-body" }, el("p", { class: "muted", text: "Loading…" }));
  details.append(explainBox(item), body);
  const render = (data) => {
    body.replaceChildren(reviewPanel(data, render));
    // Keep the surrounding table row in step with the new status (no full reload needed).
    const cell = details.closest("tr")?.querySelector('td[data-label="Status"]');
    if (cell) cell.textContent = FINDING_STATUS[data.finding.status] || data.finding.status;
  };
  const load = async () => {
    try {
      render(await fetchJson(`/api/findings/${item.id}?${sourceQuery()}`));
    } catch (err) {
      body.replaceChildren(el("p", { class: "alert", text: `Could not load: ${err.message}` }));
    }
  };
  let loaded = false;
  details.addEventListener("toggle", () => { if (details.open && !loaded) { loaded = true; load(); } });
  return details;
}

// The stored reason is "<Band> (<score>): <title> – <factors>"; next to the title only the factors are shown.
function reasonFactors(item) {
  const reason = item.reason || "";
  const cut = reason.indexOf(" – ");
  return cut >= 0 ? `${item.band} (${item.score}): ${reason.slice(cut + 3)}` : reason;
}

// Compact finding: band + title, one meta line, the short reason, and one collapsed details panel.
// In a floor-plan seat panel (inSeat) the endpoint and seat are already shown above, so they are left out.
function fixItem(item, inSeat = false) {
  const facts = `${SOURCE_LABELS[item.source] || item.source} · ${FINDING_STATUS[item.status]} · open ${daysText(item.days_open)}`;
  const meta = inSeat ? el("p", { class: "fix-meta", text: facts })
    : el("p", { class: "fix-meta" },
      el("a", { href: `#/pc/${encodeURIComponent(item.endpoint_id)}`, text: item.endpoint_label || item.endpoint_id }),
      document.createTextNode(` · ${item.seat || "No seat assigned"} · ${facts}`));
  return el("li", { class: `fix-item band-edge-${item.band_key}`, "data-finding-id": item.id },
    el("div", { class: "fix-head" }, bandBadge(item), el("strong", { class: "fix-title", text: item.title })),
    meta,
    el("p", { class: "fix-reason", text: reasonFactors(item) }),
    findingDetails(item));
}

async function renderFixFirst() {
  try {
    const risk = await getRisk();
    $("risk-basis").textContent = riskBasis(risk);
    $("needs-data-count").textContent = risk.needs_data_count;
    const byBand = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of risk.findings) byBand[f.band_key] = (byBand[f.band_key] || 0) + 1;
    for (const b of Object.keys(byBand)) $(`band-count-${b}`).textContent = byBand[b];
    $("band-count-needs").textContent = risk.needs_data_count;
    const top = risk.findings.slice(0, 10);
    $("fix-first-list").replaceChildren(...top.map((f) => fixItem(f)));
    $("fix-first-empty").hidden = top.length > 0;
  } catch (err) {
    $("fix-first-list").replaceChildren();
    $("fix-first-empty").hidden = false;
    $("fix-first-empty").textContent = `Prioritized findings could not be loaded: ${err.message}`;
  }
}

$("daily-summary-btn").addEventListener("click", async () => {
  const box = $("daily-summary");
  const button = $("daily-summary-btn");
  box.hidden = false;
  button.disabled = true;
  box.replaceChildren(el("p", { class: "muted", text: "Preparing summary…" }));
  try {
    const r = await fetchJson(`/api/risk/summary?${sourceQuery()}`, {
      method: "POST", headers: { ...APP_HEADER, "Content-Type": "application/json" }, body: "{}" });
    // JSON key order is alphabetical; show bands from most to least urgent.
    const order = ["Critical", "High", "Medium", "Low"];
    const bands = Object.entries(r.counts.by_band)
      .sort(([a], [b]) => (order.indexOf(a) + 99) % 99 - (order.indexOf(b) + 99) % 99)
      .map(([b, n]) => `${b}: ${n}`).join(" · ");
    const counts = el("p", { class: "explain-meta", text: `Counts sent: ${bands} · Needs data: ${r.counts.needs_data}` });
    box.replaceChildren(r.ai
      ? el("div", { class: "explain-result explain-ai" }, el("span", { class: "badge badge-ai", text: r.label }),
        el("p", { class: "explain-text", text: r.summary }), counts)
      : el("div", { class: "explain-result" }, el("span", { class: "badge badge-rule", text: "Counts only" }),
        el("p", { class: "explain-text", text: bands }), el("p", { class: "explain-meta", text: r.note })));
  } catch (err) {
    box.replaceChildren(el("p", { class: "alert", text: `Could not build the summary: ${err.message}` }));
  } finally {
    button.disabled = false;
  }
});

// ---- Overview ----

function setText(id, value) { $(id).textContent = value ?? "–"; }

async function showOverview() {
  const ok = await withLoading("overview", async () => {
    const { summary } = await getFleet();
    const pcs = summary.pcs, checks = summary.checks;
    setText("pc-total", pcs.total); setText("pc-compliant", pcs.compliant);
    setText("pc-noncompliant", pcs.noncompliant); setText("pc-unknown", pcs.unknown);
    setText("pc-offline", pcs.offline_or_stale); setText("pc-unassigned", pcs.unassigned);
    setText("chk-rate", formatPercent(checks.pass_percentage));
    $("chk-meter").style.width = `${checks.pass_percentage ?? 0}%`;
    setText("chk-total", checks.total); setText("chk-passed", checks.passed); setText("chk-failed", checks.failed);
    setText("chk-unknown", checks.unknown); setText("chk-na", checks.not_applicable);
    $("dept-table").querySelector("tbody").replaceChildren(...summary.departments.map((d) => {
      const link = el("a", { href: "#/map", text: d.name });
      link.addEventListener("click", () => { $("map-department").dataset.pending = d.name; });
      return el("tr", {},
        el("td", {}, link),
        el("td", { class: "num", text: d.pcs }),
        el("td", { class: "num", text: d.compliant }),
        el("td", { class: "num", text: d.noncompliant }),
        el("td", { class: "num", text: d.unknown }),
        el("td", {}, el("div", { class: "rate-cell" }, meter(d.pass_percentage, true),
          el("span", { text: formatPercent(d.pass_percentage) }))));
    }));
  });
  $("view-overview").hidden = !ok;
  if (ok) await renderFixFirst();
}

// ---- Endpoint map ----

function reqRate(e) {
  const s = e.requirement_summary;
  if (!s) return "n/a";
  return s.compliance_rate === null ? "no data" : `${formatPercent(s.compliance_rate)} (${s.non_compliant} failing)`;
}

function pcCard(e) {
  const rate = e.counts.pass_percentage;
  const card = el("a", {
    class: `pc-card status-${e.status}`, href: `#/pc/${encodeURIComponent(e.key)}`,
    "data-key": e.key, "data-status": e.status, "data-connectivity": e.connectivity,
    // Kept on every card so a floor plan can later position PCs by building / floor / room.
    "data-building": e.location.building || "", "data-floor": e.location.floor || "", "data-room": e.location.room || "",
  },
    el("span", { class: "pc-name", text: e.hostname || `Agent ${e.agent_id}` }),
    el("span", { class: "pc-id", text: `Agent ${e.agent_id}` }),
    el("span", { class: "pc-rate", text: `Requirements: ${reqRate(e)}` }),
    el("span", { class: "pc-rate pc-rate-raw", text: `CIS benchmark: ${rate === null ? "no results" : formatPercent(rate)}` }),
    el("span", { class: "pc-loc", text: locationText(e.location) || "No location assigned" }));
  const badges = el("span", { class: "badges" }, el("span", { class: `badge badge-pc-${e.status}`, text: PC_STATUS[e.status] }));
  if (e.connectivity !== "online") badges.append(el("span", { class: `badge badge-conn-${e.connectivity}`, text: CONNECTIVITY[e.connectivity] }));
  card.append(badges);
  card.setAttribute("aria-label", `${e.hostname || e.agent_id}: ${PC_STATUS[e.status]}, ${CONNECTIVITY[e.connectivity]}`);
  return card;
}

function filterEndpoints(endpoints) {
  const query = $("map-search").value.trim().toLowerCase();
  const dept = $("map-department").value;
  const status = $("map-status").value;
  return endpoints.filter((e) => {
    if (dept && e.department !== dept) return false;
    if (status === "offline_or_stale" ? !["offline", "stale"].includes(e.connectivity) : status && e.status !== status) return false;
    return !query || [e.hostname, e.agent_id].some((v) => v && v.toLowerCase().includes(query));
  });
}

function renderMap() {
  const fleet = fleetState.fleet;
  if (!fleet) return;
  const matches = filterEndpoints(fleet.endpoints);
  const groups = new Map(fleet.summary.departments.map((d) => [d.name, []]));
  for (const e of matches) groups.get(e.department).push(e);
  const sections = [];
  for (const [name, pcs] of groups) {
    if (!pcs.length) continue;
    sections.push(el("section", { class: "dept-group", "data-department": name },
      el("h2", {}, document.createTextNode(name), el("span", { class: "muted", text: ` ${pcs.length} PC${pcs.length === 1 ? "" : "s"}` })),
      el("div", { class: "pc-grid" }, ...pcs.map(pcCard))));
  }
  $("map-groups").replaceChildren(...sections);
  $("map-empty").hidden = matches.length > 0;
}

async function showMap() {
  const ok = await withLoading("endpoint map", async () => {
    const fleet = await getFleet();
    const select = $("map-department");
    const wanted = select.dataset.pending ?? select.value;
    delete select.dataset.pending;
    const names = fleet.summary.departments.map((d) => d.name);
    select.replaceChildren(el("option", { value: "", text: "All departments" }),
      ...names.map((n) => el("option", { value: n, text: n })));
    select.value = names.includes(wanted) ? wanted : "";
    renderMap();
  });
  $("view-map").hidden = !ok;
}

// ---- PC details ----

// One label/value pair, kept together in a <div> so a grid of facts can never split a label from its value.
function fact(label, value) {
  return [el("div", { class: "fact" }, el("dt", { text: label }),
    el("dd", {}, value instanceof Node ? value : textOrNone(value)))];
}

// Long Wazuh texts (PowerShell commands, CIS remediation paragraphs) are shortened in tables; the full text is in
// the tooltip and in the check dialog (click the check name).
function shortText(text, max) {
  if (!text) return textOrNone(text);
  const clean = String(text).replace(/\s+/g, " ").trim();
  if (clean.length <= max) return document.createTextNode(clean);
  return el("span", { class: "short-text", title: clean, text: clean.slice(0, max - 1).trimEnd() + "…" });
}

function evidenceCell(c) {
  const cell = el("td", { "data-label": "Evidence / reason" });
  if (c.result) cell.append(el("span", { class: "raw-result", text: `Wazuh result: ${c.result}` }));
  else cell.append(el("span", { class: "raw-result", text: "Wazuh result: none reported" }));
  if (c.reason) cell.append(el("span", { class: "reason", text: c.reason }));
  else if (c.status === "failed") cell.append(el("span", { class: "none", text: "No failure reason provided by Wazuh." }));
  for (const [kind, values] of Object.entries(c.targets || {})) {
    cell.append(el("span", { class: "target" }, document.createTextNode(`Examined ${kind}: `), shortText(values.join("; "), 90)));
  }
  return cell;
}

function checkRow(c, index) {
  const open = el("button", { type: "button", class: "link-btn", "data-check-index": index, text: c.name || "(unnamed check)" });
  open.addEventListener("click", () => openCheck(c));
  const nameCell = el("td", { "data-label": "Check" }, open);
  if (c.id !== null && c.id !== undefined) nameCell.append(el("span", { class: "check-id", text: `ID ${c.id}` }));
  if (c.policy) nameCell.append(el("span", { class: "check-id", text: c.policy }));
  const row = el("tr", { class: `check-row row-${c.status}` },
    nameCell,
    el("td", { "data-label": "Status" }, el("span", { class: `badge badge-${c.status}`, text: CHECK_STATUS[c.status] })),
    evidenceCell(c),
    el("td", { "data-label": "Expected" }, textOrNone(c.expected)),
    el("td", { "data-label": "Remediation" }, shortText(c.remediation, 160)),
    el("td", { "data-label": "Frameworks" }, complianceCell(c.compliance)),
    el("td", { "data-label": "Assessed" }, timeNode(c.assessed_at)));
  return row;
}

// ---- Requirement compliance of one PC (the selected baseline, separate from the CIS benchmark score) ----

const REQ_BADGE = { compliant: "passed", non_compliant: "failed", exception: "not_applicable", not_applicable: "not_applicable",
  unknown: "unknown", no_data: "unknown" };

function renderRequirementSummary(e) {
  const s = e.requirement_summary;
  $("pc-req-version").textContent = s ? `(catalogue v${s.catalogue_version}, ${s.total} requirements)` : "";
  setText("pc-req-rate", s ? formatPercent(s.compliance_rate) : "–");
  $("pc-req-meter").style.width = `${(s && s.compliance_rate) || 0}%`;
  setText("pc-req-compliant", s ? s.compliant : "–");
  setText("pc-req-noncompliant", s ? s.non_compliant : "–");
  setText("pc-req-exception", s ? s.exception : "–");
  setText("pc-req-unknown", s ? s.unknown + s.not_applicable : "–");
  setText("pc-req-nodata", s ? s.no_data : "–");
}

function renderRequirements() {
  const e = fleetState.endpoint;
  if (!e) return;
  const wanted = $("pc-req-filter").value;
  const order = ["non_compliant", "unknown", "exception", "no_data", "not_applicable", "compliant"];
  const rows = (e.requirements || [])
    .filter((r) => !wanted || r.status === wanted)
    .sort((a, b) => order.indexOf(a.status) - order.indexOf(b.status) || a.id.localeCompare(b.id));
  $("pc-req-table").querySelector("tbody").replaceChildren(...rows.map((r) => el("tr", { class: `req-row req-${r.status}` },
    el("td", { "data-label": "Requirement" }, el("span", { class: "risk-title", text: r.title }),
      el("span", { class: "check-id", text: `${r.id}${r.area ? ` · ${r.area}` : ""} · source: ${r.sources.join(", ") || "none"}` })),
    el("td", { "data-label": "Severity" }, el("span", { class: `badge band-badge band-${{ critical: "critical", high: "high", medium: "medium", low: "low" }[r.severity]}`, text: r.severity })),
    el("td", { "data-label": "Status" }, el("span", { class: `badge badge-${REQ_BADGE[r.status]} req-badge-${r.status}`, text: r.label })),
    el("td", { "data-label": "Evidence" }, el("ul", { class: "req-evidence" }, ...r.evidence.map((x) => el("li", {}, shortText(x, 140))))))));
  $("pc-req-table").hidden = rows.length === 0;
  $("pc-req-empty").hidden = rows.length > 0;
  if (!e.requirements) {
    $("pc-req-empty").hidden = false;
    $("pc-req-empty").textContent = "Requirement status is not available (prioritization config not loaded).";
  }
}

$("pc-req-filter").addEventListener("change", renderRequirements);

function renderChecks() {
  const e = fleetState.endpoint;
  if (!e) return;
  const status = $("pc-filter-status").value;
  const query = $("pc-filter-text").value.trim().toLowerCase();
  const rows = [];
  e.checks.forEach((c, i) => {
    if (status !== "all" && c.status !== status) return;
    const hay = [c.id, c.name, c.policy, c.reason, c.remediation, ...Object.keys(c.compliance || {})]
      .filter((v) => v !== null && v !== undefined).join(" ").toLowerCase();
    if (query && !hay.includes(query)) return;
    rows.push(checkRow(c, i));
  });
  $("pc-checks").querySelector("tbody").replaceChildren(...rows);
  $("pc-checks").hidden = rows.length === 0;
  $("pc-checks-empty").hidden = rows.length > 0;
}

async function showPc(id) {
  $("pc-filter-status").value = "all";
  $("pc-filter-text").value = "";
  const ok = await withLoading(`endpoint ${id}`, async () => {
    const body = await fetchJson(`/api/fleet/endpoint?${sourceQuery()}&id=${encodeURIComponent(id)}`);
    renderSourceMeta(body);
    const e = fleetState.endpoint = body.endpoint;
    $("pc-title").textContent = e.hostname || `Agent ${e.agent_id}`;
    $("pc-badges").replaceChildren(el("span", { class: `badge badge-pc-${e.status}`, text: PC_STATUS[e.status] }),
      el("span", { class: `badge badge-conn-${e.connectivity}`, text: CONNECTIVITY[e.connectivity] }));
    const loc = e.location;
    $("pc-facts").replaceChildren(
      ...fact("Hostname", e.hostname), ...fact("Wazuh agent ID", e.agent_id),
      ...fact("Department", e.assigned ? loc.department : el("span", { class: "unassigned", text: "Unassigned" })),
      ...fact("Assigned location", locationText(loc)),
      ...fact("Wazuh agent status", e.agent_status), ...fact("Last seen (keep-alive)", timeNode(e.last_seen)),
      ...fact("Last assessment", timeNode(e.last_assessment)),
      ...fact("Operating system", e.os), ...fact("IP address", e.ip),
      ...fact("SCA policies", e.policies.join(", ")));
    setText("pc-rate", formatPercent(e.counts.pass_percentage));
    setText("pc-passed", e.counts.passed); setText("pc-failed", e.counts.failed);
    setText("pc-unknown-checks", e.counts.unknown); setText("pc-na", e.counts.not_applicable);
    renderRequirementSummary(e);
    renderRequirements();
    renderChecks();
  });
  $("view-pc").hidden = !ok;
}

function dialogSection(title, content) {
  return el("section", { class: "dlg-section" }, el("h3", { text: title }),
    content instanceof Node ? content : textOrNone(content));
}

function openCheck(c) {
  $("dlg-title").textContent = c.name || "(unnamed check)";
  const targets = Object.entries(c.targets || {}).map(([k, v]) => `${k}: ${v.join("; ")}`).join("\n");
  $("dlg-body").replaceChildren(
    el("p", {}, el("span", { class: `badge badge-${c.status}`, text: CHECK_STATUS[c.status] }),
      document.createTextNode(` ID ${c.id ?? "—"} · ${c.policy || "Unknown policy"}`)),
    dialogSection("Wazuh result", c.result || "None reported (treated as Unknown)"),
    dialogSection("Failure / status reason", c.reason || (c.status === "failed" ? "Wazuh did not provide a reason." : null)),
    dialogSection("What was examined", targets || null),
    dialogSection("Expected requirement", c.expected),
    dialogSection("Description", c.description),
    dialogSection("Rationale", c.rationale),
    dialogSection("Recommended remediation", c.remediation),
    dialogSection("Compliance framework mapping", complianceCell(c.compliance)),
    dialogSection("Last assessment", timeNode(c.assessed_at)),
    el("p", { class: "muted", text: "Remediation is guidance only. Nothing is changed on the endpoint by this dashboard." }));
  $("check-dialog").showModal();
}

// ---- Findings ----

function sortedRisk(items) {
  const { key, dir } = fleetState.riskSort;
  const bands = (fleetState.risk && fleetState.risk.bands) || [];
  const value = {
    score: (i) => i.score,
    band: (i) => bands.length - bands.indexOf(i.band), // Critical highest
    days: (i) => i.days_open,
  }[key];
  // Server order (score, then oldest first) breaks ties.
  const indexed = items.map((item, index) => ({ item, index }));
  indexed.sort((a, b) => (dir === "desc" ? value(b.item) - value(a.item) : value(a.item) - value(b.item))
    || a.index - b.index);
  return indexed.map((x) => x.item);
}

function riskRow(item) {
  const finding = el("td", { "data-label": "Finding" }, el("span", { class: "risk-title", text: item.title }));
  const meta = [SOURCE_LABELS[item.source] || item.source, item.requirement_id && `${item.requirement_id} · ${item.severity}`,
    item.cve_id && `CVSS ${item.cvss ?? "—"}`].filter(Boolean).join(" · ");
  finding.append(el("span", { class: "check-id", text: meta }),
    el("span", { class: "fix-reason", text: reasonFactors(item) }), findingDetails(item));
  return el("tr", { "data-finding-id": item.id },
    el("td", { class: "num", "data-label": "Score", text: item.score }),
    el("td", { "data-label": "Band" }, el("span", { class: `badge band-badge band-${item.band_key}`, text: item.band })),
    el("td", { "data-label": "Endpoint", class: "endpoint-cell" },
      el("a", { href: `#/pc/${encodeURIComponent(item.endpoint_id)}`, text: item.endpoint_label || item.endpoint_id }),
      el("span", { class: "seat-line", text: item.seat || "No seat assigned" })),
    finding,
    el("td", { "data-label": "Status", text: FINDING_STATUS[item.status] || item.status }),
    el("td", { class: "num", "data-label": "Days open", text: item.days_open }));
}

function renderRiskTable() {
  const risk = fleetState.risk;
  if (!risk) return;
  const band = $("risk-band").value;
  const items = sortedRisk(risk.findings.filter((i) => !band || i.band_key === band));
  $("risk-table").querySelector("tbody").replaceChildren(...items.map(riskRow));
  $("risk-table").hidden = items.length === 0;
  $("risk-empty").hidden = items.length > 0;
  $("risk-count").textContent = `(${items.length} of ${risk.findings.length} scored)`;
  for (const th of $("risk-table").querySelectorAll("th[aria-sort]")) {
    const key = th.querySelector(".sort-btn").dataset.sort;
    th.setAttribute("aria-sort", key === fleetState.riskSort.key
      ? (fleetState.riskSort.dir === "desc" ? "descending" : "ascending") : "none");
  }
}

function renderNeedsData(risk) {
  $("needs-data-total").textContent = risk.needs_data_count;
  $("needs-data-list").replaceChildren(...risk.needs_data.map((n) => el("li", {},
    el("a", { href: `#/pc/${encodeURIComponent(n.endpoint_id)}`, text: n.endpoint_label || n.endpoint_id }),
    document.createTextNode(` · ${n.title} · unknown result: re-run the assessment before judging it`))));
}

for (const button of document.querySelectorAll("#risk-table .sort-btn")) {
  button.addEventListener("click", () => {
    const key = button.dataset.sort;
    const sort = fleetState.riskSort;
    fleetState.riskSort = { key, dir: sort.key === key && sort.dir === "desc" ? "asc" : "desc" };
    renderRiskTable();
  });
}
$("risk-band").addEventListener("change", renderRiskTable);

async function showFindings() {
  const ok = await withLoading("findings", async () => {
    const risk = await getRisk(true);
    const select = $("risk-band");
    const wanted = select.value;
    select.replaceChildren(el("option", { value: "", text: "All bands" }),
      ...risk.bands.map((b) => el("option", { value: b.toLowerCase(), text: b })));
    select.value = risk.bands.some((b) => b.toLowerCase() === wanted) ? wanted : "";
    $("risk-list-basis").textContent = riskBasis(risk);
    renderRiskTable();
    renderNeedsData(risk);
    const body = await fetchJson(`/api/fleet/findings?${sourceQuery()}`);
    renderSourceMeta(body);
    $("findings-basis").textContent = body.basis;
    $("prio-list").replaceChildren(...body.findings.map((g) => {
      const affected = el("ul", { class: "affected" }, ...g.endpoints.map((x) =>
        el("li", {}, el("a", { href: `#/pc/${encodeURIComponent(x.key)}`, text: x.hostname || x.key }),
          el("span", { class: "muted", text: ` · ${x.department}` }))));
      return el("li", { class: "card prio-item", "data-check-id": g.id ?? "" },
        el("div", { class: "section-head" },
          el("h2", {}, document.createTextNode(g.name || "(unnamed check)"),
            el("span", { class: "check-id", text: `ID ${g.id ?? "—"} · ${g.policy || "Unknown policy"}` })),
          el("span", { class: "badge badge-failed", text: `${g.affected} PC${g.affected === 1 ? "" : "s"} noncompliant` })),
        el("div", { class: "chips" }, ...g.departments.map((d) => el("span", { class: "chip", text: d }))),
        el("h3", { text: "Why this needs attention" }),
        el("ul", { class: "why" }, ...g.why.map((w) => el("li", { text: w }))),
        el("h3", { text: "Recommended remediation" }), el("p", {}, textOrNone(g.remediation)),
        g.expected ? el("p", { class: "muted", text: `Expected: ${g.expected}` }) : document.createTextNode(""),
        el("details", {}, el("summary", { text: `Affected endpoints (${g.affected})` }), affected));
    }));
    $("prio-empty").hidden = body.findings.length > 0;
    $("raw-count").textContent = `${body.findings.length} failed check${body.findings.length === 1 ? "" : "s"}`;
  });
  $("view-findings").hidden = !ok;
}

// ---- Assets ----

function savedAssignmentFor(e) {
  const list = fleetState.assignments;
  return list.find((a) => a.key_type === "agent_id" && a.key_value === e.agent_id)
    || (e.hostname && list.find((a) => a.key_type === "hostname" && a.key_value === e.hostname.toLowerCase()));
}

function fillAssetForm(keyType, keyValue, loc, saved) {
  $("asset-key-type").value = keyType;
  $("asset-key-value").value = keyValue;
  for (const f of LOCATION_FIELDS) $(`asset-${f}`).value = (loc && loc[f]) || "";
  $("asset-role").value = (saved && saved.role) || "agent";
  $("asset-client-data").checked = Boolean(saved && saved.handles_client_data);
  $("asset-form-title").textContent = `Assign ${keyValue}`;
  $("asset-department").focus();
}

function renderAssets() {
  const fleet = fleetState.fleet;
  $("asset-endpoints").querySelector("tbody").replaceChildren(...fleet.endpoints.map((e) => {
    const saved = savedAssignmentFor(e);
    const origin = saved ? `Saved (${saved.key_type === "agent_id" ? "agent ID" : "hostname"})`
      : e.assigned || locationText(e.location) ? "Bundled sample" : "None";
    const edit = el("button", { type: "button", class: "btn btn-secondary btn-small", text: "Edit" });
    edit.addEventListener("click", () => fillAssetForm("agent_id", e.agent_id, e.location, saved));
    return el("tr", { "data-key": e.key },
      el("td", { "data-label": "Hostname" }, textOrNone(e.hostname)),
      el("td", { "data-label": "Agent ID", text: e.agent_id }),
      el("td", { "data-label": "Department" }, e.assigned ? document.createTextNode(e.department)
        : el("span", { class: "unassigned", text: "Unassigned" })),
      ...["building", "floor", "room"].map((f) => el("td", { "data-label": f }, textOrNone(e.location[f]))),
      el("td", { "data-label": "Assignment", text: origin }),
      el("td", {}, edit));
  }));
  const saved = fleetState.assignments;
  $("asset-saved").querySelector("tbody").replaceChildren(...saved.map((a) => {
    const del = el("button", { type: "button", class: "btn btn-secondary btn-small", text: "Delete" });
    del.addEventListener("click", () => deleteAssignment(a));
    const edit = el("button", { type: "button", class: "btn btn-secondary btn-small", text: "Edit" });
    edit.addEventListener("click", () => fillAssetForm(a.key_type, a.key_value, a, a));
    return el("tr", {},
      el("td", { text: a.key_type === "agent_id" ? "Agent ID" : "Hostname" }),
      el("td", { text: a.key_value }),
      ...LOCATION_FIELDS.map((f) => el("td", {}, textOrNone(a[f]))),
      el("td", { text: ROLE_LABELS[a.role] || a.role }),
      el("td", { text: a.handles_client_data ? "Yes" : "No" }),
      el("td", {}, timeNode(a.updated_at)),
      el("td", { class: "row-actions" }, edit, del));
  }));
  $("asset-saved").hidden = saved.length === 0;
  $("asset-saved-empty").hidden = saved.length > 0;
  $("asset-count").textContent = saved.length ? `${saved.length} saved` : "";
}

async function showAssets(force) {
  const ok = await withLoading("assets", async () => {
    const [, assets] = await Promise.all([getFleet(force), fetchJson("/api/assets")]);
    fleetState.assignments = assets.assignments;
    renderAssets();
  });
  $("view-assets").hidden = !ok;
}

async function assetRequest(method, url, body, success) {
  $("asset-message").textContent = "";
  try {
    const isForm = body instanceof FormData;
    const result = await fetchJson(url, {
      method, body: isForm ? body : JSON.stringify(body),
      headers: isForm ? APP_HEADER : { ...APP_HEADER, "Content-Type": "application/json" },
    });
    $("asset-message").textContent = "Saved. Reloading…";
    invalidateFleet(); // assignments change departments and risk scores; reload both
    await showAssets(true);
    $("asset-message").textContent = success(result);
  } catch (err) {
    $("asset-message").textContent = `Not saved: ${err.message}`;
  }
}

function deleteAssignment(a) {
  if (!confirm(`Delete the assignment for ${a.key_value}?`)) return;
  assetRequest("DELETE", "/api/assets", { key_type: a.key_type, key_value: a.key_value }, () => `Deleted ${a.key_value}.`);
}

$("asset-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const body = { key_type: $("asset-key-type").value, key_value: $("asset-key-value").value.trim() };
  for (const f of LOCATION_FIELDS) body[f] = $(`asset-${f}`).value.trim() || null;
  body.role = $("asset-role").value;
  body.handles_client_data = $("asset-client-data").checked;
  assetRequest("PUT", "/api/assets", body, () => `Saved assignment for ${body.key_value}.`);
});

$("asset-form").addEventListener("reset", () => { $("asset-form-title").textContent = "Assign an endpoint"; });
// Editing a PC that has no saved assignment starts from the defaults.
$("asset-key-value").addEventListener("change", () => {
  const value = $("asset-key-value").value.trim();
  const type = $("asset-key-type").value;
  const saved = fleetState.assignments.find((a) => a.key_type === type
    && a.key_value === (type === "hostname" ? value.toLowerCase() : value));
  $("asset-role").value = (saved && saved.role) || "agent";
  $("asset-client-data").checked = Boolean(saved && saved.handles_client_data);
});

$("asset-csv").addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const form = new FormData();
  form.append("file", file);
  assetRequest("POST", "/api/assets/import", form, (r) => `Imported ${r.imported} assignment(s) from ${file.name}.`);
  event.target.value = "";
});

// ---- Floor plan ----

const IMAGE_EXTENSIONS = { "image/png": [".png"], "image/jpeg": [".jpg", ".jpeg"], "image/webp": [".webp"] };
const fpState = { plans: [], maxBytes: 2 * 1024 * 1024, selectedKey: null, justDragged: false };

function placeKey(building, floor) { return JSON.stringify([building, floor]); }
function placeLabel(building, floor) { return `${building} · Floor ${floor}`; }
function currentPlace() { try { return JSON.parse($("fp-floor").value); } catch { return null; } }

function onFloor(e, place) {
  return place && e.location.building === place[0] && e.location.floor === place[1];
}

function fpMatches(e) {
  const dept = $("fp-department").value;
  const status = $("fp-status").value;
  if (dept && e.department !== dept) return false;
  if ($("fp-urgent").checked && !(e.risk && ["critical", "high"].includes(e.risk.band))) return false;
  if (status === "offline_or_stale") return ["offline", "stale"].includes(e.connectivity);
  return !status || e.status === status;
}

// Seat colour = highest risk band of the PC's open findings; the letter repeats it so colour is never the only cue.
function seatBand(e) { return (e.risk && e.risk.band) || "unknown"; }
function seatLetter(e) { return (e.risk && e.risk.letter) || "?"; }

function markerLabel(e) {
  const risk = e.risk && e.risk.top_score !== null ? `${SEAT_LABELS[seatBand(e)]} risk (top score ${e.risk.top_score})`
    : SEAT_LABELS[seatBand(e)];
  return `${e.hostname || e.agent_id}: ${risk}, ${PC_STATUS[e.status]}, ${CONNECTIVITY[e.connectivity]}`;
}

function seatDot(e) {
  return el("span", { class: "fp-dot", "aria-hidden": "true", text: seatLetter(e) });
}

function fpMarker(e) {
  const marker = el("button", {
    type: "button", class: `fp-marker band-${seatBand(e)} conn-${e.connectivity}`, "data-key": e.key,
    "data-band": seatBand(e), "aria-label": markerLabel(e), title: markerLabel(e),
  }, seatDot(e), el("span", { class: "fp-label", text: e.hostname || e.agent_id }));
  marker.style.left = `${e.position.x * 100}%`;
  marker.style.top = `${e.position.y * 100}%`;
  if (e.key === fpState.selectedKey) marker.classList.add("selected");
  attachDrag(marker, e);
  marker.addEventListener("keydown", (ev) => {
    const step = { ArrowLeft: [-0.01, 0], ArrowRight: [0.01, 0], ArrowUp: [0, -0.01], ArrowDown: [0, 0.01] }[ev.key];
    if (!step) return;
    ev.preventDefault();
    const clamp = (v) => Math.min(1, Math.max(0, Math.round(v * 10000) / 10000));
    savePosition(e, clamp(e.position.x + step[0]), clamp(e.position.y + step[1]));
  });
  return marker;
}

function fpTrayItem(e) {
  const item = el("button", { type: "button", class: `fp-tray-item band-${seatBand(e)} conn-${e.connectivity}`,
    "data-key": e.key, "aria-label": `${markerLabel(e)} (not placed)` },
  seatDot(e), el("span", { text: e.hostname || e.agent_id }),
  e.connectivity !== "online" ? el("span", { class: `badge badge-conn-${e.connectivity}`, text: CONNECTIVITY[e.connectivity] })
    : document.createTextNode(""));
  attachDrag(item, e);
  return item;
}

// Pointer drag: markers move within the plan; tray items are dropped onto it. A press without
// movement is a normal click (opens details).
function attachDrag(node, endpoint) {
  node.addEventListener("click", () => {
    if (fpState.justDragged) { fpState.justDragged = false; return; }
    showFpDetail(endpoint.key);
  });
  node.addEventListener("pointerdown", (down) => {
    if (down.button !== 0 || $("fp-stage").hidden) return;
    const start = [down.clientX, down.clientY];
    let ghost = null;
    const move = (ev) => {
      if (!ghost) {
        if (Math.hypot(ev.clientX - start[0], ev.clientY - start[1]) < 5) return;
        ghost = el("span", { class: `fp-marker fp-ghost band-${seatBand(endpoint)} conn-${endpoint.connectivity}` },
          seatDot(endpoint), el("span", { class: "fp-label", text: endpoint.hostname || endpoint.agent_id }));
        document.body.append(ghost);
        node.classList.add("dragging");
      }
      ghost.style.left = `${ev.clientX}px`;
      ghost.style.top = `${ev.clientY}px`;
    };
    const up = (ev) => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      if (!ghost) return;
      ghost.remove();
      node.classList.remove("dragging");
      fpState.justDragged = true;
      setTimeout(() => { fpState.justDragged = false; }, 0);
      const rect = $("fp-image").getBoundingClientRect();
      const x = (ev.clientX - rect.left) / rect.width;
      const y = (ev.clientY - rect.top) / rect.height;
      if (x < 0 || x > 1 || y < 0 || y > 1) {
        $("fp-message").textContent = "Dropped outside the floor plan; position unchanged.";
        return;
      }
      savePosition(endpoint, Math.round(x * 10000) / 10000, Math.round(y * 10000) / 10000);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  });
}

async function savePosition(endpoint, x, y) {
  try {
    const body = await fetchJson(`/api/positions?${sourceQuery()}`, {
      method: "PUT", headers: { ...APP_HEADER, "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: endpoint.key, x, y }),
    });
    endpoint.position = body.position;
    $("fp-message").textContent = `Saved position of ${endpoint.hostname || endpoint.key}.`;
  } catch (err) {
    $("fp-message").textContent = `Position not saved: ${err.message}`;
  }
  renderFloorplan();
  const marker = $("fp-markers").querySelector(`[data-key="${CSS.escape(endpoint.key)}"]`);
  if (marker && document.activeElement !== marker && endpoint.key === fpState.selectedKey) marker.focus();
}

async function removePosition(endpoint) {
  try {
    await fetchJson("/api/positions", { method: "DELETE", headers: { ...APP_HEADER, "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: endpoint.key }) });
    endpoint.position = null;
    $("fp-message").textContent = `Removed ${endpoint.hostname || endpoint.key} from the plan.`;
  } catch (err) {
    $("fp-message").textContent = `Not removed: ${err.message}`;
  }
  renderFloorplan();
  showFpDetail(endpoint.key);
}

async function showFpDetail(key) {
  fpState.selectedKey = key;
  for (const m of $("fp-markers").children) m.classList.toggle("selected", m.dataset.key === key);
  const panel = $("fp-detail");
  panel.hidden = false;
  panel.replaceChildren(el("p", { class: "muted", text: "Loading…" }));
  let e, risk;
  try {
    [e, risk] = await Promise.all([
      fetchJson(`/api/fleet/endpoint?${sourceQuery()}&id=${encodeURIComponent(key)}`).then((b) => b.endpoint),
      fetchJson(`/api/risk?${sourceQuery()}&endpoint=${encodeURIComponent(key)}`)
        .catch((err) => ({ error: err.message, findings: [], needs_data_count: 0 })),
    ]);
  } catch (err) {
    panel.replaceChildren(el("p", { class: "alert", text: `Could not load ${key}: ${err.message}` }));
    return;
  }
  if (fpState.selectedKey !== key) return;
  const failed = e.checks.filter((c) => c.status === "failed");
  // Raw Wazuh failures (all checks, mapped or not); only the first SEAT_TOP are listed here.
  const list = el("ul", { class: "fp-failed" }, ...failed.slice(0, SEAT_TOP).map((c) => {
    const open = el("button", { type: "button", class: "link-btn", text: c.name || "(unnamed check)" });
    open.addEventListener("click", () => openCheck(c));
    return el("li", {}, open, el("span", { class: "check-id", text: `ID ${c.id ?? "—"}` }),
      el("span", { class: "fp-remediation" }, document.createTextNode("Remediation: "), shortText(c.remediation, 110)));
  }));
  const cached = fleetState.fleet && fleetState.fleet.endpoints.find((x) => x.key === key);
  const actions = el("p", { class: "fp-actions" }, el("a", { href: `#/pc/${encodeURIComponent(key)}`, text: "Open full details" }));
  if (cached && cached.position) {
    const remove = el("button", { type: "button", class: "btn btn-secondary btn-small", text: "Remove from plan" });
    remove.addEventListener("click", () => removePosition(cached));
    actions.append(remove);
  }
  panel.replaceChildren(
    el("div", { class: "section-head" }, el("h2", { text: e.hostname || `Agent ${e.agent_id}` }),
      el("div", { class: "badges" }, el("span", { class: `badge badge-pc-${e.status}`, text: PC_STATUS[e.status] }),
        el("span", { class: `badge badge-conn-${e.connectivity}`, text: CONNECTIVITY[e.connectivity] }))),
    el("dl", { class: "facts fp-facts" },
      ...fact("Wazuh agent ID", e.agent_id),
      ...fact("Department", e.assigned ? e.department : el("span", { class: "unassigned", text: "Unassigned" })),
      ...fact("Location", locationText(e.location)),
      ...fact("Requirement compliance", reqRate(e)),
      ...fact("CIS benchmark (Wazuh SCA)", e.counts.pass_percentage === null ? "No passed/failed results"
        : `${formatPercent(e.counts.pass_percentage)} (${e.counts.passed} passed, ${e.counts.failed} failed)`),
      ...fact("Last seen", timeNode(e.last_seen))),
    el("h3", { text: `Open findings by priority (${risk.findings.length})` }),
    risk.error ? el("p", { class: "alert", text: `Priorities could not be loaded: ${risk.error}` })
      : risk.findings.length ? el("ol", { class: "fix-list fp-risk" }, ...risk.findings.slice(0, SEAT_TOP).map((f) => fixItem(f, true)))
        : el("p", { class: "muted", text: "No scored open findings on this PC." }),
    risk.findings.length > SEAT_TOP
      ? el("p", { class: "muted" }, document.createTextNode(`Showing the top ${SEAT_TOP} of ${risk.findings.length}. `),
        el("a", { href: "#/findings", text: "See all on the Findings tab" }))
      : document.createTextNode(""),
    risk.needs_data_count ? el("p", { class: "muted", text: `Needs data: ${risk.needs_data_count} unknown result(s), not scored.` })
      : document.createTextNode(""),
    // Raw Wazuh results, folded away: the prioritized findings above are what to act on.
    el("details", { class: "fp-raw" },
      el("summary", { text: `Failed checks (${failed.length}) — raw Wazuh results` }),
      el("p", { class: "muted", text: "All failed Wazuh checks, including ones outside the requirement catalogue (not prioritized)." }),
      failed.length ? list : el("p", { class: "muted", text: "No failed checks reported." }),
      failed.length > SEAT_TOP
        ? el("p", { class: "muted" }, document.createTextNode(`Showing ${SEAT_TOP} of ${failed.length}. `),
          el("a", { href: `#/pc/${encodeURIComponent(key)}`, text: "See all checks for this PC" }))
        : document.createTextNode("")),
    actions);
}

// Keep marker labels inside the plan at any window size: shift them sideways at the left/right edges
// and show them above the dot near the bottom edge. Re-run whenever the plan is resized.
function fitMarkerLabels() {
  if ($("fp-stage").hidden) return;
  const stage = $("fp-stage").getBoundingClientRect();
  for (const marker of $("fp-markers").children) {
    const label = marker.querySelector(".fp-label");
    label.style.removeProperty("--shift");
    marker.classList.remove("label-above");
    const r = label.getBoundingClientRect();
    if (r.bottom > stage.bottom) marker.classList.add("label-above");
    const shift = r.left < stage.left ? stage.left - r.left : r.right > stage.right ? stage.right - r.right : 0;
    if (shift) label.style.setProperty("--shift", `${shift}px`);
  }
}

$("fp-image").addEventListener("load", () => {
  const img = $("fp-image");
  if (img.naturalWidth && img.naturalHeight) {
    $("fp-stage").style.setProperty("--fp-aspect", String(img.naturalWidth / img.naturalHeight));
  }
  fitMarkerLabels();
});
if (window.ResizeObserver) new ResizeObserver(fitMarkerLabels).observe($("fp-stage"));
window.addEventListener("resize", fitMarkerLabels);

function renderFloorplan() {
  const fleet = fleetState.fleet;
  if (!fleet) return;
  const place = currentPlace();
  const plan = place && fpState.plans.find((p) => p.building === place[0] && p.floor === place[1]);
  const onThisFloor = fleet.endpoints.filter((e) => onFloor(e, place));
  const shown = onThisFloor.filter(fpMatches);
  const hasFloors = $("fp-floor").options.length > 0;
  $("fp-no-floors").hidden = hasFloors;
  $("fp-floor").hidden = !hasFloors; // an empty building/floor picker is just confusing
  $("fp-no-plan").hidden = !place || Boolean(plan);
  $("fp-stage").hidden = !plan;
  $("fp-help").hidden = !plan;
  $("fp-delete-plan").hidden = !plan;
  if (plan) {
    const src = `/api/floorplans/image?building=${encodeURIComponent(plan.building)}&floor=${encodeURIComponent(plan.floor)}&v=${encodeURIComponent(plan.uploaded_at)}`;
    if ($("fp-image").getAttribute("src") !== src) $("fp-image").setAttribute("src", src);
    $("fp-image").alt = `Floor plan: ${placeLabel(plan.building, plan.floor)}`;
  }
  $("fp-markers").replaceChildren(...(plan ? shown.filter((e) => e.position).map(fpMarker) : []));
  fitMarkerLabels();
  const unplaced = shown.filter((e) => !e.position);
  $("fp-tray").replaceChildren(...unplaced.map(fpTrayItem));
  $("fp-tray-empty").hidden = unplaced.length > 0;
  $("fp-tray-empty").textContent = place ? "Every PC on this floor that matches the filters is placed."
    : "No floor selected. Give PCs a building and floor on the Assets tab first.";
  $("fp-tray-count").textContent = unplaced.length ? `${unplaced.length} PC${unplaced.length === 1 ? "" : "s"}` : "";
  const missing = fleet.endpoints.filter((e) => !e.location.building || !e.location.floor).length;
  const sourceNote = fleet.source.is_sample
    ? "Sample PCs: markers appear only where an administrator placed them; no positions are generated."
    : "Live Wazuh PCs: markers appear only where an administrator placed them.";
  $("fp-note").textContent = `${sourceNote} ${missing ? `${missing} PC(s) have no building/floor assigned and cannot be placed until they are assigned on the Assets tab.` : ""}`;
}

async function showFloorplan(force) {
  const ok = await withLoading("floor plan", async () => {
    const [fleet, plans] = await Promise.all([getFleet(force), fetchJson("/api/floorplans")]);
    fpState.plans = plans.floor_plans;
    fpState.maxBytes = plans.max_bytes;
    const places = new Map();
    for (const e of fleet.endpoints) {
      if (e.location.building && e.location.floor) places.set(placeKey(e.location.building, e.location.floor), [e.location.building, e.location.floor]);
    }
    for (const p of fpState.plans) places.set(placeKey(p.building, p.floor), [p.building, p.floor]);
    const sorted = [...places.values()].sort((a, b) => placeLabel(...a).localeCompare(placeLabel(...b), undefined, { numeric: true }));
    const select = $("fp-floor");
    const wanted = select.dataset.pending ?? select.value;
    delete select.dataset.pending;
    select.replaceChildren(...sorted.map(([b, f]) => el("option", { value: placeKey(b, f), text: placeLabel(b, f) })));
    const withPlan = sorted.find(([b, f]) => fpState.plans.some((p) => p.building === b && p.floor === f));
    select.value = places.has(wanted) ? wanted : withPlan ? placeKey(...withPlan) : (select.options[0]?.value ?? "");
    const dept = $("fp-department");
    const deptValue = dept.value;
    const names = fleet.summary.departments.map((d) => d.name);
    dept.replaceChildren(el("option", { value: "", text: "All departments" }), ...names.map((n) => el("option", { value: n, text: n })));
    dept.value = names.includes(deptValue) ? deptValue : "";
    const place = currentPlace();
    if (place && !$("fp-up-building").value && !$("fp-up-floor").value) {
      $("fp-up-building").value = place[0];
      $("fp-up-floor").value = place[1];
    }
    $("fp-detail").hidden = true;
    fpState.selectedKey = null;
    renderFloorplan();
  });
  $("view-floorplan").hidden = !ok;
}

$("fp-floor").addEventListener("change", () => {
  const place = currentPlace();
  if (place) { $("fp-up-building").value = place[0]; $("fp-up-floor").value = place[1]; }
  $("fp-detail").hidden = true;
  renderFloorplan();
});
$("fp-department").addEventListener("change", renderFloorplan);
$("fp-status").addEventListener("change", renderFloorplan);
$("fp-urgent").addEventListener("change", renderFloorplan);

$("fp-upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("fp-up-file").files[0];
  const building = $("fp-up-building").value.trim();
  const floor = $("fp-up-floor").value.trim();
  const ext = file ? file.name.slice(file.name.lastIndexOf(".")).toLowerCase() : "";
  // Mirrors the server checks; the server also verifies the file signature.
  if (!file || !Object.values(IMAGE_EXTENSIONS).flat().includes(ext)) {
    $("fp-message").textContent = "Not uploaded: choose a PNG, JPEG or WebP image.";
    return;
  }
  if (file.size > fpState.maxBytes) {
    $("fp-message").textContent = `Not uploaded: the image is larger than ${fpState.maxBytes / (1024 * 1024)} MB.`;
    return;
  }
  const form = new FormData();
  form.append("building", building);
  form.append("floor", floor);
  form.append("file", file);
  try {
    await fetchJson("/api/floorplans", { method: "POST", body: form, headers: APP_HEADER });
    $("fp-floor").dataset.pending = placeKey(building, floor);
    $("fp-up-file").value = "";
    await showFloorplan();
    $("fp-message").textContent = `Uploaded floor plan for ${placeLabel(building, floor)}.`;
  } catch (err) {
    $("fp-message").textContent = `Not uploaded: ${err.message}`;
  }
});

$("fp-delete-plan").addEventListener("click", async () => {
  const place = currentPlace();
  if (!place || !confirm(`Delete the floor plan for ${placeLabel(...place)}? Saved marker positions are kept.`)) return;
  try {
    await fetchJson("/api/floorplans", { method: "DELETE", headers: { ...APP_HEADER, "Content-Type": "application/json" },
      body: JSON.stringify({ building: place[0], floor: place[1] }) });
    $("fp-floor").dataset.pending = placeKey(...place);
    await showFloorplan();
    $("fp-message").textContent = `Deleted the floor plan for ${placeLabel(...place)}.`;
  } catch (err) {
    $("fp-message").textContent = `Not deleted: ${err.message}`;
  }
});

// ---- Admin: accounts and requirement catalogue ----

async function userRequest(method, url, body) {
  $("user-message").textContent = "";
  try {
    const r = await fetchJson(url, { method, headers: { ...APP_HEADER, "Content-Type": "application/json" },
      body: JSON.stringify(body) });
    renderUsers(r.users);
    $("user-message").textContent = "Saved.";
  } catch (err) {
    $("user-message").textContent = `Not saved: ${err.message}`;
  }
}

function renderUsers(list) {
  $("users-table").querySelector("tbody").replaceChildren(...list.map((u) => {
    const role = el("select", { "aria-label": `Role of ${u.username}` },
      el("option", { value: "reviewer", text: "Reviewer" }), el("option", { value: "admin", text: "Administrator" }));
    role.value = u.role;
    role.addEventListener("change", () => userRequest("PATCH", `/api/users/${u.id}`, { role: role.value }));
    const toggle = el("button", { type: "button", class: "btn btn-secondary btn-small", text: u.active ? "Disable" : "Enable" });
    toggle.addEventListener("click", () => userRequest("PATCH", `/api/users/${u.id}`, { active: !u.active }));
    const reset = el("button", { type: "button", class: "btn btn-secondary btn-small", text: "Reset password" });
    reset.addEventListener("click", () => {
      const password = prompt(`New password for ${u.username} (12+ characters):`);
      if (password) userRequest("PATCH", `/api/users/${u.id}`, { password });
    });
    return el("tr", {}, el("td", { text: u.username }), el("td", {}, role),
      el("td", { text: u.active ? (u.locked_until ? `Yes (locked until ${formatTime(u.locked_until)})` : "Yes") : "No" }),
      el("td", {}, timeNode(u.last_login_at, "Never")), el("td", { class: "row-actions" }, toggle, reset));
  }));
}

async function showAdmin() {
  const ok = await withLoading("administration", async () => {
    const [usersBody, reqs] = await Promise.all([fetchJson("/api/users"), fetchJson("/api/requirements")]);
    renderUsers(usersBody.users);
    $("req-version").textContent = `(version ${reqs.version})`;
    $("req-table").querySelector("tbody").replaceChildren(...reqs.requirements.map((r) => el("tr", {},
      el("td", { text: r.id }), el("td", { text: r.area || "" }), el("td", { text: r.title }),
      el("td", {}, el("span", { class: `badge band-badge band-${{ critical: "critical", high: "high", medium: "medium", low: "low" }[r.severity]}`, text: r.severity })),
      el("td", { class: "num", text: r.mapped_checks }))));
  });
  $("view-admin").hidden = !ok;
}

$("user-form").addEventListener("submit", (event) => {
  event.preventDefault();
  userRequest("POST", "/api/users", { username: $("user-username").value.trim(), password: $("user-password").value,
    role: $("user-role").value });
  $("user-password").value = "";
});

async function loadUser() {
  try {
    const me = await fetchJson("/api/me");
    fleetState.user = me;
    $("user-name").textContent = `${me.username} · ${me.role === "admin" ? "Administrator" : "Reviewer"}`;
    $("logout-btn").hidden = !me.login_required;
    $("nav-admin").hidden = me.role !== "admin";
  } catch { /* fetchJson already redirects to the sign-in page on 401 */ }
}

$("logout-btn").addEventListener("click", async () => {
  try { await fetchJson("/logout", { method: "POST", headers: APP_HEADER }); } catch { /* go to sign-in anyway */ }
  location.href = "/login";
});

function updateReportLink() { $("report-link").href = `/report?${sourceQuery()}`; }

// ---- Routing ----

function route() {
  const [, view = "overview", param] = (location.hash || "#/overview").match(/^#\/([a-z]+)(?:\/(.+))?$/) || [];
  const name = VIEWS.includes(view) ? view : "overview";
  for (const v of VIEWS) $(`view-${v}`).hidden = true;
  for (const link of document.querySelectorAll("[data-nav]")) {
    const active = link.dataset.nav === name || (name === "pc" && link.dataset.nav === "map");
    if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current");
  }
  const fleetView = name !== "report";
  $("fleet-views").hidden = !fleetView;
  document.querySelector(".source-picker").hidden = !fleetView;
  if (name === "report") { $("view-report").hidden = false; return; }
  if (name === "pc" && param) showPc(decodeURIComponent(param));
  else if (name === "map") showMap();
  else if (name === "floorplan") showFloorplan();
  else if (name === "findings") showFindings();
  else if (name === "assets") showAssets();
  else if (name === "admin") showAdmin();
  else showOverview();
}

$("fleet-source").value = fleetState.source;
$("fleet-source").addEventListener("change", () => {
  fleetState.source = $("fleet-source").value;
  try { localStorage.setItem("fleet-source", fleetState.source); } catch { /* storage blocked */ }
  invalidateFleet();
  updateReportLink();
  route();
});
function scanSummary(scan, warnings) {
  const parts = [`Scan finished ${formatTime(new Date().toISOString())}`,
    `${scan.created} new`, `${scan.reopened} reopened`, `${scan.cleared} cleared`, `${scan.verified} verified`];
  if (warnings.length) parts.push(`${warnings.length} source warning(s)`);
  return parts.join(" · ");
}

// "Scan now": re-read every source (read-only), re-run the compliance check and verification, report changes.
async function scanNow() {
  const button = $("fleet-refresh");
  if (button.disabled) return;
  button.disabled = true;
  button.textContent = "Scanning…";
  setFleetError("");
  $("scan-result").textContent = "";
  invalidateFleet();
  try {
    const body = await getFleet(true);
    route();
    $("scan-result").textContent = body.scan ? scanSummary(body.scan, body.warnings || [])
      : `Scan finished ${formatTime(new Date().toISOString())}`;
  } catch (err) {
    setFleetError(`Scan failed: ${err.message}`);
  } finally {
    button.disabled = false;
    button.textContent = "Scan now";
  }
}

$("fleet-refresh").addEventListener("click", scanNow);
for (const id of ["map-search", "map-department", "map-status"]) {
  $(id).addEventListener(id === "map-search" ? "input" : "change", renderMap);
}
$("pc-filter-status").addEventListener("change", renderChecks);
$("pc-filter-text").addEventListener("input", renderChecks);
window.addEventListener("hashchange", route);
updateReportLink();
loadUser();
route();
