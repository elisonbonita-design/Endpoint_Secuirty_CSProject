"use strict";

// All server data is inserted with textContent / DOM nodes, never innerHTML.

const $ = (id) => document.getElementById(id);
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024;
const ALL_POLICIES = "__all__";
const STATUS_LABELS = { passed: "passed", failed: "failed", not_applicable: "not applicable", unknown: "unknown" };
let currentFindings = [];
let currentSource = null; // the loaded single report: sample, wazuh (with agent and policy) or upload

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "text") node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) node.append(child);
  return node;
}

function formatPercent(value) {
  return value === null || value === undefined ? "N/A" : `${value.toFixed(2)}%`;
}

function meter(value, small) {
  const fill = el("div", { class: "meter-fill" });
  fill.style.width = `${value ?? 0}%`;
  return el("div", { class: small ? "meter small" : "meter", "aria-hidden": "true" }, fill);
}

function showError(message) {
  $("error").textContent = message;
  $("error").hidden = false;
}

function clearMessages() {
  $("error").hidden = true;
  $("error").textContent = "";
  $("status").textContent = "";
}

function renderOverall(overall) {
  $("pass-rate").textContent = formatPercent(overall.pass_percentage);
  $("pass-meter").style.width = `${overall.pass_percentage ?? 0}%`;
  $("count-passed").textContent = overall.passed;
  $("count-failed").textContent = overall.failed;
  $("count-not_applicable").textContent = overall.not_applicable ?? 0;
  $("count-unknown").textContent = overall.unknown;
  $("count-total").textContent = overall.total;
}

function renderFrameworks(frameworks) {
  const names = Object.keys(frameworks);
  const tbody = $("frameworks-table").querySelector("tbody");
  tbody.replaceChildren();
  for (const name of names) {
    const fw = frameworks[name];
    tbody.append(el("tr", {},
      el("td", { text: name }),
      el("td", { class: "num", text: fw.passed }),
      el("td", { class: "num", text: fw.failed }),
      el("td", { class: "num", text: fw.not_applicable ?? 0 }),
      el("td", { class: "num", text: fw.unknown }),
      el("td", {}, el("div", { class: "rate-cell" },
        meter(fw.pass_percentage, true), el("span", { text: formatPercent(fw.pass_percentage) }))),
    ));
  }
  $("frameworks-table").hidden = names.length === 0;
  $("frameworks-empty").hidden = names.length > 0;
  $("framework-count").textContent = names.length ? `${names.length} framework${names.length === 1 ? "" : "s"}` : "";
}

function textOrNone(value) {
  return value ? document.createTextNode(value) : el("span", { class: "none", text: "—" });
}

function complianceCell(compliance) {
  const names = Object.keys(compliance || {});
  if (!names.length) return textOrNone(null);
  const list = el("ul", { class: "mapping" });
  for (const name of names) {
    list.append(el("li", {}, el("span", { class: "fw", text: name }), document.createTextNode(`: ${compliance[name].join(", ")}`)));
  }
  return list;
}

function findingRow(f) {
  const nameCell = el("td", { "data-label": "Check" }, textOrNone(f.name));
  if (f.id !== null && f.id !== undefined) nameCell.append(el("span", { class: "check-id", text: `ID ${f.id}` }));

  const label = STATUS_LABELS[f.status] || f.status;
  const resultCell = el("td", { "data-label": "Result" }, el("span", { class: `badge badge-${f.status}`, text: label }));
  if (f.result && f.result.toLowerCase() !== label) resultCell.append(el("span", { class: "raw-result", text: f.result }));

  return el("tr", {},
    nameCell,
    resultCell,
    el("td", { "data-label": "Reason / evidence" }, textOrNone(f.reason)),
    el("td", { "data-label": "Remediation" }, textOrNone(f.remediation)),
    el("td", { "data-label": "Compliance" }, complianceCell(f.compliance)),
  );
}

function renderFindings() {
  const status = $("filter-status").value;
  const query = $("filter-text").value.trim().toLowerCase();
  const matches = currentFindings.filter((f) => {
    if (status !== "all" && f.status !== status) return false;
    if (!query) return true;
    const haystack = [f.id, f.name, f.reason, f.remediation, ...Object.keys(f.compliance || {})]
      .filter((v) => v !== null && v !== undefined).join(" ").toLowerCase();
    return haystack.includes(query);
  });
  $("findings-table").querySelector("tbody").replaceChildren(...matches.map(findingRow));
  $("findings-table").hidden = matches.length === 0;
  $("findings-empty").hidden = matches.length > 0;
}

function renderPolicies(report) {
  const policies = report.policies || [];
  $("policy-bar").hidden = policies.length === 0;
  if (!policies.length) return;
  const total = policies.reduce((sum, p) => sum + p.checks, 0);
  const options = [el("option", { value: ALL_POLICIES, text: `All policies (${total} checks)` })];
  for (const p of policies) options.push(el("option", { value: p.name, text: `${p.name} (${p.checks} checks)` }));
  $("policy-select").replaceChildren(...options);
  $("policy-select").value = report.policy || ALL_POLICIES;
}

function renderReport(report) {
  $("source-name").textContent = report.source;
  renderPolicies(report);
  renderOverall(report.overall);
  renderFrameworks(report.frameworks);
  currentFindings = report.findings;
  renderFindings();
  $("report").hidden = false;
}

async function loadReport(request, label, source) {
  clearMessages();
  $("status").textContent = `Loading ${label}…`;
  try {
    const response = await request;
    let body = null;
    try { body = await response.json(); } catch { /* non-JSON error page */ }
    if (!response.ok) {
      const reason = (body && body.error) || `Request failed (HTTP ${response.status}).`;
      const kept = $("report").hidden ? "" : " The report below is unchanged.";
      showError(`Could not load ${label}: ${reason}${kept}`);
      $("status").textContent = "";
      return;
    }
    renderReport(body);
    if (source.mode === "wazuh") source.policy = body.policy || ALL_POLICIES;
    currentSource = source;
    $("status").textContent = "";
  } catch {
    showError("Could not reach the dashboard server.");
    $("status").textContent = "";
  }
}

$("load-sample").addEventListener("click", () => loadReport(fetch("/api/sample"), "sample data", { mode: "sample" }));

// The browser blocks malformed IDs itself (pattern attribute); clear any stale error so its hint stands alone.
$("agent-id").addEventListener("invalid", clearMessages);

function loadWazuh(agentId, policy) {
  const query = `agent_id=${encodeURIComponent(agentId)}` + (policy ? `&policy=${encodeURIComponent(policy)}` : "");
  loadReport(fetch(`/api/wazuh/sca?${query}`), `Wazuh agent ${agentId}`, { mode: "wazuh", agent_id: agentId });
}

$("wazuh-form").addEventListener("submit", (event) => {
  event.preventDefault();
  loadWazuh($("agent-id").value.trim()); // server picks the default policy (CIS when present)
});

$("policy-select").addEventListener("change", () => {
  if (currentSource && currentSource.mode === "wazuh") loadWazuh(currentSource.agent_id, $("policy-select").value);
});

$("file-input").addEventListener("change", (event) => {
  const file = event.target.files[0];
  if (!file) return;
  // Mirrors the server's 2 MB limit: the dev server can drop oversized uploads mid-transfer,
  // which the browser would only report as a network failure.
  if (file.size > MAX_UPLOAD_BYTES) {
    clearMessages();
    const kept = $("report").hidden ? "" : " The report below is unchanged.";
    showError(`Could not load ${file.name}: File is too large. The limit is 2 MB.${kept}`);
    event.target.value = "";
    return;
  }
  const form = new FormData();
  form.append("file", file);
  loadReport(fetch("/api/upload", { method: "POST", body: form }), file.name, { mode: "upload", file });
  event.target.value = "";
});

$("filter-status").addEventListener("change", renderFindings);
$("filter-text").addEventListener("input", renderFindings);

loadReport(fetch("/api/sample"), "sample data", { mode: "sample" });
