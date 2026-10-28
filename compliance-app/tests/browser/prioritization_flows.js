// Browser flows for risk prioritization (Fix first, prioritized findings, floor-plan seat bands, explanations).
// Run against tests/browser/serve_e2e.py on port 5001 (fresh DB, no Indexer, local AI off), from compliance-app:
//   playwright-cli run-code --filename=tests/browser/prioritization_flows.js
async page => {
  const BASE = "http://127.0.0.1:5001/";
  const PLAN = "tests/fixtures/floorplan_test.png";
  const H = { "Content-Type": "application/json", "X-Requested-With": "compliance-dashboard" };
  const passed = [];
  const errors = [];
  const failedResponses = [];
  page.on("response", (r) => { if (r.status() >= 400) failedResponses.push(`${r.status()} ${new URL(r.url()).pathname}`); });
  page.on("console", (m) => { if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  const check = (cond, name) => { if (!cond) throw new Error(`FAILED: ${name}`); passed.push(name); };
  const text = (sel) => page.locator(sel).innerText();

  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(BASE);
  // Clean state, then: S01 handles client data and is an IT admin PC; S01 and S02 placed on HQ floor 2.
  await page.evaluate(async (headers) => {
    try { localStorage.clear(); } catch {}
    const { assignments } = await (await fetch("/api/assets")).json();
    for (const a of assignments) await fetch("/api/assets", { method: "DELETE", headers, body: JSON.stringify(a) });
    for (const id of ["S01", "S02", "S03", "S04", "S05", "S06", "S07"]) {
      await fetch("/api/positions", { method: "DELETE", headers, body: JSON.stringify({ agent_id: id }) });
    }
    await fetch("/api/assets", { method: "PUT", headers, body: JSON.stringify({ key_type: "agent_id", key_value: "S01",
      department: "Finance (sample)", building: "HQ", floor: "2", room: "201", handles_client_data: true, role: "it_admin" }) });
  }, H);
  await page.goto(`${BASE}#/floorplan`);
  await page.locator("#fp-floor option").first().waitFor({ state: "attached" });
  await page.selectOption("#fp-floor", { label: "HQ · Floor 2" });
  if (await page.locator("#fp-no-plan").isVisible()) {
    await page.setInputFiles("#fp-up-file", PLAN);
    await page.click("#fp-upload-form button[type=submit]");
    await page.locator("#fp-message", { hasText: "Uploaded floor plan" }).waitFor();
  }
  await page.evaluate(async (headers) => {
    for (const [id, x, y] of [["S01", 0.3, 0.4], ["S02", 0.7, 0.4]]) {
      await fetch("/api/positions?source=sample", { method: "PUT", headers, body: JSON.stringify({ agent_id: id, x, y }) });
    }
  }, H);
  failedResponses.length = 0; // 404s from deleting positions that did not exist are expected

  // Overview: Fix first panel.
  await page.goto(`${BASE}#/overview`);
  await page.reload();
  await page.locator("#fix-first-list .fix-item").first().waitFor();
  const items = await page.locator("#fix-first-list .fix-item").count();
  check(items === 10, `fix first shows top 10 (${items})`);
  const first = await page.locator("#fix-first-list .fix-item").first().innerText();
  // S01: BitLocker off (collector, critical 40) + Defender off event on the same PC (15) + client data/IT admin (20) + time (10).
  check(first.includes("Critical · 85") && first.includes("SAMPLE-FIN-01") && first.includes("HQ · Floor 2 · Room 201")
    && first.includes("BitLocker"), "top item: band, score, endpoint, seat, source");
  check(first.includes("IT admin role (8)") && first.includes("handles client data (12)")
    && first.includes("Defender real-time protection off on this endpoint (15)") && /open \d+ days/.test(first),
    "reason and days open shown");
  check(await text("#needs-data-count") === "2", "needs data count");
  const tiles = await Promise.all(["critical", "high", "medium", "low", "needs"].map((b) => text(`#band-count-${b}`)));
  check(tiles[0] === "1" && tiles[4] === "2" && tiles.every((t) => /^\d+$/.test(t)), `band tiles ${tiles.join("/")}`);
  check((await text("#risk-basis")).includes("weights v1.0"), "weights version shown");

  // Explain with the local AI off: rule-based fallback, never an AI label.
  await page.locator("#fix-first-list .fix-item").first().locator("summary", { hasText: "Explain, review and history" }).click();
  await page.locator("#fix-first-list .fix-item").first().getByRole("button", { name: "Explain" }).click();
  const explained = page.locator("#fix-first-list .fix-item").first().locator(".explain-result");
  await explained.waitFor();
  const explainText = await explained.innerText();
  check(explainText.includes("Rule-based explanation") && explainText.includes("Remediation")
    && !explainText.includes("AI-generated"), "AI off: rule-based explanation and remediation");

  await page.click("#daily-summary-btn");
  await page.locator("#daily-summary .explain-result").waitFor();
  check((await text("#daily-summary")).includes("Counts only"), "daily summary falls back to counts");

  // Findings: prioritized table, sorting and band filter.
  await page.click("[data-nav=findings]");
  await page.locator("#risk-table tbody tr").first().waitFor();
  const scores = async () => (await page.locator("#risk-table tbody tr td:first-child").allInnerTexts()).map(Number);
  const desc = await scores();
  check(desc.length > 10 && desc.every((s, i) => i === 0 || desc[i - 1] >= s), "sorted by score, highest first");
  await page.click('#risk-table .sort-btn[data-sort="score"]');
  const asc = await scores();
  check(asc.every((s, i) => i === 0 || asc[i - 1] <= s), "score sort toggles to ascending");
  check(await page.locator('#risk-table th[aria-sort="ascending"]').count() === 1, "aria-sort updated");
  await page.selectOption("#risk-band", "high");
  const bands = await page.locator("#risk-table tbody tr td:nth-child(2)").allInnerTexts();
  check(bands.length > 0 && bands.every((b) => b === "High"), "band filter");
  check(await text("#needs-data-total") === "2", "needs data listed separately");
  check(!(await page.locator("#raw-results").getAttribute("open")), "raw Wazuh list collapsed by default");
  await page.locator("#raw-results > summary").click();
  check((await text(".prio-list")).includes("PCs noncompliant"), "existing grouped list kept");

  // Floor plan: seat colour by band, letter on the dot, legend, urgent filter, per-seat list.
  await page.click("[data-nav=floorplan]");
  await page.locator('#fp-markers [data-key="S01"]').waitFor();
  const s01 = page.locator('#fp-markers [data-key="S01"]');
  check(await s01.getAttribute("data-band") === "critical" && await s01.locator(".fp-dot").innerText() === "C", "S01 critical, letter C");
  check((await s01.getAttribute("aria-label")).includes("Critical risk (top score 85)"), "band in accessible name");
  const s02 = page.locator('#fp-markers [data-key="S02"]');
  check(await s02.getAttribute("data-band") === "clear" && await s02.locator(".fp-dot").innerText() === "✓", "S02 green, no open findings");
  const dotColor = (loc) => loc.locator(".fp-dot").evaluate((d) => getComputedStyle(d).backgroundColor);
  check(await dotColor(s01) !== await dotColor(s02), "different colours for different bands");
  check((await page.locator(".legend").last().innerText()).includes("Unknown results only"), "legend lists bands");
  await page.check("#fp-urgent");
  check(await page.locator("#fp-markers .fp-marker").count() === 1 && await s01.isVisible(), "Critical/High filter");
  await page.uncheck("#fp-urgent");
  await s01.click();
  await page.locator("#fp-detail .fp-risk .fix-item").first().waitFor();
  const detail = await text("#fp-detail");
  check(/Open findings by priority \(4\)/.test(detail) && /Failed checks \(2\)/.test(detail), "seat lists findings from all sources");
  const seatScores = (await page.locator("#fp-detail .fp-risk .band-badge").allInnerTexts()).map((t) => Number(t.split("·")[1]));
  check(seatScores[0] >= seatScores[1], "seat findings sorted by score");

  // PC page: requirement compliance shown separately from the CIS benchmark score.
  await page.goto(`${BASE}#/pc/S01`);
  await page.locator("#pc-req-table tbody tr").first().waitFor();
  const reqRows = await page.locator("#pc-req-table tbody tr").count();
  const firstStatus = await page.locator("#pc-req-table tbody tr td:nth-child(3)").first().innerText();
  check(reqRows === 27 && firstStatus === "Non-compliant", `requirements listed, failing first (${reqRows}, ${firstStatus})`);
  check(/%/.test(await text("#pc-req-rate")) && /%/.test(await text("#pc-rate")), "both measures shown");
  await page.selectOption("#pc-req-filter", "compliant");
  const shown = await page.locator("#pc-req-table tbody tr td:nth-child(3)").allInnerTexts();
  check(shown.length > 0 && shown.every((t) => t === "Compliant"), "requirement filter");

  // Assets form keeps the risk fields.
  await page.click("[data-nav=assets]");
  await page.locator('#asset-endpoints tr[data-key="S01"] button').click();
  check(await page.inputValue("#asset-role") === "it_admin" && await page.isChecked("#asset-client-data"), "asset risk fields pre-filled");
  check((await text("#asset-saved")).includes("IT admin"), "saved assignments show role");

  // Phone width: no horizontal scroll.
  await page.setViewportSize({ width: 390, height: 844 });
  for (const view of ["overview", "findings", "floorplan"]) {
    await page.goto(`${BASE}#/${view}`);
    await page.waitForTimeout(400);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    check(overflow <= 0, `no horizontal scroll at 390px on ${view} (${overflow})`);
  }

  check(errors.length === 0, `no console errors ${JSON.stringify(errors)}`);
  check(failedResponses.length === 0, `no failed requests ${JSON.stringify(failedResponses)}`);
  return `${passed.length} prioritization checks passed`;
}
