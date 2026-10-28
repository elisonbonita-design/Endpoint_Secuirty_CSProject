// Browser flows for the fleet dashboard. Run against tests/browser/serve_e2e.py (fresh DB, no Indexer):
//   python tests/browser/serve_e2e.py 5001
//   playwright-cli open http://127.0.0.1:5001/
//   playwright-cli run-code --filename=tests/browser/dashboard_flows.js
async page => {
  const BASE = "http://127.0.0.1:5001/";
  const passed = [];
  const errors = [];
  const failedResponses = [];
  page.on("response", (r) => { if (r.status() >= 400) failedResponses.push(`${r.status()} ${new URL(r.url()).pathname}`); });
  // Failed responses are asserted exactly at the end, so the browser's "Failed to load resource" lines are skipped here.
  page.on("console", (m) => { if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  const check = (cond, name) => { if (!cond) throw new Error(`FAILED: ${name}`); passed.push(name); };
  const text = (sel) => page.locator(sel).first().innerText();
  const cards = () => page.locator("#map-groups .pc-card:visible").count();

  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto(BASE);
  // Start from no saved assignments so reruns are repeatable.
  await page.evaluate(async () => {
    try { localStorage.clear(); } catch {}
    const { assignments } = await (await fetch("/api/assets")).json();
    for (const a of assignments) {
      await fetch("/api/assets", { method: "DELETE", body: JSON.stringify({ key_type: a.key_type, key_value: a.key_value }),
        headers: { "Content-Type": "application/json", "X-Requested-With": "compliance-dashboard" } });
    }
  });

  // Overview: PC status and check status are separate.
  await page.goto(`${BASE}#/overview`);
  await page.reload();
  await page.locator("#pc-total", { hasText: "7" }).waitFor();
  check((await text("#source-banner")).includes("SAMPLE DATA"), "sample data is labelled");
  check(await text("#pc-compliant") === "1" && await text("#pc-noncompliant") === "4"
    && await text("#pc-unknown") === "2" && await text("#pc-offline") === "3", "overview PC counts");
  check(await text("#chk-total") === "36" && await text("#chk-unknown") === "2"
    && await text("#chk-na") === "2" && await text("#chk-rate") === "68.75%", "overview check counts");

  // Endpoint map: grouping and filters.
  await page.click("[data-nav=map]");
  await page.locator("#map-groups .pc-card").first().waitFor();
  check(await cards() === 7, "map shows all 7 PCs");
  check(await page.locator('.dept-group[data-department="Unassigned"] .pc-card').count() === 2, "Unassigned group");
  check(await page.locator('.pc-card[data-key="S01"]').getAttribute("data-floor") === "2", "card carries floor data");
  await page.selectOption("#map-department", "IT (sample)");
  check(await cards() === 2, "department filter");
  await page.selectOption("#map-department", "");
  await page.selectOption("#map-status", "noncompliant");
  check(await cards() === 4, "status filter noncompliant");
  await page.selectOption("#map-status", "offline_or_stale");
  check(await cards() === 3, "status filter offline/stale");
  await page.selectOption("#map-status", "");
  await page.fill("#map-search", "lab");
  check(await cards() === 1, "search filter by hostname");
  await page.fill("#map-search", "S04");
  check(await cards() === 1, "search filter by agent ID");
  await page.fill("#map-search", "zzz");
  check(await page.locator("#map-empty").isVisible(), "empty state when nothing matches");
  await page.fill("#map-search", "");

  // PC details and failed-check drill-down.
  await page.click('.pc-card[data-key="S01"]');
  await page.locator("#pc-title", { hasText: "SAMPLE-FIN-01" }).waitFor();
  check(page.url().endsWith("#/pc/S01"), "card opens PC details");
  const facts = await text("#pc-facts");
  check(facts.includes("Finance (sample)") && facts.includes("HQ · Floor 2 · Room 201") && facts.includes("S01"), "PC facts");
  check(await page.locator("#pc-checks tbody tr").count() === 6, "all checks listed");
  await page.selectOption("#pc-filter-status", "failed");
  check(await page.locator("#pc-checks tbody tr").count() === 2, "check status filter");
  await page.locator("#pc-checks tbody tr .link-btn").first().click();
  await page.locator("#check-dialog[open]").waitFor();
  const dlg = await text("#check-dialog");
  check(dlg.includes("Noncompliant") && /recommended remediation/i.test(dlg) && dlg.includes("Minimum password length"), "failed check dialog");
  await page.click("#check-dialog .dialog-close button");
  check(!(await page.locator("#check-dialog[open]").count()), "dialog closes");

  // Unassigned PC details.
  await page.goto(`${BASE}#/pc/S06`);
  await page.locator("#pc-title", { hasText: "SAMPLE-LAB-01" }).waitFor();
  check((await text("#pc-facts")).includes("Unassigned"), "missing metadata shows Unassigned");

  // Findings.
  await page.click("[data-nav=findings]");
  await page.locator("#raw-results > summary").click();   // the raw Wazuh list is collapsed by default
  await page.locator(".prio-item").first().waitFor();
  const top = page.locator(".prio-item").first();
  check(await top.getAttribute("data-check-id") === "S2" && (await top.innerText()).includes("4 PCs noncompliant"), "top finding grouped");
  check((await text("#findings-basis")).includes("no risk score"), "ranking basis explained");

  // Assets: edit, CSV import (valid + invalid), delete.
  await page.click("[data-nav=assets]");
  await page.locator('#asset-endpoints tr[data-key="S06"]').waitFor();
  await page.locator('#asset-endpoints tr[data-key="S06"] button').click();
  check(await page.inputValue("#asset-key-value") === "S06", "edit pre-fills agent ID");
  await page.fill("#asset-department", "Lab (test)");
  await page.fill("#asset-floor", "1");
  await page.click("#asset-form button[type=submit]");
  await page.locator("#asset-message", { hasText: "Saved assignment for S06" }).waitFor();
  check((await page.locator('#asset-endpoints tr[data-key="S06"]').innerText()).includes("Lab (test)"), "assignment saved");
  await page.setInputFiles("#asset-csv", { name: "assets.csv", mimeType: "text/csv",
    buffer: Buffer.from("agent_id,hostname,department,building,floor,room\nS07,,Reception (test),HQ,0,R1\n") });
  await page.locator("#asset-message", { hasText: "Imported 1" }).waitFor();
  check((await page.locator('#asset-endpoints tr[data-key="S07"]').innerText()).includes("Reception (test)"), "CSV import");
  await page.setInputFiles("#asset-csv", { name: "bad.csv", mimeType: "text/csv",
    buffer: Buffer.from("agent_id,department\nS01,Ok\n,No key\n") });
  await page.locator("#asset-message", { hasText: "Nothing was imported" }).waitFor();
  check(true, "invalid CSV rejected");
  await page.click("[data-nav=overview]");
  await page.locator("#pc-unassigned", { hasText: "0" }).waitFor();
  check(true, "overview reflects new assignments");
  await page.click("[data-nav=assets]");
  await page.evaluate(() => { window.confirm = () => true; }); // CLI intercepts native dialogs
  await page.locator("#asset-saved tr", { hasText: "S06" }).getByRole("button", { name: "Delete" }).click();
  await page.locator("#asset-message", { hasText: "Deleted S06" }).waitFor();
  check((await page.locator('#asset-endpoints tr[data-key="S06"]').innerText()).includes("Unassigned"), "delete restores Unassigned");

  // Live source without an Indexer: clear error, no fabricated data.
  await page.selectOption("#fleet-source", "wazuh");
  await page.locator("#fleet-error", { hasText: "not configured" }).waitFor();
  check(await page.locator("#source-banner").isHidden() && await page.locator("#view-assets").isHidden(), "live error shows no data");
  // Scan now against the live source with no Indexer: clear error, button usable again.
  await page.click("#fleet-refresh");
  await page.locator("#fleet-error", { hasText: "Scan failed" }).waitFor();
  check(await page.locator("#fleet-refresh").isEnabled() && await text("#fleet-refresh") === "Scan now",
    "failed scan re-enables the button");
  await page.selectOption("#fleet-source", "sample");
  await page.locator('#asset-endpoints tr[data-key="S01"]').waitFor();

  // Scan now on sample data: re-reads, re-checks and reports what changed.
  await page.click("#fleet-refresh");
  await page.locator("#scan-result", { hasText: "Scan finished" }).waitFor();
  check(/0 new · 0 reopened · 0 cleared · 0 verified/.test(await text("#scan-result")), "repeat scan reports no changes");
  check(await page.locator("#fleet-error").isHidden() && await page.locator("#fleet-refresh").isEnabled(), "scan succeeds");

  // Existing single report: sample + JSON upload still work.
  await page.click("[data-nav=report]");
  await page.locator("#source-name", { hasText: "Bundled sample" }).waitFor();
  check(await page.locator(".source-picker").isHidden(), "report view hides fleet source picker");
  await page.setInputFiles("#file-input", { name: "upload.json", mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify([{ check: { id: "U1", name: "Uploaded", result: "failed" } }])) });
  await page.locator("#source-name", { hasText: "upload.json" }).waitFor();
  check(await text("#count-failed") === "1", "JSON upload still works");

  // Phone width: no horizontal page scroll.
  await page.setViewportSize({ width: 390, height: 844 });
  for (const view of ["overview", "map", "pc/S01", "findings", "assets"]) {
    await page.goto(`${BASE}#/${view}`);
    await page.waitForLoadState("networkidle");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    check(overflow <= 0, `no horizontal scroll at 390px: ${view}`);
  }
  await page.setViewportSize({ width: 1280, height: 800 });

  check(JSON.stringify(failedResponses) === JSON.stringify(["400 /api/assets/import", "503 /api/fleet", "503 /api/fleet"]),
    `only the intentional error responses occurred (${failedResponses.join(", ")})`);
  check(errors.length === 0, `no console errors (${errors.join(" | ")})`);
  return `${passed.length} browser checks passed`;
}
