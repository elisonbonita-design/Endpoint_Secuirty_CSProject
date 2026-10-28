// Browser flows for the floor plan. Run against tests/browser/serve_e2e.py on port 5001 (fresh DB, no Indexer),
// from the compliance-app folder:
//   playwright-cli run-code --filename=tests/browser/floorplan_flows.js
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
  const markers = () => page.locator("#fp-markers .fp-marker:visible").count();

  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(BASE);
  // Start from a clean state: no plans, positions or saved assignments.
  await page.evaluate(async (headers) => {
    try { localStorage.clear(); } catch {}
    const { assignments } = await (await fetch("/api/assets")).json();
    for (const a of assignments) await fetch("/api/assets", { method: "DELETE", headers, body: JSON.stringify(a) });
    const { floor_plans } = await (await fetch("/api/floorplans")).json();
    for (const p of floor_plans) await fetch("/api/floorplans", { method: "DELETE", headers, body: JSON.stringify(p) });
    for (const id of ["S01", "S02", "S03", "S04", "S05", "S06", "S07"]) {
      await fetch("/api/positions", { method: "DELETE", headers, body: JSON.stringify({ agent_id: id }) });
    }
  }, H);
  failedResponses.length = 0; // 404s from deleting positions that did not exist are expected
  await page.goto(`${BASE}#/floorplan`);
  await page.reload();

  // Before any upload: floors come only from assignments; nothing is placed.
  await page.locator("#fp-floor option").first().waitFor({ state: "attached" });
  const floors = await page.locator("#fp-floor option").allInnerTexts();
  check(JSON.stringify(floors) === JSON.stringify(["HQ · Floor 1", "HQ · Floor 2", "HQ · Floor 3"]), "floors from assignments");
  check(await page.locator("#fp-no-plan").isVisible(), "no plan message");
  check((await page.locator("#fp-note").innerText()).includes("2 PC(s) have no building/floor"), "missing location data reported");
  check((await page.locator("#source-banner").innerText()).includes("SAMPLE DATA"), "sample data labelled");

  // Invalid uploads are rejected.
  await page.selectOption("#fp-floor", { label: "HQ · Floor 2" });
  await page.setInputFiles("#fp-up-file", { name: "plan.svg", mimeType: "image/svg+xml", buffer: Buffer.from("<svg/>") });
  await page.click("#fp-upload-form button[type=submit]");
  await page.locator("#fp-message", { hasText: "choose a PNG, JPEG or WebP" }).waitFor();
  check(true, "client rejects SVG");
  await page.setInputFiles("#fp-up-file", { name: "fake.png", mimeType: "image/png", buffer: Buffer.from("not really a png") });
  await page.click("#fp-upload-form button[type=submit]");
  await page.locator("#fp-message", { hasText: "extension matches its content" }).waitFor();
  check(true, "server rejects a non-image renamed to .png");

  // Valid upload.
  await page.setInputFiles("#fp-up-file", PLAN);
  await page.click("#fp-upload-form button[type=submit]");
  await page.locator("#fp-message", { hasText: "Uploaded floor plan for HQ · Floor 2" }).waitFor();
  await page.locator("#fp-stage img").waitFor();
  await page.waitForFunction(() => document.getElementById("fp-image").naturalWidth === 800);
  check(await markers() === 0, "no invented positions after upload");
  check(await page.locator("#fp-tray .fp-tray-item").count() === 2, "floor 2 PCs listed as not placed");

  // Drag S01 from the tray onto the plan.
  const drag = async (from, fx, fy) => {
    await from.scrollIntoViewIfNeeded();
    const box = await page.locator("#fp-image").boundingBox();
    const b = await from.boundingBox();
    await page.mouse.move(b.x + b.width / 2, b.y + b.height / 2);
    await page.mouse.down();
    await page.mouse.move(b.x + b.width / 2 + 20, b.y + b.height / 2 + 20, { steps: 4 });
    await page.mouse.move(box.x + box.width * fx, box.y + box.height * fy, { steps: 8 });
    await page.mouse.up();
  };
  await drag(page.locator('#fp-tray [data-key="S01"]'), 0.25, 0.3);
  await page.locator('#fp-markers [data-key="S01"]').waitFor();
  check(await page.locator('#fp-tray [data-key="S01"]').count() === 0, "dropped PC leaves the tray");
  const pos = await page.evaluate(async () => (await (await fetch("/api/fleet")).json()).endpoints.find((e) => e.key === "S01").position);
  check(Math.abs(pos.x - 0.25) < 0.02 && Math.abs(pos.y - 0.3) < 0.02, `position saved (${pos.x}, ${pos.y})`);

  // Drag the placed marker to a new spot; it persists across a reload.
  await drag(page.locator('#fp-markers [data-key="S01"]'), 0.7, 0.6);
  await page.locator("#fp-message", { hasText: "Saved position of SAMPLE-FIN-01" }).waitFor();
  await page.reload();
  await page.locator('#fp-markers [data-key="S01"]').waitFor();
  const style = await page.locator('#fp-markers [data-key="S01"]').getAttribute("style");
  check(/left: 7\d(\.\d+)?%/.test(style) && /top: 6\d(\.\d+)?%/.test(style), `marker kept after reload (${style})`);

  // Dropping outside the plan changes nothing.
  await drag(page.locator('#fp-tray [data-key="S02"]'), 1.5, 0.5);
  await page.locator("#fp-message", { hasText: "Dropped outside" }).waitFor();
  check(await page.locator('#fp-tray [data-key="S02"]').count() === 1, "drop outside keeps PC unplaced");

  // Click a marker: details with compliance, failed checks and remediation.
  await page.locator('#fp-markers [data-key="S01"]').click();
  await page.locator("#fp-detail h2", { hasText: "SAMPLE-FIN-01" }).waitFor();
  await page.locator("#fp-detail .fp-raw > summary").click();   // raw Wazuh failures are folded by default
  const detail = await page.locator("#fp-detail").innerText();
  check(detail.includes("Finance (sample)") && detail.includes("HQ · Floor 2 · Room 201") && detail.includes("60.00%")
    && /Failed checks \(2\)/.test(detail) && detail.includes("Remediation:"), "marker details");
  await page.locator("#fp-detail .fp-failed .link-btn").first().click();
  await page.locator("#check-dialog[open]").waitFor();
  check(/recommended remediation/i.test(await page.locator("#check-dialog").innerText()), "failed check opens full details");
  await page.click("#check-dialog .dialog-close button");

  // Keyboard nudge saves too.
  await page.locator('#fp-markers [data-key="S01"]').focus();
  await page.keyboard.press("ArrowLeft");
  await page.locator("#fp-message", { hasText: "Saved position" }).waitFor();
  check(true, "arrow key moves marker");

  // Filters.
  await drag(page.locator('#fp-tray [data-key="S02"]'), 0.4, 0.4);
  await page.locator('#fp-markers [data-key="S02"]').waitFor();
  check(await markers() === 2, "two markers on floor 2");
  await page.selectOption("#fp-status", "noncompliant");
  check(await markers() === 1 && await page.locator('#fp-markers [data-key="S01"]').isVisible(), "status filter");
  await page.selectOption("#fp-status", "");
  await page.selectOption("#fp-department", "IT (sample)");
  check(await markers() === 0, "department filter");
  await page.selectOption("#fp-department", "");
  await page.selectOption("#fp-floor", { label: "HQ · Floor 1" });
  check(await page.locator("#fp-no-plan").isVisible() && await markers() === 0, "floor filter shows that floor only");
  check(await page.locator("#fp-tray .fp-tray-item").count() === 2, "floor 1 PCs in tray");
  const stale = page.locator('#fp-tray [data-key="S05"]');
  check((await stale.getAttribute("class")).includes("conn-stale") && (await stale.innerText()).includes("Stale"), "stale agent distinguished");
  await page.selectOption("#fp-status", "offline_or_stale");
  check(await page.locator("#fp-tray .fp-tray-item").count() === 1, "offline/stale filter");
  await page.selectOption("#fp-status", "");

  // Reassigning a PC to another floor drops its old marker (never shown at a stale spot).
  await page.evaluate(async (headers) => {
    await fetch("/api/assets", { method: "PUT", headers, body: JSON.stringify({ key_type: "agent_id", key_value: "S02",
      department: "Finance (sample)", building: "HQ", floor: "3", room: "301" }) });
  }, H);
  await page.click("#fleet-refresh");
  await page.selectOption("#fp-floor", { label: "HQ · Floor 2" });
  await page.locator('#fp-markers [data-key="S01"]').waitFor();
  check(await page.locator('#fp-markers [data-key="S02"]').count() === 0, "moved PC's old marker not shown");

  // Remove from plan.
  await page.locator('#fp-markers [data-key="S01"]').click();
  await page.locator("#fp-detail button", { hasText: "Remove from plan" }).click();
  await page.locator('#fp-tray [data-key="S01"]').waitFor();
  check(await markers() === 0, "remove from plan");

  // Phone width: no horizontal page scroll.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(100);
  check(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth) <= 0, "no horizontal scroll at 390px");
  await page.setViewportSize({ width: 1280, height: 900 });

  check(JSON.stringify(failedResponses) === JSON.stringify(["400 /api/floorplans"]),
    `only the intentional error responses occurred (${failedResponses.join(", ")})`);
  check(errors.length === 0, `no console errors (${errors.join(" | ")})`);
  return `${passed.length} floor plan checks passed`;
}
