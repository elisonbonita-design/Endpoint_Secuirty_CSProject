// Responsive layout checks across window sizes, resizing the same page live (no reload) the way a user drags
// the window edge. Run against tests/browser/serve_e2e.py on port 5001 from the compliance-app folder:
//   playwright-cli run-code --filename=tests/browser/responsive_flows.js
async page => {
  const BASE = "http://127.0.0.1:5001/";
  const H = { "Content-Type": "application/json", "X-Requested-With": "compliance-dashboard" };
  const SIZES = [[320, 640], [375, 667], [390, 844], [600, 900], [768, 1024], [900, 700], [1024, 768],
    [1280, 720], [1366, 768], [1440, 900], [1920, 1080], [2560, 1440], [3840, 2160], [1280, 500], [800, 400]];
  const VIEWS = ["overview", "map", "floorplan", "pc/S01", "findings", "assets", "report"];
  const problems = [];
  let checks = 0;
  const fail = (msg) => problems.push(msg);

  // Known state: HQ floor 2 has a plan with S01 and S02 placed.
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(BASE);
  await page.evaluate(async (headers) => {
    try { localStorage.clear(); } catch {}
    const { assignments } = await (await fetch("/api/assets")).json();
    for (const a of assignments) await fetch("/api/assets", { method: "DELETE", headers, body: JSON.stringify(a) });
  }, H);
  const hasPlan = await page.evaluate(async () =>
    (await (await fetch("/api/floorplans")).json()).floor_plans.some((p) => p.building === "HQ" && p.floor === "2"));
  if (!hasPlan) {
    await page.goto(`${BASE}#/floorplan`);
    await page.locator("#fp-floor option").first().waitFor({ state: "attached" });
    await page.fill("#fp-up-building", "HQ");
    await page.fill("#fp-up-floor", "2");
    await page.setInputFiles("#fp-up-file", "tests/fixtures/floorplan_test.png");
    await page.click("#fp-upload-form button[type=submit]");
    await page.locator("#fp-message", { hasText: "Uploaded" }).waitFor();
  }
  await page.evaluate(async (headers) => {
    for (const [id, x, y] of [["S01", 0.03, 0.05], ["S02", 0.97, 0.95]]) {
      await fetch("/api/positions?source=sample", { method: "PUT", headers, body: JSON.stringify({ agent_id: id, x, y }) });
    }
  }, H);

  // Elements that stick out past the right edge of the window (content inside a horizontal scroller is fine).
  const overflowReport = () => page.evaluate(() => {
    const vw = document.documentElement.clientWidth;
    const out = [];
    if (document.documentElement.scrollWidth > vw + 1) out.push(`page scrollWidth ${document.documentElement.scrollWidth} > ${vw}`);
    for (const node of document.querySelectorAll("body *")) {
      if (!node.offsetParent && getComputedStyle(node).position !== "fixed") continue;
      if (node.closest(".table-wrap, dialog:not([open])")) continue;
      const r = node.getBoundingClientRect();
      if (r.width && (r.right > vw + 1 || r.left < -1)) {
        out.push(`${node.tagName.toLowerCase()}${node.id ? "#" + node.id : ""}.${String(node.className).split(" ")[0]} [${Math.round(r.left)}..${Math.round(r.right)}]`);
      }
      if (out.length > 4) break;
    }
    return out;
  });

  // Each marker's dot must sit on its saved fraction of the image, at any size.
  const markerReport = () => page.evaluate(() => {
    const img = document.getElementById("fp-image");
    const r = img.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    const out = [];
    if (r.right > vw + 1) out.push(`plan image exceeds window (${Math.round(r.right)} > ${vw})`);
    if (r.height > window.innerHeight) out.push(`plan taller than window (${Math.round(r.height)} > ${window.innerHeight})`);
    for (const m of document.querySelectorAll("#fp-markers .fp-marker")) {
      const dot = m.querySelector(".fp-dot").getBoundingClientRect();
      const cx = dot.left + dot.width / 2, cy = dot.top + dot.height / 2;
      const ex = r.left + parseFloat(m.style.left) / 100 * r.width;
      const ey = r.top + parseFloat(m.style.top) / 100 * r.height;
      if (Math.abs(cx - ex) > 2 || Math.abs(cy - ey) > 2) out.push(`${m.dataset.key} dot off by ${Math.round(cx - ex)},${Math.round(cy - ey)}px`);
      const label = m.querySelector(".fp-label").getBoundingClientRect();
      if (label.right > vw + 1 || label.left < -1) out.push(`${m.dataset.key} label outside window`);
      if (label.left < r.left - 1 || label.right > r.right + 1 || label.top < r.top - 1 || label.bottom > r.bottom + 1) {
        out.push(`${m.dataset.key} label outside plan`);
      }
    }
    // The plan should use the space it has: fill the card width, or be capped by the window height.
    const card = document.querySelector(".fp-stage-card").getBoundingClientRect();
    const fillsWidth = r.width >= card.width - 2 * 24 - 4;
    const heightCapped = r.height >= window.innerHeight * 0.7 - 4;
    if (!fillsWidth && !heightCapped) out.push(`plan not using available space (${Math.round(r.width)}x${Math.round(r.height)})`);
    return out;
  });

  for (const view of VIEWS) {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto(`${BASE}#/${view}`);
    await page.reload();
    await page.waitForLoadState("networkidle");
    if (view === "floorplan") {
      await page.selectOption("#fp-floor", { label: "HQ · Floor 2" });
      await page.waitForFunction(() => document.getElementById("fp-image").naturalWidth > 0);
    }
    for (const [w, h] of SIZES) {
      await page.setViewportSize({ width: w, height: h }); // live resize, same page
      await page.waitForTimeout(60);
      checks++;
      for (const p of await overflowReport()) fail(`${view} @${w}x${h}: ${p}`);
      if (view === "floorplan") {
        checks++;
        for (const p of await markerReport()) fail(`${view} @${w}x${h}: ${p}`);
      }
    }
  }

  // Check dialog and marker detail at small and large sizes.
  for (const [w, h] of [[320, 568], [800, 400], [1920, 1080]]) {
    await page.setViewportSize({ width: w, height: h });
    await page.goto(`${BASE}#/pc/S01`);
    await page.locator("#pc-checks .link-btn").first().waitFor();
    await page.locator("#pc-checks .link-btn").first().click();
    await page.locator("#check-dialog[open]").waitFor();
    const d = await page.locator("#check-dialog").boundingBox();
    checks++;
    if (d.x < 0 || d.y < 0 || d.x + d.width > w + 1 || d.y + d.height > h + 1) fail(`dialog @${w}x${h} outside window`);
    await page.click("#check-dialog .dialog-close button");
  }

  // Dragging still lands precisely after a live resize.
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${BASE}#/floorplan`);
  await page.reload();
  await page.selectOption("#fp-floor", { label: "HQ · Floor 2" });
  await page.locator('#fp-markers [data-key="S01"]').waitFor();
  for (const [w, h] of [[700, 900], [1920, 1080]]) {
    await page.setViewportSize({ width: w, height: h });
    await page.waitForTimeout(60);
    const marker = page.locator('#fp-markers [data-key="S01"] .fp-dot');
    await marker.scrollIntoViewIfNeeded();
    const box = await page.locator("#fp-image").boundingBox();
    const m = await marker.boundingBox();
    await page.mouse.move(m.x + m.width / 2, m.y + m.height / 2);
    await page.mouse.down();
    await page.mouse.move(m.x + 30, m.y + 30, { steps: 4 });
    await page.mouse.move(box.x + box.width * 0.5, box.y + box.height * 0.5, { steps: 8 });
    await page.mouse.up();
    await page.locator("#fp-message", { hasText: "Saved position" }).waitFor();
    const pos = await page.evaluate(async () => (await (await fetch("/api/fleet")).json()).endpoints.find((e) => e.key === "S01").position);
    checks++;
    if (Math.abs(pos.x - 0.5) > 0.02 || Math.abs(pos.y - 0.5) > 0.02) fail(`drag after resize to ${w}x${h} saved ${pos.x},${pos.y}`);
  }

  await page.setViewportSize({ width: 1280, height: 900 });
  if (problems.length) throw new Error(`FAILED ${problems.length} of ${checks} checks:\n` + problems.slice(0, 40).join("\n"));
  return `${checks} responsive checks passed (${VIEWS.length} views x ${SIZES.length} sizes, dialogs, drag after resize)`;
}
