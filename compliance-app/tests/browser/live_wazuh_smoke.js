// Read-only smoke test of the live Wazuh source. Needs the dashboard started with
// scripts/run_with_wazuh.sh (port 5000) and the Wazuh lab running. Makes no changes.
//   playwright-cli run-code --filename=tests/browser/live_wazuh_smoke.js
async page => {
  const BASE = "http://127.0.0.1:5000/";
  const passed = [];
  const check = (cond, name) => { if (!cond) throw new Error(`FAILED: ${name}`); passed.push(name); };
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto(`${BASE}#/overview`);
  await page.selectOption("#fleet-source", "wazuh");
  await page.locator("#source-banner", { hasText: "LIVE WAZUH DATA" }).waitFor({ timeout: 30000 });
  const total = Number(await page.locator("#pc-total").innerText());
  check(total >= 1, `live overview lists ${total} PC(s)`);
  const checks = Number(await page.locator("#chk-total").innerText());
  check(checks > 0, `live overview counts ${checks} checks`);

  await page.click("[data-nav=map]");
  await page.locator("#map-groups .pc-card").first().waitFor({ timeout: 30000 });
  check(await page.locator("#map-groups .pc-card").count() === total, "map shows every live PC");
  const first = page.locator("#map-groups .pc-card").first();
  const key = await first.getAttribute("data-key");
  check(/^\d{3,8}$/.test(key), `live card uses a Wazuh agent ID (${key})`);
  await first.click();
  await page.locator("#pc-checks tbody tr").first().waitFor({ timeout: 30000 });
  check((await page.locator("#pc-facts").innerText()).includes(key), "PC details show the agent ID");
  await page.selectOption("#pc-filter-status", "failed");
  await page.locator("#pc-checks tbody tr .link-btn").first().click();
  await page.locator("#check-dialog[open]").waitFor();
  check(/recommended remediation/i.test(await page.locator("#check-dialog").innerText()), "live failed-check dialog");
  await page.screenshot({ path: "test-artifacts/fleet/live-check-dialog.png" });
  await page.click("#check-dialog .dialog-close button");

  await page.click("[data-nav=findings]");
  await page.locator("#raw-results > summary").click({ timeout: 30000 });
  await page.locator(".prio-item").first().waitFor({ timeout: 30000 });
  check(await page.locator(".prio-item").count() > 0, "live findings listed");
  // Floor plan with live data: only shows what is assigned/placed; nothing is invented.
  await page.click("[data-nav=floorplan]");
  await page.locator("#fp-note", { hasText: "Live Wazuh PCs" }).waitFor({ timeout: 30000 });
  const live = await page.evaluate(async () => (await (await fetch("/api/fleet?source=wazuh")).json()).endpoints);
  const placed = live.filter((e) => e.position).length;
  check(await page.locator("#fp-markers .fp-marker").count() <= placed, `live markers only for saved positions (${placed})`);
  check(live.every((e) => e.position === null || (e.location.building && e.location.floor)), "live positions require a location");
  await page.selectOption("#fleet-source", "sample"); // leave the stored preference on sample
  return `${passed.length} live checks passed`;
}
