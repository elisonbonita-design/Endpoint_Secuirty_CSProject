// Browser flows for sign-in, roles, the finding review workflow, the admin page and the compliance report.
// Run against a login-enabled server, from compliance-app:
//   python tests/browser/serve_e2e.py 5002 --login
//   playwright-cli run-code --filename=tests/browser/workflow_flows.js
async page => {
  const BASE = "http://127.0.0.1:5002/";
  const PASSWORD = "e2e-synthetic-pass"; // synthetic test account only
  const passed = [];
  const errors = [];
  page.on("console", (m) => { if (m.type() === "error" && !m.text().startsWith("Failed to load resource")) errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  const check = (cond, name) => { if (!cond) throw new Error(`FAILED: ${name}`); passed.push(name); };
  const signIn = async (user, password = PASSWORD) => {
    await page.goto(`${BASE}login`);
    await page.fill("input[name=username]", user);
    await page.fill("input[name=password]", password);
    await page.click("button[type=submit]");
  };

  await page.setViewportSize({ width: 1280, height: 900 });
  await page.context().clearCookies();
  await page.goto(BASE);
  check(page.url().endsWith("/login"), "unauthenticated visit goes to sign-in");
  await signIn("e2e-reviewer", "wrong-password-0");
  check((await page.locator(".alert").innerText()).includes("Wrong username or password"), "wrong password rejected");

  // Reviewer: review a finding, record a simulated fix, see the history.
  await signIn("e2e-reviewer");
  await page.locator("#user-name", { hasText: "e2e-reviewer · Reviewer" }).waitFor();
  check(await page.locator("#nav-admin").isHidden(), "reviewer has no admin tab");
  await page.goto(`${BASE}#/findings`);
  const row = page.locator("#risk-table tbody tr").first();
  await row.waitFor();
  await row.locator("summary", { hasText: "Explain, review and history" }).click();
  const review = row.locator(".review");
  await review.waitFor();
  const options = await review.locator("select option").allInnerTexts();
  check(!options.some((o) => o.includes("exception")) && options.includes("In review"), "reviewer cannot set exceptions");
  await review.locator("select").selectOption("fixed_pending");
  await review.getByRole("button", { name: "Change status" }).click();
  await row.locator(".review .status", { hasText: "Add a note" }).waitFor();
  check(true, "a simulated fix needs a note");
  await row.locator(".review textarea").fill("Applied the GPO setting and ran gpupdate /force (simulated in lab)");
  await row.locator(".review select").selectOption("fixed_pending");
  await row.locator(".review").getByRole("button", { name: "Change status" }).click();
  await row.locator(".review .history", { hasText: "Applied the GPO setting" }).waitFor();
  const history = await row.locator(".review .history").innerText();
  check(history.includes("e2e-reviewer") && history.includes("Applied the GPO setting"), "history shows actor and note");
  check((await row.locator(".review").innerText()).includes("never set by hand"), "verification rule explained");

  // Report page.
  const report = await page.context().newPage();
  await report.goto(`${BASE}report?source=sample`);
  const reportText = await report.locator("body").innerText();
  check(reportText.includes("Endpoint Compliance Report") && reportText.includes("e2e-reviewer (reviewer)")
    && reportText.includes("Applied the GPO setting"), "report includes findings and review history");
  await report.close();

  // Sign out; admin signs in and sees the admin page.
  await page.click("#logout-btn");
  await page.waitForURL(/\/login$/);
  check(true, "sign out");
  await signIn("e2e-admin");
  await page.goto(`${BASE}#/admin`);
  await page.locator("#users-table tbody tr").nth(1).waitFor();
  check((await page.locator("#users-table").innerText()).includes("e2e-reviewer"), "admin sees accounts");
  check((await page.locator("#req-table tbody tr").count()) >= 27, "requirement catalogue listed");
  check((await page.locator("#req-version").innerText()).includes("1.3"), "catalogue version shown");

  check(errors.length === 0, `no console errors ${JSON.stringify(errors)}`);
  return `${passed.length} workflow checks passed`;
}
