import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {createRequire} from "node:module";

const require = createRequire(import.meta.url);
const phase = process.env.P8_BROWSER_PHASE;
const stage = {name: "configuration"};

function required(name) {
  const setting = process.env[name];
  assert(typeof setting === "string" && setting.length > 0, "A required browser fixture setting is missing");
  return setting;
}

function consoleUrl() {
  const origin = new URL(required("P8_BROWSER_URL"));
  assert(new Set(["127.0.0.1", "[::1]", "localhost"]).has(origin.hostname));
  assert(new Set(["http:", "https:"]).has(origin.protocol));
  assert(!origin.username && !origin.password && !origin.search && !origin.hash);
  if (origin.pathname === "/") origin.pathname = "/console/";
  return origin.href;
}

async function connect(page, token) {
  const credential = page.locator("#credential");
  await credential.fill(token);
  await page.locator("#connect-form button[type=submit]").click();
  await page.locator("#session").waitFor({state: "visible"});
  assert.equal(await credential.inputValue(), "");
  const leaked = await page.evaluate((value) => [
    document.documentElement.textContent,
    JSON.stringify(window.localStorage),
    JSON.stringify(window.sessionStorage),
  ].some((sample) => sample.includes(value)), token);
  assert.equal(leaked, false);
}

async function taskStatus(page, expected) {
  await page.locator(`#task-status[data-state=${expected}]`).waitFor({state: "visible"});
}

async function loadTask(page, taskId) {
  await page.locator("#task-input").fill(taskId);
  await page.locator("#load-task").click();
  await page.locator("#task-content").waitFor({state: "visible"});
  assert.equal(await page.locator("#task-id").textContent(), taskId);
}

async function approve(page) {
  stage.name = "connect requester";
  await connect(page, required("P8_REQUESTER_TOKEN"));
  stage.name = "launch controlled action";
  await page.locator("#app").selectOption("controlled-action");
  await page.locator("#object").fill("asset-1");
  await page.locator("#object-version").fill("1");
  if (process.env.P8_BROWSER_CITATIONS !== undefined) {
    const citations = JSON.parse(process.env.P8_BROWSER_CITATIONS);
    assert(Array.isArray(citations) && citations.length > 0);
    const field = page.locator("#launch-citations");
    if (await field.isHidden()) await page.locator("#launch-options summary").click();
    await field.fill(JSON.stringify(citations));
  }
  await page.locator("#launch-button").click();
  await taskStatus(page, "planning");
  const id = await page.locator("#task-id").textContent();
  assert.match(id, /^[0-9a-f]{32}$/);

  stage.name = "advance to approval";
  await page.locator("[data-operation=advance]").click();
  await taskStatus(page, "awaiting_approval");
  assert(await page.locator("#review").isHidden());

  stage.name = "switch to reviewer";
  await page.locator("#disconnect").click();
  await page.locator("#task-content").waitFor({state: "hidden"});
  await connect(page, required("P8_REVIEWER_TOKEN"));
  await loadTask(page, id);
  await taskStatus(page, "awaiting_approval");
  await page.locator("#review").waitFor({state: "visible"});
  const proposalDigest = await page.locator("#review-details dt").filter({hasText: /^提议摘要$/})
    .locator("xpath=following-sibling::dd[1]").textContent();
  assert.match(proposalDigest, /^[0-9a-f]{64}$/);

  stage.name = "approve pinned proposal";
  const [sent] = await Promise.all([
    page.waitForRequest((request) => request.method() === "POST" &&
      new URL(request.url()).pathname === `/v1/tasks/${id}/decision`),
    page.locator("[data-decision=approve]").click(),
  ]);
  const decision = sent.postDataJSON();
  assert.deepEqual(decision, {verdict: "approve", proposal_digest: proposalDigest});
  await taskStatus(page, "ready");
  return {id, status: "ready"};
}

async function complete(page) {
  stage.name = "reopen authorized task";
  await connect(page, required("P8_REQUESTER_TOKEN"));
  const id = required("P8_BROWSER_TASK_ID");
  await loadTask(page, id);
  await taskStatus(page, "ready");

  stage.name = "execute authorized task";
  await page.locator("[data-operation=advance]").click();
  await taskStatus(page, "completed");

  stage.name = "load events";
  await page.locator("#load-events").click();
  await page.locator("#events li").first().waitFor({state: "visible"});

  stage.name = "load evidence";
  await page.locator("#load-proof").click();
  await page.locator("#download-proof").waitFor({state: "visible"});

  stage.name = "download evidence";
  const [download] = await Promise.all([page.waitForEvent("download"), page.locator("#download-proof").click()]);
  const proof = JSON.parse(await readFile(await download.path(), "utf8"));
  assert.equal(proof.id, id);
  assert.equal(proof.status, "completed");
  assert.equal(proof.effect_recorded, true);
  if (proof.receipt?.operation_id !== undefined) assert.equal(proof.receipt.operation_id, id);

  stage.name = "check mobile layout";
  await page.setViewportSize({width: 390, height: 844});
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
  return {id, status: "completed", effect_recorded: true};
}

let browser;
try {
  assert(phase === "approve" || phase === "complete");
  const {chromium} = require(process.env.P8_PLAYWRIGHT_MODULE || "playwright");
  stage.name = "open browser";
  browser = await chromium.launch({channel: process.env.P8_BROWSER_CHANNEL || "chrome", headless: true});
  const page = await browser.newPage({acceptDownloads: true, viewport: {width: 1280, height: 900}});
  page.setDefaultTimeout(12_000);
  await page.goto(consoleUrl(), {waitUntil: "domcontentloaded", timeout: 12_000});
  const result = phase === "approve" ? await approve(page) : await complete(page);
  process.stdout.write(JSON.stringify(result) + "\n");
} catch {
  process.stderr.write(`P8 browser verification failed during ${stage.name}.\n`);
  process.exitCode = 1;
} finally {
  if (browser) await browser.close();
}
