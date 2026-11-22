import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { piiIn, luhn } from "../src/pii.mjs";
import { scan } from "../src/scan.mjs";
import { summarise, renderTerminal, renderHtml, renderAgentNotes } from "../src/report.mjs";

const BIN = fileURLToPath(new URL("../bin/agent-audit.mjs", import.meta.url));
const NOW = new Date().toISOString();
const at = (local, domain) => local + "@" + domain;

/** A Luhn-valid number from a prefix, built at run time so no card number sits in the repo. */
function card(prefix, length) {
  let body = prefix;
  for (let i = 0; body.length < length - 1; i++) body += String((i * 7 + 3) % 10);
  for (let c = 0; c < 10; c++) if (luhn(body + c)) return body + c;
  throw new Error("no check digit");
}
const VISA = card("4539", 16);
const AMEX = card("3714", 15);
const OWN = at("pat.example", "mailbox.test");
const OTHER = at("dana.whitfield", "gmail.com");
const WORK = at("sam", "harborlight-studio.io");
const SSN = ["512", "44", "9031"].join("-");

const types = (text, own) => piiIn(text, own).map((p) => p.type);

test("finds a person's email, a card number and a labelled SSN", () => {
  assert.deepEqual(types(`contact ${OTHER} about the refund`), ["email"]);
  assert.deepEqual(types(`card ${VISA} exp 04/29`), ["card"]);
  assert.deepEqual(types(`card: ${VISA.replace(/(\d{4})(?=\d)/g, "$1 ")}`), ["card"]);
  assert.deepEqual(types(`amex ${AMEX}`), ["card"]);
  assert.deepEqual(types(`SSN: ${SSN}`), ["ssn"]);
  assert.deepEqual(types(`{"social_security": "${SSN}"}`), ["ssn"]);
});

test("the masked form never contains the value", () => {
  for (const [text, value] of [[`mail ${OTHER}`, OTHER], [`mail ${WORK}`, WORK], [`card ${VISA}`, VISA], [`ssn ${SSN}`, SSN]]) {
    const [p] = piiIn(text);
    assert.ok(p, text);
    assert.ok(!p.masked.includes(value));
    assert.ok(!p.masked.includes(value.split("@")[0]));
  }
  assert.equal(piiIn(`mail ${OTHER}`)[0].masked, "d***@gmail.com");
  assert.equal(piiIn(`mail ${WORK}`)[0].masked, "s***@h***.io");
  // A short name or domain would be given away by its first letter.
  assert.equal(piiIn(`mail ${at("al", "gmail.com")}`)[0].masked, "***@gmail.com");
  assert.equal(piiIn(`mail ${at("kim", "qz.co")}`)[0].masked, "k***@***.co");
  assert.equal(piiIn(`card ${VISA}`)[0].masked, `Visa card ending ${VISA.slice(-4)}`);
  assert.equal(piiIn(`ssn ${SSN}`)[0].masked, "***-**-****");
});

test("precision: things that only look like personal data", () => {
  const own = new Set([OWN]);
  assert.deepEqual(types(`Author: Pat <${OWN}>`, own), []);
  for (const text of [
    at("git", "github.com") + ":acme/repo.git",
    at("deploy", "build-host.example.com") + ":/srv/app",
    at("noreply", "github.com"),
    at("1234567+octocat", "users.noreply.github.com"),
    at("support", "stripe.com"),
    at("jane", "example.com"),
    at("icon", "2x.png"),
    at("react", "18.3.1"),
    "@" + "types/node" + "@" + "20.11.0",
    at("x", "obj.finish"),
    at("pkg", "1.0.tgz"),
    "4242424242424242",
    "4111 1111 1111 1111",
    "order id 1234567890123456",
    "sha 4539148803436467a9f",
    "ts=1731628800000 id=4539148803436467123456",
    "version 1.4539.1488.0343.6467",
    "123-45-6789",
    `range ${SSN}`,
    "phone 555-01-2345",
    // Logins, not addresses.
    "https://" + at("token123", "github.com") + "/acme/repo.git",
    "https://user:" + at("hunter2", "host.com") + "/",
    "ssh -i k.pem " + at("ec2-user", "ec2-1-2-3-4.compute-1.amazonaws.com"),
    "ssh " + at("dana", "build.harborlight.io") + " uptime",
    // Project metadata.
    "Author: Dana Whitfield <" + OTHER + ">",
    "Signed-off-by: Dana <" + OTHER + ">",
    '"author": "Dana Whitfield <' + OTHER + '>"',
    // Fixture and placeholder domains.
    at("dana", "x.com"), at("dana", "acme-corp.dev"), at("dana", "corp.com"), at("dana", "mailinator.com"),
    at("ops", "harborlight.io"),
    // Published test cards, and a bare digit run with no card word near it.
    "card 4000002500003155", "card 4009348888881881", "card 5454545454545454", "card 6011016011016011",
    `id ${VISA}`,
    `{"order_id": ${VISA}, "total": 12}`,
    `stripe test card ${VISA.replace(/(\d{4})(?=\d)/g, "$1 ")}`,
  ]) assert.deepEqual(types(text), [], text);
});

test("examples: a personal mailbox sorts before a work address and a public office", () => {
  const rank = (addr) => piiIn(`to ${addr}`)[0].rank;
  assert.ok(rank(OTHER) > rank(WORK));
  assert.ok(rank(WORK) > rank(at("clerk.jones", "parks.ca.gov")));
  assert.ok(piiIn(`card ${VISA}`)[0].rank > rank(OTHER));
});

test("escaped tool output: a literal \\n before a value does not hide or distort it", () => {
  assert.deepEqual(types(`name\\ncard ${VISA}`), ["card"]);
  assert.deepEqual(types(`x\\nssn: ${SSN}`), ["ssn"]);
  assert.deepEqual(piiIn(`a\\n${OTHER}\\tb`).map((p) => p.key), [`email:${OTHER}`]);
  assert.deepEqual(types("x\\n" + at("info", "harborlight.io")), []);
});

function home() {
  const h = mkdtempSync(join(tmpdir(), "aa-pii-"));
  writeFileSync(join(h, ".gitconfig"), `[user]\n\temail = ${OWN}\n`);
  const cdir = join(h, ".claude", "projects", "-work-proj");
  mkdirSync(cdir, { recursive: true });
  const user = (content) => JSON.stringify({ type: "user", sessionId: "s1", cwd: "/work/proj", timestamp: NOW, message: { role: "user", content } });
  writeFileSync(join(cdir, "s1.jsonl"), [
    user(`refund ${OTHER}, card ${VISA}`),
    JSON.stringify({ type: "assistant", sessionId: "s1", cwd: "/work/proj", timestamp: NOW, message: { role: "assistant", content: [{ type: "tool_use", id: "t1", name: "Bash", input: { command: "cat customers.csv" } }] } }),
    user([{ type: "tool_result", tool_use_id: "t1", content: `name,email,ssn\nDana,${OTHER},${SSN}\nSam,${WORK},\nPat,${OWN},` }]),
    user([{ type: "tool_result", tool_use_id: "t2", content: [{ type: "text", text: `again ${OTHER}` }] }]),
  ].join("\n") + "\n");
  const xdir = join(h, ".codex", "sessions", "2026", "11", "07");
  mkdirSync(xdir, { recursive: true });
  const cx = (type, payload) => JSON.stringify({ timestamp: NOW, type, payload });
  writeFileSync(join(xdir, "rollout-1.jsonl"), [
    cx("session_meta", { session_id: "c1", cwd: "/work/api" }),
    cx("response_item", { type: "function_call", name: "shell_command", arguments: JSON.stringify({ command: "cat users.json" }) }),
    // The three shapes Codex writes: a JSON string wrapping the text, an array of parts, a plain string.
    cx("response_item", { type: "function_call_output", output: JSON.stringify({ output: `id,email\n7,${at("lee.okafor", "yahoo.com")}\n`, metadata: { exit_code: 0 } }) }),
    cx("response_item", { type: "custom_tool_call_output", output: [{ type: "input_text", text: `to: ${at("mira.castellan", "outlook.com")}` }] }),
    cx("response_item", { type: "message", role: "user", content: [{ type: "input_text", text: `ask ${at("lee.okafor", "yahoo.com")} again` }] }),
  ].join("\n") + "\n");
  return h;
}

test("scan: counts each distinct value once and reports only masked text", async () => {
  const h = home();
  const result = await scan({ home: h, days: 30 });
  const s = summarise(result, { examples: 10 });
  const pii = s.categories.find((c) => c.id === "pii");
  assert.equal(pii.count, 6); // card, SSN, two Claude Code emails, two Codex emails; own address and repeats are not counted
  assert.equal(pii.sessions, 2);
  assert.match(pii.examples[0].text, /card ending|\*\*\*-\*\*-\*\*\*\*/); // worst first
  assert.ok(pii.examples.some((e) => e.why === "card number in a prompt"));
  assert.ok(pii.examples.some((e) => e.why === "US Social Security number in tool output"));
  assert.ok(pii.examples.some((e) => e.harness === "Codex"));
  for (const out of [renderTerminal(s), renderHtml(s), JSON.stringify(s), JSON.stringify(summarise(result, { raw: true, examples: 10 }))]) {
    for (const v of [OTHER, WORK, VISA, SSN, "dana.whitfield", "lee.okafor", "mira.castellan"]) assert.ok(!out.includes(v), `leaked ${v.slice(0, 3)}…`);
  }
});

test("agent notes: printed with --agent, name the top findings, never for --json", () => {
  const h = home();
  const env = { ...process.env, HOME: h, NO_COLOR: "1" };
  for (const k of ["CLAUDECODE", "AI_AGENT", "CODEX_SANDBOX", "CURSOR_AGENT"]) delete env[k];
  const plain = spawnSync(process.execPath, [BIN], { env, encoding: "utf8" });
  assert.equal(plain.status, 0, plain.stderr);
  assert.doesNotMatch(plain.stdout, /Notes for an agent/);
  assert.match(plain.stdout, /Personal data the model read\s+6/);
  const agent = spawnSync(process.execPath, [BIN, "--agent"], { env, encoding: "utf8" });
  assert.match(agent.stdout, /Notes for an agent relaying this report/);
  assert.match(agent.stdout, /Lead with: Personal data the model read \(6\)/);
  const auto = spawnSync(process.execPath, [BIN], { env: { ...env, CLAUDECODE: "1" }, encoding: "utf8" });
  assert.match(auto.stdout, /Notes for an agent/);
  const json = spawnSync(process.execPath, [BIN, "--json", "--agent"], { env, encoding: "utf8" });
  assert.doesNotThrow(() => JSON.parse(json.stdout));
  assert.match(renderAgentNotes({ categories: [] }), /Nothing serious was found/);
});
