#!/usr/bin/env node
// agent-audit — what did your coding agents actually do?
//
// Reads the session logs Claude Code and Codex already keep on your
// machine and reports the risky calls. Read-only. Nothing leaves your
// machine.

import { writeFileSync } from "node:fs";
import { scan, SOURCES } from "../src/scan.mjs";
import { summarise, renderTerminal, renderHtml } from "../src/report.mjs";

const HELP = `agent-audit — what did your coding agents actually do?

Usage: npx agent-audit [options]

  --days N         look back N days (default 30)
  --harness NAME   only scan one harness: ${Object.keys(SOURCES).join(", ")} (repeatable)
  --email ADDR     also flag this address in outbound headers (repeatable; git user.email is automatic)
  --html FILE      also write a shareable HTML report
  --json           print the summary as JSON
  --examples N     examples per finding (default 3)
  --raw            show examples unredacted (stays on your machine; don't screenshot)
  -h, --help       this help
`;

const argv = process.argv.slice(2);
const opts = { days: 30, harnesses: [], emails: [], html: null, json: false, raw: false, examples: 3 };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  const next = () => argv[++i];
  if (a === "-h" || a === "--help") { process.stdout.write(HELP); process.exit(0); }
  else if (a === "--days") {
    const v = Number(next());
    if (!Number.isFinite(v) || v <= 0) { process.stderr.write("--days needs a positive number\n"); process.exit(2); }
    opts.days = v;
  }
  else if (a === "--harness") opts.harnesses.push(next());
  else if (a === "--email") opts.emails.push(next());
  else if (a === "--html") opts.html = next();
  else if (a === "--json") opts.json = true;
  else if (a === "--raw") opts.raw = true;
  else if (a === "--examples") opts.examples = Math.max(0, Number(next()) || 0);
  else { process.stderr.write(`unknown option: ${a}\n\n${HELP}`); process.exit(2); }
}
const bad = opts.harnesses.filter((h) => !SOURCES[h]);
if (bad.length) { process.stderr.write(`unknown harness: ${bad.join(", ")}\n`); process.exit(2); }

const result = await scan({ days: opts.days, harnesses: opts.harnesses.length ? opts.harnesses : undefined, emails: opts.emails });
const summary = summarise(result, { raw: opts.raw, examples: opts.examples });
if (opts.json) process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
else process.stdout.write(renderTerminal(summary) + "\n");
if (opts.html) {
  writeFileSync(opts.html, renderHtml(summarise(result, { raw: false, examples: opts.examples })));
  process.stderr.write(`HTML report written to ${opts.html} (redacted)\n`);
}
