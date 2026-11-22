// Walk every covered harness's local sessions and collect findings.

import { homedir } from "node:os";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { claudeFiles, readClaude } from "./sources/claude.mjs";
import { codexFiles, readCodex } from "./sources/codex.mjs";
import { findingsFor, hostsFor, tokensFor } from "./findings.mjs";
import { piiIn } from "./pii.mjs";
import { displayHost } from "./vendor/net.mjs";
import { showableHost } from "./redact.mjs";

export const SOURCES = {
  claude: { name: "Claude Code", files: claudeFiles, read: readClaude },
  codex: { name: "Codex", files: codexFiles, read: readCodex },
};

function gitEmail(home) {
  for (const p of [join(home, ".gitconfig"), join(home, ".config", "git", "config")]) {
    try {
      const m = /\[user\][^[]*?\n\s*email\s*=\s*"?([^\s"#;]+)/i.exec(readFileSync(p, "utf8"));
      if (m) return m[1];
    } catch { /* absent */ }
  }
  return null;
}

/** Distinct personal-data values kept per scan. */
const MAX_PII = 10_000;

export async function scan({ home = homedir(), days = 30, harnesses = Object.keys(SOURCES), emails = [] } = {}) {
  const sinceMs = Date.now() - days * 86_400_000;
  const allEmails = [...emails];
  const g = gitEmail(home);
  if (g) allEmails.push(g);
  const ctx = { tokens: tokensFor(allEmails) };
  const findings = [];
  const own = new Set(allEmails.map((e) => String(e).toLowerCase()));
  const seenPii = new Set();
  const hosts = new Map();
  const byHarness = {};
  let calls = 0, shell = 0, cost = 0;
  // A session counts (and its cost and bypass flag) only when it made at
  // least one call inside the window; a file touched yesterday by a
  // 60-day-old session must not pull its whole history in.
  const sessions = new Map();
  for (const key of harnesses) {
    const src = SOURCES[key];
    if (!src) continue;
    byHarness[src.name] ??= { sessions: 0 };
    for (const file of src.files(home, sinceMs)) {
      try {
        for await (const ev of src.read(file, sinceMs)) {
          const sk = `${ev.harness}:${ev.session}`;
          const rec = sessions.get(sk) ?? { harness: ev.harness, session: ev.session, calls: 0, bypass: false, cost: null, cwd: null };
          sessions.set(sk, rec);
          if (ev.kind === "session") {
            rec.bypass ||= ev.bypass;
            if (typeof ev.cost === "number") rec.cost = Math.max(rec.cost ?? 0, ev.cost);
            rec.cwd ??= ev.cwd;
            continue;
          }
          if (ev.kind === "text") {
            for (const p of piiIn(ev.text, own)) {
              // One finding per distinct value, however often it was read.
              if (seenPii.has(p.key) || seenPii.size >= MAX_PII) continue;
              seenPii.add(p.key);
              findings.push({ category: "pii", why: `${p.label} in ${ev.where}`, example: p.masked, rank: p.rank, harness: ev.harness, session: ev.session, ts: ev.ts });
            }
            continue;
          }
          rec.calls++;
          calls++;
          if (ev.tool === "Bash" || typeof ev.input?.command === "string") shell++;
          for (const h of hostsFor(ev)) {
            if (!showableHost(h)) continue;
            const d = displayHost(h);
            hosts.set(d, (hosts.get(d) ?? 0) + 1);
          }
          for (const f of findingsFor(ev, ctx)) {
            findings.push({ ...f, example: String(f.example ?? "").slice(0, 4_000), harness: ev.harness, session: ev.session, ts: ev.ts });
          }
        }
      } catch { /* one unreadable file never stops the scan */ }
    }
  }
  for (const rec of sessions.values()) {
    if (!rec.calls) continue;
    byHarness[rec.harness].sessions++;
    if (typeof rec.cost === "number") cost += rec.cost;
    if (rec.bypass) findings.push({ category: "unattended", why: "ran with no approval prompts", example: rec.cwd ?? "", harness: rec.harness, session: rec.session, ts: 0 });
  }
  const topHosts = [...hosts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 20);
  return {
    findings,
    stats: { days, calls, shell, cost, byHarness, hostCount: hosts.size, topHosts, covered: harnesses.map((k) => SOURCES[k]?.name).filter(Boolean) },
  };
}
