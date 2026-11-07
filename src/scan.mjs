// Walk every covered harness's local sessions and collect findings.

import { homedir } from "node:os";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { claudeFiles, readClaude } from "./sources/claude.mjs";
import { codexFiles, readCodex } from "./sources/codex.mjs";
import { findingsFor, hostsFor, tokensFor } from "./findings.mjs";
import { displayHost } from "./vendor/net.mjs";

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

export async function scan({ home = homedir(), days = 30, harnesses = Object.keys(SOURCES), emails = [] } = {}) {
  const sinceMs = Date.now() - days * 86_400_000;
  const allEmails = [...emails];
  const g = gitEmail(home);
  if (g) allEmails.push(g);
  const ctx = { tokens: tokensFor(allEmails) };
  const findings = [];
  const hosts = new Map();
  const byHarness = {};
  let calls = 0, shell = 0, cost = 0;
  const sessionsSeen = new Set();
  for (const key of harnesses) {
    const src = SOURCES[key];
    if (!src) continue;
    byHarness[src.name] ??= { sessions: 0 };
    for (const file of src.files(home, sinceMs)) {
      try {
        for await (const ev of src.read(file, sinceMs)) {
          if (ev.kind === "session") {
            const sk = `${ev.harness}:${ev.session}`;
            if (sessionsSeen.has(sk)) continue;
            sessionsSeen.add(sk);
            byHarness[src.name].sessions++;
            if (typeof ev.cost === "number") cost += ev.cost;
            if (ev.bypass) findings.push({ category: "unattended", why: "ran with no approval prompts", example: ev.cwd ?? "", harness: ev.harness, session: ev.session, ts: 0 });
            continue;
          }
          calls++;
          if (ev.tool === "Bash" || typeof ev.input?.command === "string") shell++;
          for (const h of hostsFor(ev)) { const d = displayHost(h); hosts.set(d, (hosts.get(d) ?? 0) + 1); }
          for (const f of findingsFor(ev, ctx)) findings.push({ ...f, harness: ev.harness, session: ev.session, ts: ev.ts });
        }
      } catch { /* one unreadable file never stops the scan */ }
    }
  }
  const topHosts = [...hosts.entries()].sort((a, b) => b[1] - a[1]);
  return {
    findings,
    stats: { days, calls, shell, cost, byHarness, hostCount: hosts.size, topHosts, covered: harnesses.map((k) => SOURCES[k]?.name).filter(Boolean) },
  };
}
