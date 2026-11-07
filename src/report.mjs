// Terminal, JSON and HTML renderings of one scan. Every example passes
// through redact() unless the caller asked for raw output.

import { CATEGORIES } from "./findings.mjs";
import { redact } from "./redact.mjs";

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = (s) => c("1", s), dim = (s) => c("2", s), red = (s) => c("31", s), yellow = (s) => c("33", s), green = (s) => c("32", s);

function fmtDays(days) {
  return days === 1 ? "24 hours" : `${days} days`;
}

export function summarise(scan, { raw = false, examples = 3 } = {}) {
  const cats = CATEGORIES.map((cat) => {
    const items = scan.findings.filter((f) => f.category === cat.id);
    const sessions = new Set(items.map((f) => f.session)).size;
    const seen = new Set();
    const ex = [];
    for (const f of items) {
      const text = raw ? String(f.example) : redact(f.example);
      if (seen.has(text)) continue;
      seen.add(text);
      ex.push({ harness: f.harness, why: raw ? f.why : redact(f.why, { max: 90 }), text, when: f.ts ? new Date(f.ts).toISOString().slice(0, 10) : null });
      if (ex.length >= examples) break;
    }
    return { ...cat, count: items.length, sessions, examples: ex };
  });
  return { ...scan.stats, categories: cats };
}

export function renderTerminal(s) {
  const lines = [];
  const w = 64;
  lines.push("");
  lines.push(bold(`  What your coding agents did in the last ${fmtDays(s.days)}`));
  const harnessLine = Object.entries(s.byHarness).map(([h, n]) => `${h} ${n.sessions} sessions`).join(" · ") || "no sessions found";
  lines.push(dim(`  ${harnessLine} · ${s.calls.toLocaleString()} tool calls · ${s.shell.toLocaleString()} shell commands${s.cost ? ` · $${s.cost.toFixed(0)} spent in those sessions` : ""}`));
  lines.push(dim(`  ${"─".repeat(w)}`));
  const flagged = s.categories.filter((cat) => cat.count > 0);
  for (const cat of s.categories) {
    const n = cat.count;
    const mark = n === 0 ? green("  ✓") : cat.severity >= 3 ? red("  ✗") : cat.severity === 2 ? yellow("  !") : dim("  ·");
    const count = n === 0 ? dim("none") : bold(String(n));
    const where = n ? dim(` in ${cat.sessions} session${cat.sessions === 1 ? "" : "s"}`) : "";
    lines.push(`${mark} ${cat.title.padEnd(36)} ${count}${where}`);
    if (n && cat.severity >= 2) {
      for (const e of cat.examples) lines.push(dim(`      ${e.when ?? ""} ${e.harness}: ${e.why}`) + `\n${dim("        ")}${e.text}`);
    }
  }
  if (s.topHosts.length) {
    lines.push(dim(`  ${"─".repeat(w)}`));
    lines.push(`  Reached ${bold(String(s.hostCount))} hosts. Most often: ${s.topHosts.slice(0, 6).map(([h, n]) => `${h} (${n})`).join(", ")}`);
  }
  lines.push(dim(`  ${"─".repeat(w)}`));
  const serious = flagged.filter((cat) => cat.id === "catastrophic" || cat.id === "destructive").reduce((a, cat) => a + cat.count, 0);
  if (serious) {
    lines.push(`  ${bold(String(serious))} of these are calls a pre-tool check stops, or holds for your approval, before they run.`);
    lines.push(dim("  To have them asked about next time, in every harness: https://agenticcontrolplane.com/getting-started"));
  } else {
    lines.push(green("  Nothing catastrophic or destructive. Nice."));
  }
  lines.push(dim(`  Covered: ${s.covered.join(", ")}. Examples are redacted; --raw shows them in full (local only).`));
  lines.push("");
  return lines.join("\n");
}

const esc = (t) => String(t ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);

export function renderHtml(s) {
  const rows = s.categories.map((cat) => `
    <section class="cat ${cat.count ? `sev${cat.severity}` : "ok"}">
      <div class="head"><span class="n">${cat.count || "✓"}</span><div><h2>${esc(cat.title)}</h2><p>${esc(cat.blurb)}${cat.count ? ` · ${cat.sessions} session${cat.sessions === 1 ? "" : "s"}` : ""}</p></div></div>
      ${cat.examples.map((e) => `<div class="ex"><span>${esc(e.when ?? "")} · ${esc(e.harness)} · ${esc(e.why)}</span><code>${esc(e.text)}</code></div>`).join("")}
    </section>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Agent audit</title><style>
:root{--bg:#fafaf9;--fg:#1c1917;--mute:#78716c;--line:#e7e5e4;--card:#fff;--red:#b91c1c;--amber:#b45309;--green:#15803d}
@media (prefers-color-scheme:dark){:root{--bg:#0c0a09;--fg:#f5f5f4;--mute:#a8a29e;--line:#292524;--card:#1c1917;--red:#f87171;--amber:#fbbf24;--green:#4ade80}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 ui-sans-serif,system-ui,sans-serif}
main{max-width:760px;margin:0 auto;padding:32px 16px}h1{font-size:24px;margin:0 0 4px}.sub{color:var(--mute);margin:0 0 24px}
.cat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.head{display:flex;gap:14px;align-items:center}.n{font:600 22px ui-monospace,monospace;min-width:48px;text-align:center}
.sev3 .n{color:var(--red)}.sev2 .n{color:var(--amber)}.ok .n{color:var(--green)}h2{font-size:16px;margin:0}.head p{margin:2px 0 0;color:var(--mute);font-size:13px}
.ex{margin:10px 0 0 62px;font-size:13px}.ex span{color:var(--mute);display:block}code{display:block;overflow-wrap:anywhere;font:12.5px ui-monospace,monospace}
footer{color:var(--mute);font-size:13px;margin-top:24px}a{color:inherit}
</style></head><body><main>
<h1>What your coding agents did in the last ${esc(fmtDays(s.days))}</h1>
<p class="sub">${esc(Object.entries(s.byHarness).map(([h, n]) => `${h} ${n.sessions} sessions`).join(" · "))} · ${s.calls.toLocaleString()} tool calls · ${s.shell.toLocaleString()} shell commands${s.cost ? ` · $${s.cost.toFixed(0)} spent in those sessions` : ""} · ${s.hostCount} hosts reached</p>
${rows}
<footer>Generated locally by agent-audit. Examples are redacted. Covered: ${esc(s.covered.join(", "))}.<br>
To have the risky ones asked about before they run, in every harness: <a href="https://agenticcontrolplane.com/getting-started">Agentic Control Plane</a>.</footer>
</main></body></html>`;
}
