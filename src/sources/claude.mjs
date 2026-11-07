// Claude Code sessions: ~/.claude/projects/<project>/<session>.jsonl.
// One JSON object per line. Tool calls are assistant content blocks of
// type "tool_use" with the full `input`; each line carries cwd, sessionId
// and timestamp. "permission-mode" lines record bypass mode, and
// "cost-state" lines carry the session's running cost.

import { createReadStream, readdirSync, statSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";

export function claudeFiles(home, sinceMs) {
  // projects/<project>/<session>.jsonl, and subagents one level down:
  // projects/<project>/<session>/subagents/agent-*.jsonl
  const root = join(home, ".claude", "projects");
  const out = [];
  const walk = (dir, depth) => {
    let entries = [];
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory() && depth < 3) walk(p, depth + 1);
      else if (e.isFile() && e.name.endsWith(".jsonl")) {
        try { if (statSync(p).mtimeMs >= sinceMs) out.push(p); } catch { /* vanished */ }
      }
    }
  };
  walk(root, 0);
  return out;
}

/** Yields { kind: "call" | "session", … } events from one file. */
export async function* readClaude(path, sinceMs) {
  const rl = createInterface({ input: createReadStream(path, { encoding: "utf8" }), crlfDelay: Infinity });
  // A subagent file belongs to its parent session (the directory name).
  const sub = /[\\/]([^\\/]+)[\\/]subagents[\\/][^\\/]+\.jsonl$/.exec(path);
  let session = sub ? sub[1] : null;
  let cwd = null;
  let bypass = false;
  let cost = null;
  for await (const line of rl) {
    if (!line || line[0] !== "{") continue;
    let o;
    try { o = JSON.parse(line); } catch { continue; }
    session ??= o.sessionId ?? o.session_id ?? null;
    if (typeof o.cwd === "string") cwd = o.cwd;
    if (o.type === "permission-mode" && o.permissionMode === "bypassPermissions") bypass = true;
    if (o.permissionMode === "bypassPermissions") bypass = true;
    if (o.type === "cost-state" && typeof o.totalCostUSD === "number") cost = o.totalCostUSD;
    if (o.type !== "assistant" || !Array.isArray(o.message?.content)) continue;
    const ts = Date.parse(o.timestamp ?? "") || 0;
    if (ts && ts < sinceMs) continue;
    for (const b of o.message.content) {
      if (b?.type !== "tool_use") continue;
      yield { kind: "call", harness: "Claude Code", session: session ?? path, cwd, ts, tool: String(b.name ?? ""), input: b.input ?? {}, subagent: Boolean(sub) || o.isSidechain === true };
    }
  }
  // Subagent files carry no cost-state of their own; the parent does.
  yield { kind: "session", harness: "Claude Code", session: session ?? path, cwd, bypass, cost: sub ? null : cost };
}
