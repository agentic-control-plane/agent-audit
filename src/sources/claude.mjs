// Claude Code sessions: ~/.claude/projects/<project>/<session>.jsonl.
// One JSON object per line. Tool calls are assistant content blocks of
// type "tool_use" with the full `input`; each line carries cwd, sessionId
// and timestamp. "permission-mode" lines record bypass mode, and
// "cost-state" lines carry the session's running cost.

import { createReadStream, readdirSync, statSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";

export function claudeFiles(home, sinceMs) {
  const root = join(home, ".claude", "projects");
  const out = [];
  let dirs = [];
  try { dirs = readdirSync(root); } catch { return out; }
  for (const d of dirs) {
    let files = [];
    try { files = readdirSync(join(root, d)); } catch { continue; }
    for (const f of files) {
      if (!f.endsWith(".jsonl")) continue;
      const p = join(root, d, f);
      try { if (statSync(p).mtimeMs >= sinceMs) out.push(p); } catch { /* vanished */ }
    }
  }
  return out;
}

/** Yields { kind: "call" | "session", … } events from one file. */
export async function* readClaude(path, sinceMs) {
  const rl = createInterface({ input: createReadStream(path, { encoding: "utf8" }), crlfDelay: Infinity });
  let session = null;
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
      yield { kind: "call", harness: "Claude Code", session, cwd, ts, tool: String(b.name ?? ""), input: b.input ?? {}, subagent: o.isSidechain === true };
    }
  }
  if (session) yield { kind: "session", harness: "Claude Code", session, cwd, bypass, cost };
}
