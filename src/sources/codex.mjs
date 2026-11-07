// Codex sessions: ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl.
// Shell calls appear as function_call shell_command {command},
// exec_command {cmd}, older shell {command: [...]}, local_shell_call
// {action.command: [...]}, or inside the JavaScript `exec` tool as
// tools.exec_command({ cmd: "…" }). File edits arrive as apply_patch text.
// turn_context records the approval policy and sandbox.

import { createReadStream, readdirSync, statSync } from "node:fs";
import { createInterface } from "node:readline";
import { join } from "node:path";

export function codexFiles(home, sinceMs) {
  const out = [];
  const walk = (dir, depth) => {
    let entries = [];
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory() && depth < 4) walk(p, depth + 1);
      else if (e.isFile() && e.name.endsWith(".jsonl")) {
        try { if (statSync(p).mtimeMs >= sinceMs) out.push(p); } catch { /* vanished */ }
      }
    }
  };
  walk(join(home, ".codex", "sessions"), 0);
  return out;
}

function parseJson(s) {
  try { return JSON.parse(s); } catch { return null; }
}

/** `cmd: "…"` string values inside exec code (quotes or backticks). */
export function execCodeCommands(code) {
  const out = [];
  const re = /\bcmd\s*:\s*(["'`])((?:\\[\s\S]|(?!\1)[\s\S]){1,20000}?)\1/g;
  let m;
  while ((m = re.exec(String(code ?? ""))) !== null) {
    out.push(m[2].replace(/\\n/g, "\n").replace(/\\(["'`\\])/g, "$1"));
  }
  return out;
}

/** File paths touched by an apply_patch body. */
export function patchPaths(patch) {
  const out = [];
  const re = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm;
  let m;
  while ((m = re.exec(String(patch ?? ""))) !== null) out.push(m[1].trim());
  return out;
}

export async function* readCodex(path, sinceMs) {
  const rl = createInterface({ input: createReadStream(path, { encoding: "utf8" }), crlfDelay: Infinity });
  let session = null;
  let cwd = null;
  let bypass = false;
  const call = (ts, tool, input, extra = {}) => ({ kind: "call", harness: "Codex", session: session ?? path, cwd, ts, tool, input, ...extra });
  for await (const line of rl) {
    if (!line || line[0] !== "{") continue;
    const o = parseJson(line);
    if (!o) continue;
    const p = o.payload && typeof o.payload === "object" ? o.payload : {};
    if (o.type === "session_meta") { session = p.session_id ?? p.id ?? session; if (typeof p.cwd === "string") cwd = p.cwd; continue; }
    if (o.type === "turn_context") {
      if (typeof p.cwd === "string") cwd = p.cwd;
      const sandbox = p.sandbox_policy?.type ?? p.sandbox_policy?.mode;
      if (p.approval_policy === "never" && /danger|full/i.test(String(sandbox ?? ""))) bypass = true;
      continue;
    }
    if (o.type !== "response_item") continue;
    const ts = Date.parse(o.timestamp ?? "") || 0;
    if (ts && ts < sinceMs) continue;
    const workdir = (a) => (a && typeof a.workdir === "string" ? a.workdir : undefined);
    if (p.type === "function_call") {
      const a = parseJson(p.arguments) ?? {};
      const name = String(p.name ?? "");
      if (name === "shell_command" && typeof a.command === "string") yield call(ts, "Bash", { command: a.command }, { cwd: workdir(a) ?? cwd });
      else if (name === "exec_command" && typeof a.cmd === "string") yield call(ts, "Bash", { command: a.cmd }, { cwd: workdir(a) ?? cwd });
      else if (name === "shell" && Array.isArray(a.command)) {
        const argv = a.command.map(String);
        const cmd = argv.length >= 3 && /(?:^|\/)(?:ba|z)?sh$/.test(argv[0]) && argv[1].startsWith("-") ? argv.slice(2).join(" ") : argv.join(" ");
        yield call(ts, "Bash", { command: cmd }, { cwd: workdir(a) ?? cwd });
      } else if (name === "apply_patch") {
        const patch = typeof a.input === "string" ? a.input : typeof a.patch === "string" ? a.patch : "";
        for (const file_path of patchPaths(patch)) yield call(ts, "Edit", { file_path });
      } else yield call(ts, name, a);
    } else if (p.type === "local_shell_call") {
      const argv = Array.isArray(p.action?.command) ? p.action.command.map(String) : [];
      if (argv.length) yield call(ts, "Bash", { command: argv.length >= 3 && argv[1] === "-lc" ? argv[2] : argv.join(" ") });
    } else if (p.type === "custom_tool_call") {
      const name = String(p.name ?? "");
      const input = typeof p.input === "string" ? p.input : "";
      if (name === "exec") {
        for (const cmd of execCodeCommands(input)) yield call(ts, "Bash", { command: cmd });
        if (/\bfetch\s*\(|\brequest\s*\(/.test(input)) yield call(ts, "CodeFetch", { code: input });
      } else if (name === "apply_patch") {
        for (const file_path of patchPaths(input)) yield call(ts, "Edit", { file_path });
      } else yield call(ts, name, { input });
    }
  }
  yield { kind: "session", harness: "Codex", session: session ?? path, cwd, bypass, cost: null };
}
