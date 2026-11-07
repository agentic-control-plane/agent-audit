// The shell command a tool call will run, across harness input shapes:
// Claude Code / Codex / Cursor / Copilot `{ command: "..." }`, a JSON
// string of that, or a raw string on a Bash-named tool. Any other tool is
// shell-shaped only when its input carries a `command` field: a bare
// string on an unknown tool is data, not a command.

export function floorCommand(toolName, toolInput) {
  let cmd = "";
  if (toolInput && typeof toolInput === "object") {
    if (typeof toolInput.command === "string") cmd = toolInput.command;
  } else if (typeof toolInput === "string") {
    try {
      const p = JSON.parse(toolInput);
      if (p && typeof p === "object" && typeof p.command === "string") cmd = p.command;
    } catch {
      if (/^(?:Bash|Pwsh|bash|shell)\b/.test(String(toolName ?? ""))) cmd = toolInput;
    }
  }
  return cmd.replace(/\\\r?\n/g, " ");
}
