// What counts as worth showing. Every rule is the replay of something a
// pre-tool check could have stopped; the floors come straight from ACP's
// open decision engine so a finding here is exactly a call ACP holds.

import { hardlineFloor, destructiveFloor } from "./vendor/decide.mjs";
import { detectIdentityEgress, identityTokens } from "./vendor/identity.mjs";
import { classifyHost, isInternalHostClass, displayHost } from "./vendor/net.mjs";
import { secretTypes } from "./redact.mjs";

export const CATEGORIES = [
  { id: "catastrophic", title: "Catastrophic commands", severity: 3, blurb: "rm -rf on /, ~ or ., mkfs, raw disk writes" },
  { id: "destructive", title: "Destructive commands", severity: 3, blurb: "force-push, destructive SQL, curl | sh, recursive delete outside the project" },
  { id: "secret-in-args", title: "Live secrets in tool calls", severity: 3, blurb: "a real-looking key or token passed in a command or tool input" },
  { id: "credential-read", title: "Credential files read", severity: 2, blurb: ".env, SSH keys, cloud and registry credentials" },
  { id: "upload", title: "Local data sent out", severity: 2, blurb: "a file or body uploaded to a host outside your machine" },
  { id: "identity", title: "Your email sent to a site", severity: 2, blurb: "your address in a User-Agent, From header or contact field" },
  { id: "sensitive-write", title: "Sensitive files changed", severity: 2, blurb: "shell startup files, SSH config, CI workflows, git hooks" },
  { id: "unattended", title: "Sessions with no approval prompts", severity: 1, blurb: "Claude Code bypass mode, Codex never-ask + full-access sandbox" },
  { id: "push", title: "Pushes to a git remote", severity: 1, blurb: "every git push the agent ran" },
];

const SHELL = new Set(["Bash", "run_terminal_cmd", "shell"]);
const READ_TOOLS = new Set(["Read", "read_file", "View", "view"]);
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "create_file", "edit_file", "NotebookEdit"]);

const CREDENTIAL_PATH_RE = /(?:^|[\s/"'=])(?:\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w.-]+)?|\.npmrc|\.pypirc|\.netrc|\.pgpass|\.git-credentials|\.aws\/credentials|\.aws\/config|\.ssh\/id_[a-z0-9]+(?!\.pub)|\.kube\/config|\.docker\/config\.json|\.config\/gcloud\/[\w./-]*credentials[\w.-]*|\.config\/gh\/hosts\.yml|[\w.-]+\.pem|[\w.-]+\.p12|[\w.-]+\.pfx|credentials\.json|service[-_]account[\w-]*\.json)(?=$|[\s"'`;|&)])/;
const DUMP_BINS = new Set(["cat", "head", "tail", "less", "more", "bat", "grep", "rg", "awk", "sed", "cp", "scp", "base64", "xxd", "strings", "source", ".", "open", "code", "vim", "nano"]);
const KEYCHAIN_RE = /\bsecurity\s+find-(?:generic|internet)-password\b[^|;&\n]*\s-w\b|\bgcloud\s+auth\s+print-access-token\b|\baws\s+configure\s+get\s+\S*secret/;
const SENSITIVE_WRITE_RE = /(?:^|\/)(?:\.(?:zshrc|bashrc|bash_profile|profile|zprofile|zshenv)|\.ssh\/(?:config|authorized_keys)|\.github\/workflows\/[^/]+\.ya?ml|\.git\/hooks\/[^/]+|\.gitlab-ci\.yml|crontab)$/;
const UPLOAD_RE = /\bcurl\b[^|;&\n]*(?:\s-(?:d|F|T)\s*@|\s--data(?:-binary|-raw)?[=\s]+@|\s--upload-file\b|\s-F\s+\S*=@)|\b(?:scp|rsync)\b[^|;&\n]*\s[\w.-]+@?[\w.-]+:\S|\bnc\s+[\w.-]+\s+\d+\s*<|\bgh\s+gist\s+create\b/;
const PUSH_RE = /\bgit\b(?:\s+-[cC]\s+\S+)*\s+push\b/;

/** What the shell would RUN: heredoc bodies and message-style arguments
 *  (--body, --title, -m …) are text being written or described, so a
 *  `curl | sh` inside an issue body or a test fixture is not a finding.
 *  Precision beats recall in a report people screenshot. */
export function executableText(cmd) {
  let t = String(cmd ?? "");
  t = t.replace(/<<-?\s*(['"]?)([A-Za-z_][\w-]*)\1[^\n]*\n[\s\S]*?\n\s*\2(?=\s|$|[;&|)])/g, "<<HEREDOC");
  t = t.replace(/(--(?:body|title|notes|message|description|subject|comment|text|msg)|-[mb])(?:=|\s+)(?:"(?:\\.|[^"\\])*"|'[^']*'|\$\([^)]*\)|\S+)/g, "$1 MSG");
  return t;
}

/** Shell segments split at ; && || | and newlines, outside quotes (approx). */
function segments(t) {
  return String(t).split(/\n|;|&&|\|\||\|/).map((x) => x.trim()).filter(Boolean);
}

function firstWord(seg) {
  const toks = seg.split(/\s+/);
  let i = 0;
  while (i < toks.length && (/^[A-Za-z_]\w*=/.test(toks[i]) || /^(?:sudo|env|command|exec|nohup|time)$/.test(toks[i]))) i++;
  const w = toks[i] ?? "";
  return w.slice(w.lastIndexOf("/") + 1);
}

function commandOf(ev) {
  const i = ev.input;
  if (i && typeof i === "object") {
    if (typeof i.command === "string") return i.command;
    if (typeof i.cmd === "string") return i.cmd;
  }
  return "";
}

function hostsIn(text) {
  const out = [];
  const re = /\bhttps?:\/\/(?:[^\s/?#@"'`]*@)?(\[[^\]\s]+\]|[^\s/:?#"'`)]+)/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const h = m[1].replace(/^\[|\]$/g, "").toLowerCase();
    // A host the shell computes ($VAR, ${…}) or a placeholder is not a destination we know.
    if (/[$`{}]/.test(h) || !h.includes(".")) continue;
    if (!isInternalHostClass(classifyHost(h))) out.push(h);
  }
  return out;
}

/**
 * Findings for one tool call. Returns [{ category, why, example }]; the
 * example is the raw text, redacted later by the report.
 */
export function findingsFor(ev, ctx) {
  const out = [];
  const cmd = commandOf(ev);
  const shellLike = SHELL.has(ev.tool) || (cmd && !READ_TOOLS.has(ev.tool) && !WRITE_TOOLS.has(ev.tool));
  const shellInput = { command: cmd };

  const run = executableText(cmd);
  const runInput = { command: run };
  if (shellLike && cmd) {
    const hard = hardlineFloor("Bash", runInput);
    if (hard) out.push({ category: "catastrophic", why: hard, example: cmd });
    const destr = hard ? null : destructiveFloor("Bash", runInput, { cwd: ev.cwd });
    // ACP records a variable-named rm without asking; so does this report.
    if (destr && !/variable-named path/.test(destr)) out.push({ category: "destructive", why: destr.replace(/:\s.*$/, ""), example: cmd });
    if (segments(run).some((seg) => DUMP_BINS.has(firstWord(seg)) && CREDENTIAL_PATH_RE.test(` ${seg}`))) {
      out.push({ category: "credential-read", why: "read a credential file in the shell", example: cmd });
    }
    if (KEYCHAIN_RE.test(run)) out.push({ category: "credential-read", why: "pulled a secret from the keychain or a cloud CLI", example: cmd });
    const up = segments(run).find((seg) => UPLOAD_RE.test(seg));
    if (up) {
      const ext = hostsIn(up);
      const remoteCopy = /^(?:scp|rsync)$/.test(firstWord(up));
      if (ext.length || remoteCopy || /gh\s+gist/.test(up)) out.push({ category: "upload", why: ext.length ? `uploaded to ${displayHost(ext[0])}` : "copied files to a remote machine", example: cmd });
    }
    if (segments(run).some((seg) => firstWord(seg) === "git" && PUSH_RE.test(seg))) out.push({ category: "push", why: "git push", example: cmd });
  }

  if (READ_TOOLS.has(ev.tool)) {
    const p = String(ev.input?.file_path ?? ev.input?.path ?? "");
    if (p && CREDENTIAL_PATH_RE.test(` ${p}`)) out.push({ category: "credential-read", why: "read a credential file", example: p });
  }
  if (WRITE_TOOLS.has(ev.tool)) {
    const p = String(ev.input?.file_path ?? ev.input?.path ?? "");
    if (p && SENSITIVE_WRITE_RE.test(p)) out.push({ category: "sensitive-write", why: "changed a file that runs or authenticates on its own", example: p });
  }

  // Secrets: anything the call carries. Write/Edit content is the user's
  // own code more often than a leak, so only commands and non-file tools.
  if (!WRITE_TOOLS.has(ev.tool)) {
    let blob = run;
    if (!blob) { try { blob = JSON.stringify(ev.input ?? ""); } catch { blob = ""; } }
    const types = secretTypes(blob.slice(0, 200_000));
    if (types.length) out.push({ category: "secret-in-args", why: types.join(", "), example: blob });
  }

  if (ctx.tokens.length || cmd) {
    const id = detectIdentityEgress(ev.tool, ev.input, ctx.tokens);
    if (id) out.push({ category: "identity", why: `${id.what} to ${id.where}`, example: cmd || JSON.stringify(ev.input ?? "") });
  }
  return out;
}

/** Hosts this call talked to (for the "where it went" line). */
export function hostsFor(ev) {
  const cmd = commandOf(ev);
  if (cmd && /\b(?:curl|wget|http|xh|Invoke-WebRequest|iwr|git\s+clone)\b/.test(cmd)) return hostsIn(cmd);
  const url = ev.input?.url;
  if (typeof url === "string") return hostsIn(url);
  return [];
}

export function tokensFor(emails) {
  return identityTokens(undefined, [], emails);
}
