// What counts as worth showing. Every rule is the replay of something a
// pre-tool check could have stopped; the floors come straight from ACP's
// open decision engine so a finding here is exactly a call ACP holds.

import { hardlineFloor, destructiveFloor, stripDataHeredocs } from "./vendor/decide.mjs";
import { detectIdentityEgress, identityTokens } from "./vendor/identity.mjs";
import { classifyHost, isInternalHostClass, displayHost } from "./vendor/net.mjs";
import { secretTypes } from "./redact.mjs";

export const CATEGORIES = [
  { id: "catastrophic", title: "Catastrophic commands", severity: 3, blurb: "rm -rf on /, ~ or ., mkfs, raw disk writes" },
  { id: "destructive", title: "Destructive commands", severity: 3, blurb: "force-push, destructive SQL, curl | sh, recursive delete outside the project" },
  { id: "secret-in-args", title: "Live secrets in tool calls", severity: 3, blurb: "a real-looking key or token passed in a command or tool input" },
  { id: "pii", title: "Personal data the model read", severity: 2, blurb: "card numbers, US Social Security numbers and other people's email addresses in prompts and tool output" },
  { id: "credential-read", title: "Credential files read", severity: 2, blurb: ".env, SSH keys, cloud and registry credentials" },
  { id: "upload", title: "Local data sent out", severity: 2, blurb: "a file or body uploaded to a host outside your machine" },
  { id: "identity", title: "Your email sent to a site", severity: 2, blurb: "your address in a User-Agent, From header or contact field" },
  { id: "sensitive-write", title: "Sensitive files changed", severity: 2, blurb: "shell startup files, SSH config, CI workflows, git hooks" },
  { id: "unattended", title: "Sessions with no approval prompts", severity: 1, blurb: "Claude Code bypass mode, Codex never-ask + full-access sandbox" },
  { id: "push", title: "Pushes to a git remote", severity: 1, blurb: "every git push the agent ran" },
];

/** Commands longer than this are scanned on their first part only. */
const MAX_CMD = 50_000;

const SHELL = new Set(["Bash", "run_terminal_cmd", "shell"]);
const READ_TOOLS = new Set(["Read", "read_file", "View", "view"]);
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit", "create_file", "edit_file", "NotebookEdit"]);

const CREDENTIAL_PATH_RE = /(?:^|[\s/"'=])(?:\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w.-]+)?|\.npmrc|\.pypirc|\.netrc|\.pgpass|\.git-credentials|\.aws\/credentials|\.aws\/config|\.ssh\/id_[a-z0-9]+(?!\.pub)|\.kube\/config|\.docker\/config\.json|\.config\/gcloud\/[\w./-]*credentials[\w.-]*|\.config\/gh\/hosts\.yml|[\w.-]*(?:key|private|id_)[\w.-]*\.pem|[\w.-]+\.p12|[\w.-]+\.pfx|[\w.-]+\.key|(?:gcp|google|firebase|aws)?[-_]?credentials\.json|service[-_]account[\w-]*\.json)(?=$|[\s"'`;|&)])/;
const NOT_A_SECRET_RE = /\.(?:example|sample|template|dist|tmpl|defaults?)(?=$|[\s"'`;|&)])/;
function credentialIn(text) {
  const m = CREDENTIAL_PATH_RE.exec(text);
  if (!m) return false;
  const tail = text.slice(m.index, m.index + m[0].length + 40);
  return !NOT_A_SECRET_RE.test(tail.split(/[\s"'`;|&)]/).filter(Boolean)[0] ?? "");
}
const DUMP_BINS = new Set(["cat", "head", "tail", "less", "more", "bat", "grep", "rg", "awk", "sed", "cp", "scp", "base64", "xxd", "strings", "source", ".", "open", "code", "vim", "nano"]);
const KEYCHAIN_RE = /\bsecurity\s+find-(?:generic|internet)-password\b[^|;&\n]*\s-w\b|\bgcloud\s+auth\s+print-access-token\b|\baws\s+configure\s+get\s+\S*secret/;
const SENSITIVE_WRITE_RE = /(?:^|\/)(?:\.(?:zshrc|bashrc|bash_profile|profile|zprofile|zshenv|bash_login)|\.ssh\/(?:config|authorized_keys|rc)|\.git\/hooks\/[^/]+|crontab|Library\/LaunchAgents\/[^/]+\.plist|\.config\/autostart\/[^/]+)$/;
const UPLOAD_RE = /\bcurl\b[^|;&\n]*(?:\s-(?:d|F|T)\s*@|\s--data(?:-binary|-raw)?[=\s]+@|\s--upload-file\b|\s-F\s+\S*=@)|\b(?:scp|rsync)\b[^|;&\n]*\s[\w.-]+@?[\w.-]+:\S|\bnc\s+[\w.-]+\s+\d+\s*<|\bgh\s+gist\s+create\b/;
const PUSH_RE = /\bgit\b(?:\s+-[cC]\s+\S+)*\s+push\b/;

/** What the shell would RUN: heredoc bodies and message-style arguments
 *  (--body, --title, -m …) are text being written or described, so a
 *  `curl | sh` inside an issue body or a test fixture is not a finding.
 *  Precision beats recall in a report people screenshot. */
export function executableText(cmd) {
  // Data heredocs (cat > file <<EOF …) are content; heredocs fed to a shell
  // or SQL client (bash <<EOF, psql <<SQL) stay, so their commands count.
  let t = stripDataHeredocs(String(cmd ?? "").slice(0, MAX_CMD));
  t = t.replace(/(--(?:body|title|notes|message|description|subject|comment|text|msg)|-[mb])(?:=|\s+)(?:"(?:[^"\\]|\\.){0,20000}"|'[^']{0,20000}'|\$\([^)]{0,20000}\)|\S+)/g, "$1 MSG");
  return t;
}

/** Shell segments split at ; && || | and newlines, outside quotes (approx). */
function segments(t, depth = 0) {
  const out = [];
  for (const seg of splitOutsideQuotes(t, true)) {
    out.push(seg);
    // A quoted string handed to a shell runs: bash -c "…", ssh host "…",
    // docker exec app sh -c "…".
    if (depth < 2 && runsQuotedText(seg)) {
      for (const q of quotedStrings(seg)) out.push(...segments(q, depth + 1));
    }
  }
  return out;
}

const SHELL_RUNNERS = new Set(["sh", "bash", "zsh", "dash", "ksh", "ssh", "eval", "xargs", "watch", "timeout", "su"]);
const SHELL_DASH_C_RE = /(?:^|[\s/])(?:ba|z|da|k)?sh\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*c\b/;
const REMOTE_RUN_RE = /(?:^|\s)(?:ssh|tmux\s+send-keys|screen\s+-\S*X)\s/;
function runsQuotedText(seg) {
  return SHELL_RUNNERS.has(firstWord(seg)) || SHELL_DASH_C_RE.test(seg) || REMOTE_RUN_RE.test(seg);
}

/** Split at ; && || newline (and | when asked), ignoring separators inside
 *  single or double quotes. A `|` in a grep pattern is not a pipe.
 *  Comments are dropped first, so an apostrophe in `# don't` opens nothing.
 *  If the quotes still don't balance, the text is split the plain way: a
 *  stray quote must never hide the command after it. */
function splitOutsideQuotes(t, pipes) {
  const s = String(t);
  const out = [];
  let cur = "";
  let quote = "";
  let ansi = false; // inside $'…', where backslash escapes
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === "\\" && (quote === '"' || ansi) && i + 1 < s.length) { cur += c + s[++i]; continue; }
      if (c === quote) { quote = ""; ansi = false; }
      cur += c;
      continue;
    }
    if (c === "\\" && i + 1 < s.length) { cur += c + s[++i]; continue; }
    if (c === "#" && (i === 0 || /\s/.test(s[i - 1]))) {
      const nl = s.indexOf("\n", i);
      if (nl === -1) break;
      i = nl - 1;
      continue;
    }
    if (c === '"' || c === "'") { quote = c; ansi = c === "'" && s[i - 1] === "$"; cur += c; continue; }
    const two = s.slice(i, i + 2);
    if (two === "&&" || two === "||") { out.push(cur); cur = ""; i++; continue; }
    if (c === "\n" || c === ";" || (pipes && c === "|")) { out.push(cur); cur = ""; continue; }
    cur += c;
  }
  if (quote) return s.split(pipes ? /\n|;|&&|\|\||\|/ : /\n|;|&&|\|\|/).map((x) => x.trim()).filter(Boolean);
  out.push(cur);
  return out.map((x) => x.trim()).filter(Boolean);
}

function quotedStrings(seg) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"|'([^']*)'/g;
  let m;
  while ((m = re.exec(seg)) !== null) out.push(m[1] !== undefined ? m[1].replace(/\\(["\\$`])/g, "$1") : m[2]);
  return out;
}

function firstWord(seg) {
  const toks = seg.split(/\s+/);
  let i = 0;
  while (i < toks.length && (/^[A-Za-z_]\w*=/.test(toks[i]) || /^(?:sudo|env|command|exec|nohup|time)$/.test(toks[i]))) i++;
  const w = toks[i] ?? "";
  return w.slice(w.lastIndexOf("/") + 1);
}

/** The engine reads the whole command line; a report people screenshot
 *  needs the matching command to be the one actually run. A force-push
 *  needs a git segment that pushes with force; a pipe-to-shell needs a
 *  curl/wget segment piped into a shell. `grep 'git push --force'` and
 *  `echo "curl x | sh"` are not findings. */
function backedBySegment(reason, run) {
  if (/force-push/.test(reason)) return Boolean(forcePushSegment(run));
  return backedByPipe(reason, run);
}

/** The segment that pushes with force, or null. A repository created by
 *  the same command has no shared history to overwrite. */
function forcePushSegment(run) {
  const segs = segments(run);
  if (segs.some((seg) => firstWord(seg) === "git" && /\sinit(?:\s|$)/.test(seg))) return null;
  return segs.find((seg) => firstWord(seg) === "git" && /\bpush\b/.test(seg) && /(?:\s--force(?!-with-lease|-if-includes)\b|\s-[a-eg-zA-Z]*f[a-zA-Z]*(?=\s|$)|\s\+[^\s:]+)/.test(seg)) ?? null;
}

function backedByPipe(reason, run) {
  if (/pipes a remote download/.test(reason)) {
    const parts = splitOutsideQuotes(run, false).flatMap((p) => (runsQuotedText(p) ? [p, ...quotedStrings(p)] : [p]));
    return parts.some((p) => {
      const piped = splitOutsideQuotes(p, true);
      for (let i = 0; i + 1 < piped.length; i++) {
        if (/^(?:curl|wget)$/.test(firstWord(piped[i])) && /^(?:sudo\s+)?(?:\S*\/)?(?:ba|z|da|k)?sh\b/.test(piped[i + 1])) return true;
      }
      return /(?:^|\s)(?:ba|z)?sh\s+(?:-\w+\s+)*(?:-c\s+["']?\$\(\s*(?:curl|wget)|<\s*<?\s*\(\s*(?:curl|wget))/.test(p);
    });
  }
  return true;
}

/** A segment without quoted arguments that cannot be a file path: a sed
 *  program, an awk script or a search pattern has regex characters, and `u.key)` inside one is code, not a key file. */
function pathArgs(seg) {
  return seg.replace(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g, (m, dq, sq) => (/[|(){}*^\\]/.test(dq ?? sq ?? "") ? '""' : m));
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
  const cmd = commandOf(ev).slice(0, MAX_CMD);
  const shellLike = SHELL.has(ev.tool) || (cmd && !READ_TOOLS.has(ev.tool) && !WRITE_TOOLS.has(ev.tool));
  const shellInput = { command: cmd };

  const run = executableText(cmd);
  const runInput = { command: run };
  if (shellLike && cmd) {
    const hard = hardlineFloor("Bash", runInput);
    if (hard) out.push({ category: "catastrophic", why: hard, example: cmd });
    const destr = hard ? null : destructiveFloor("Bash", runInput, { cwd: ev.cwd });
    // ACP records a variable-named rm without asking; so does this report.
    if (destr && !/variable-named path/.test(destr) && backedBySegment(destr, run)) out.push({ category: "destructive", why: destr.replace(/:\s.*$/, ""), example: (/force-push/.test(destr) && forcePushSegment(run)) || cmd });
    if (segments(run).some((seg) => DUMP_BINS.has(firstWord(seg)) && credentialIn(` ${pathArgs(seg)}`))) {
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
    if (p && credentialIn(` ${p}`)) out.push({ category: "credential-read", why: "read a credential file", example: p });
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
