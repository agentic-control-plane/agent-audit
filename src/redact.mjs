// Everything shown in a report passes through here. Reports get
// screenshotted, so the default output must never carry a secret, an
// email address, a username or a home path. When in doubt, redact: a
// report with an extra [redacted] is fine, a leaked password is not.

import { homedir, userInfo } from "node:os";

export const SECRET_PATTERNS = [
  [/(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{16,}/g, "Anthropic key"],
  [/(?<![A-Za-z0-9_-])sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g, "OpenAI key"],
  [/(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{30,}/g, "GitHub token"],
  [/(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{30,}/g, "GitHub token"],
  [/(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_-]{20,}/g, "GitLab token"],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, "AWS access key"],
  [/(?<![A-Za-z0-9_])xox[abprs]-[A-Za-z0-9-]{10,}/g, "Slack token"],
  [/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g, "Slack webhook"],
  [/(?<![A-Za-z0-9_])AIza[0-9A-Za-z_-]{35}/g, "Google API key"],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, "npm token"],
  [/\b[sr]k_live_[A-Za-z0-9]{16,}/g, "Stripe key"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "JWT"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|\s)+[A-Za-z0-9+/=]{40,}/g, "private key"],
];

const EMAIL_RE = /[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}/gi;

// Generic secret positions, value replaced whatever it looks like.
const GENERIC = [
  // A whole PEM block (or as much as is in the text).
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g, "[private key]"],
  // Authorization / bearer values (before the key shapes, so no double marks).
  [/((?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic|token|digest)?\s*)[^\s"'\\]+/gi, "$1[redacted]"],
  [/(\b(?:bearer|token)\s+)[A-Za-z0-9._~+/=-]{16,}/gi, "$1[redacted]"],
  [/(--oauth2-bearer[=\s]+)\S+/g, "$1[redacted]"],
  // URL userinfo: scheme://user:pass@host → scheme://[redacted]@host
  [/([a-z][a-z0-9+.-]{1,20}:\/\/)[^\s/@"'`]+@/gi, "$1[redacted]@"],
  // curl -u / --user, wget --password, mysql -p<pw>, --password=
  [/((?:^|\s)(?:-u|--user|--proxy-user|-U)(?:=|\s+))(?:"[^"]*"|'[^']*'|\S+)/g, "$1[redacted]"],
  [/((?:^|\s)--(?:password|passwd|pass|http-password|ftp-password|secret|token|api-key|apikey|access-token)(?:=|\s+))(?:"[^"]*"|'[^']*'|\S+)/gi, "$1[redacted]"],
  [/((?:^|\s)-p)(?!\s)\S+/g, "$1[redacted]"],
  // NAME=value where the name says it's secret (env assignments, .env lines, query params).
  [/(\b[A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PASS|PWD|CREDENTIAL|AUTH|SIGNATURE|COOKIE|SESSION)[A-Za-z0-9_]*\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&;"']+)/gi, "$1[redacted]"],
  [/(\b(?:AccountKey|SharedAccessKey|sig|client_secret|access_token|refresh_token|api_key|apikey)=)[^\s&;"']+/gi, "$1[redacted]"],
  // Long opaque strings: 32+ hex, 40+ base64-ish.
  [/\b[0-9a-f]{32,}\b/gi, "[redacted]"],
];

/** 40+ base64-ish run with digits AND both cases: a token, not a path. */
const OPAQUE_RE = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/_-])/g;
function opaque(m) {
  const core = m.replace(/[/_-]/g, "");
  return /[0-9]/.test(core) && /[a-z]/.test(core) && /[A-Z]/.test(core) && core.length >= 32 ? "[redacted]" : m;
}

/** A real key has a random-looking body: placeholders like sk-xxxx…,
 *  sk-test-AAAA… or sk-…1234567890 are not findings. */
export function looksLive(token) {
  if (/PRIVATE KEY/.test(token)) return /[A-Za-z0-9+/=]{40,}$/.test(token);
  const body = token.replace(/^[A-Za-z]+[-_](?:[a-z]+[-_])?/, "").replace(/^hooks\.slack\.com\/services\//, "");
  if (body.length < 16) return false;
  if (new Set(body).size < 10) return false;
  if (!/[0-9]/.test(body) || !/[A-Za-z]/.test(body)) return false;
  if (/(.)\1{5,}/.test(body) || /(?:0123456|1234567|abcdefg|xxxxx|placeholder|example|redacted|your[_-]?)/i.test(body)) return false;
  return true;
}

/** Which secret types appear in a text (never the values). */
export function secretTypes(text) {
  const s = String(text ?? "").slice(0, 200_000);
  const out = new Set();
  for (const [re, label] of SECRET_PATTERNS) {
    re.lastIndex = 0;
    for (const m of s.matchAll(re)) {
      if (looksLive(m[0])) { out.add(label); break; }
    }
  }
  return [...out];
}

let USER = "";
try { USER = userInfo().username || ""; } catch { /* no passwd entry */ }

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function redact(text, { home = homedir(), user = USER, max = 110 } = {}) {
  // Bound the work: a report line never needs more than the first few KB.
  let s = String(text ?? "").slice(0, 8_000).replace(/\\\\/g, "\\").replace(/\s+/g, " ").trim();
  // Paths first, so a random-looking temp home is shown as ~ not [redacted].
  if (home && home.length > 1) s = s.split(home).join("~");
  s = s
    .replace(/(?:\/mnt\/[a-z])?\/Users\/[^/\s"'`]+/g, "~")
    .replace(/\/home\/[^/\s"'`]+/g, "~")
    .replace(/[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s"'`]+/g, "~");
  for (const [re, rep] of GENERIC) s = s.replace(re, rep);
  for (const [re, label] of SECRET_PATTERNS) s = s.replace(re, `[${label}]`);
  s = s.replace(OPAQUE_RE, opaque);
  s = s.replace(EMAIL_RE, "[email]");
  if (user && user.length >= 4) {
    const u = escapeRe(user);
    s = s.replace(new RegExp(`(^|[/\\\\\\s])${u}(?=[/\\\\@\\s]|$)`, "g"), "$1[user]").replace(new RegExp(`\\b${u}@`, "g"), "[user]@");
  }
  s = s.replace(/\b[A-Za-z0-9._-]+@(?=[A-Za-z0-9.-]+:)/g, "[user]@"); // scp user@host:
  if (s.length <= max) return s;
  // Never cut inside a [marker]: drop a trailing partial one.
  let cut = s.slice(0, max - 1);
  const open = cut.lastIndexOf("[");
  if (open > cut.lastIndexOf("]")) cut = cut.slice(0, open);
  return `${cut}…`;
}

/** A host safe to show: a public registrable name, not an mDNS/intranet name or an IP. */
export function showableHost(h) {
  const host = String(h ?? "").toLowerCase();
  if (!host.includes(".")) return false;
  if (/\.(?:local|internal|lan|home|corp|intranet|localdomain|test|invalid|example)$/.test(host)) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":")) return false;
  return true;
}
