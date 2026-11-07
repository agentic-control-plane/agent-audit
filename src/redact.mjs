// Everything shown in a report passes through here. Reports get
// screenshotted, so the default output never carries a secret, an email
// address, or your home path.

import { homedir } from "node:os";

export const SECRET_PATTERNS = [
  [/(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{16,}/g, "Anthropic key"],
  [/(?<![A-Za-z0-9_-])sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g, "OpenAI key"],
  [/(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{30,}/g, "GitHub token"],
  [/(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{30,}/g, "GitHub token"],
  [/(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_-]{20,}/g, "GitLab token"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "AWS access key"],
  [/(?<![A-Za-z0-9_])xox[abprs]-[A-Za-z0-9-]{10,}/g, "Slack token"],
  [/(?<![A-Za-z0-9_])AIza[0-9A-Za-z_-]{35}/g, "Google API key"],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, "npm token"],
  [/\b[sr]k_live_[A-Za-z0-9]{16,}/g, "Stripe key"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "JWT"],
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----/g, "private key"],
];

const EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const BEARER_RE = /(authorization:\s*(?:bearer|basic|token)\s+)[^\s"'\\]+/gi;

/** A real key has a random-looking body: placeholders like sk-xxxx…,
 *  sk-test-AAAA… or sk-…1234567890 are not findings. */
export function looksLive(token) {
  const body = token.replace(/^[A-Za-z]+[-_](?:[a-z]+[-_])?/, "");
  if (body.length < 16) return /PRIVATE KEY/.test(token);
  const distinct = new Set(body).size;
  if (distinct < 10) return false;
  if (!/[0-9]/.test(body) || !/[A-Za-z]/.test(body)) return false;
  if (/(.)\1{5,}/.test(body) || /(?:0123456|1234567|abcdefg|xxxxx|placeholder|example|redacted|your[_-]?)/i.test(body)) return false;
  return true;
}

/** Which secret types appear in a text (never the values). */
export function secretTypes(text) {
  const s = String(text ?? "");
  const out = new Set();
  for (const [re, label] of SECRET_PATTERNS) {
    re.lastIndex = 0;
    for (const m of s.matchAll(re)) {
      if (looksLive(m[0])) { out.add(label); break; }
    }
  }
  return [...out];
}

export function redact(text, { home = homedir(), max = 110 } = {}) {
  let s = String(text ?? "").replace(/\s+/g, " ").trim();
  for (const [re, label] of SECRET_PATTERNS) s = s.replace(re, `[${label}]`);
  s = s.replace(BEARER_RE, "$1[redacted]").replace(EMAIL_RE, "[email]");
  if (home && home.length > 1) s = s.split(home).join("~");
  s = s.replace(/\/Users\/[^/\s"']+/g, "~").replace(/\/home\/[^/\s"']+/g, "~");
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}
