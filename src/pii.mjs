// Personal data in text the model read: prompts and tool output.
// Precision over recall. Every detector returns a masked form for the
// report and never the value itself.

const EMAIL_RE = /(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})(?![A-Za-z0-9-])/g;
// Addresses that are a role, a bot or a tool, not a person.
const ROLE_LOCAL_RE = /^(?:git|hg|svn|root|admin|administrator|postmaster|webmaster|hostmaster|abuse|security|support|help|info|hello|hi|contact|sales|team|press|legal|privacy|billing|jobs|careers|feedback|notifications?|mailer-daemon|bounce|bot|ci|actions|dependabot|renovate|github-actions|user|username|name|you|me|email|someone|somebody|foo|bar|test|tester|example|sample|demo|jane|john|jdoe|alice|bob)$/i;
const NOT_PERSON_LOCAL_RE = /no-?reply|do-?not-?reply|\[bot\]|^\d+\+/i;
const NOT_PERSON_DOMAIN_RE = /(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost|local|internal|lan|users\.noreply\.github\.com|noreply\.github\.com|sentry\.io|iam\.gserviceaccount\.com|gserviceaccount\.com|appspot\.com|googlegroups\.com|group\.calendar\.google\.com|resource\.calendar\.google\.com)$/i;
// user@2x.png, name@file.json: a file, not an address.
const FILE_TLD_RE = /\.(?:png|jpe?g|gif|svg|webp|ico|js|mjs|cjs|ts|tsx|jsx|json|md|css|scss|html?|py|rb|go|rs|sh|ya?ml|lock|txt|log|map|xml|toml|pdf|zip|gz|tgz)$/i;
// A real top-level domain: any two-letter country code, or a common generic one.
const TLD_RE = /\.(?:[a-z]{2}|com|org|net|edu|gov|mil|int|info|biz|name|pro|dev|app|xyz|tech|online|site|cloud|email|mail|page|blog|shop|store|studio|design|agency|company|group|world|life|live|news|media|team|work|works|tools|systems|software|solutions|digital|network|health|care|law|bank|finance|consulting|academy|school|university|church|club|social|community|foundation|events|travel|photo|photos|art|music|games|fun|one|top|vip|global|asia|africa|nyc|london|berlin|paris|tokyo)$/i;
const COMMON_MAIL = new Set(["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "yahoo.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "aol.com", "qq.com", "163.com"]);

function maskEmail(local, domain) {
  const d = domain.toLowerCase();
  if (COMMON_MAIL.has(d)) return `${local[0]}***@${d}`;
  const tld = d.slice(d.lastIndexOf("."));
  return `${local[0]}***@${d[0]}***${tld}`;
}

// 13-19 digits, optionally in groups split by single spaces or dashes.
const CARD_RE = /(?<![\dA-Za-z.+-])(?:\d[ -]?){12,18}\d(?![\dA-Za-z]|[.-]\d)/g;
const TEST_CARDS = new Set([
  "4242424242424242", "4111111111111111", "4012888888881881", "4000056655665556", "4000000000000002",
  "5555555555554444", "5105105105105100", "5200828282828210", "2223003122003222",
  "378282246310005", "371449635398431", "6011111111111117", "6011000990139424",
  "3056930009020004", "36227206271667", "3566002020360505", "6200000000000005",
]);

export function luhn(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/** A card brand prefix with that brand's length. */
function cardBrand(d) {
  const n = d.length;
  if (/^4/.test(d) && (n === 13 || n === 16 || n === 19)) return "Visa";
  if ((/^5[1-5]/.test(d) || /^2(?:2[2-9]|[3-6]\d|7[01]|720)/.test(d)) && n === 16) return "Mastercard";
  if (/^3[47]/.test(d) && n === 15) return "Amex";
  if (/^(?:6011|65|64[4-9])/.test(d) && n === 16) return "Discover";
  return null;
}

// US Social Security number, written with dashes.
const SSN_RE = /(?<![\dA-Za-z-])(\d{3})-(\d{2})-(\d{4})(?![\dA-Za-z-])/g;
const SSN_EXAMPLES = new Set(["123-45-6789", "078-05-1120", "219-09-9999", "111-11-1111", "222-22-2222", "333-33-3333", "444-44-4444", "555-55-5555", "777-77-7777", "888-88-8888"]);

const LABEL = { card: "card number", ssn: "US Social Security number", email: "someone's email address" };
const RANK = { card: 4, ssn: 4, email: 1 };

/** Longest text scanned per message. */
const MAX_TEXT = 300_000;

/**
 * Personal data in one text. `own` is the set of the user's own addresses
 * (lower case), which are not counted. Returns
 * [{ type, key, masked, label, rank }]; `key` identifies the value for
 * de-duplication and is never shown.
 */
export function piiIn(text, own = new Set()) {
  const s = String(text ?? "").slice(0, MAX_TEXT);
  const out = [];
  if (s.length < 6) return out;

  if (s.includes("@")) {
    EMAIL_RE.lastIndex = 0;
    for (const m of s.matchAll(EMAIL_RE)) {
      const local = m[1];
      const domain = m[2];
      const full = `${local}@${domain}`.toLowerCase();
      if (own.has(full)) continue;
      if (ROLE_LOCAL_RE.test(local) || NOT_PERSON_LOCAL_RE.test(local)) continue;
      if (NOT_PERSON_DOMAIN_RE.test(domain) || FILE_TLD_RE.test(domain) || !TLD_RE.test(domain)) continue;
      // ssh remotes and scp targets: git@host:path, user@host:/path
      if (s[m.index + m[0].length] === ":") continue;
      out.push({ type: "email", key: `email:${full}`, masked: maskEmail(local, domain) });
    }
  }

  if (/\d{4}/.test(s)) {
    CARD_RE.lastIndex = 0;
    for (const m of s.matchAll(CARD_RE)) {
      const raw = m[0];
      // One separator style, in groups, or none at all.
      if (/ /.test(raw) && /-/.test(raw)) continue;
      const d = raw.replace(/[ -]/g, "");
      if (d.length < 13 || d.length > 19) continue;
      if (/[ -]/.test(raw) && !/^\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}$|^\d{4}([ -])\d{6}\2\d{5}$/.test(raw)) continue;
      const brand = cardBrand(d);
      if (!brand || !luhn(d) || TEST_CARDS.has(d) || /^(\d)\1+$/.test(d)) continue;
      out.push({ type: "card", key: `card:${d}`, masked: `${brand} card ending ${d.slice(-4)}` });
    }

    SSN_RE.lastIndex = 0;
    for (const m of s.matchAll(SSN_RE)) {
      const [raw, area, group, serial] = m;
      if (area === "000" || area === "666" || area[0] === "9" || group === "00" || serial === "0000") continue;
      if (SSN_EXAMPLES.has(raw)) continue;
      // A bare number in this shape is as often an id or a date range. Ask
      // for a nearby word that says what it is.
      const near = s.slice(Math.max(0, m.index - 60), m.index + raw.length + 20);
      if (!/\b(?:ssn|social(?:[ _-]?security)?|soc(?:ial)?[ _-]?sec|taxpayer|tax[ _-]?id|tin)\b/i.test(near)) continue;
      out.push({ type: "ssn", key: `ssn:${raw}`, masked: "***-**-****" });
    }
  }

  for (const f of out) { f.label = LABEL[f.type]; f.rank = RANK[f.type]; }
  return out;
}
