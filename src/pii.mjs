// Personal data in text the model read: prompts and tool output.
// Precision over recall. Every detector returns a masked form for the
// report and never the value itself.

const EMAIL_RE = /(?<![A-Za-z0-9._%+'-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})(?![A-Za-z0-9-])/g;
// Addresses that are a role, a bot or a tool, not a person.
const ROLE_LOCAL_RE = /^(?:git|hg|svn|root|admin|administrator|postmaster|webmaster|hostmaster|abuse|security|support|help|info|hello|hi|contact|sales|team|press|legal|privacy|billing|jobs|careers|feedback|notifications?|mailer-daemon|bounce|bot|ci|ops|dev|devs|eng|engineering|it|office|mail|news|newsletter|marketing|accounts?|service|system|alerts?|actions|dependabot|renovate|github-actions|ec2-user|ubuntu|deploy|www-data|user|username|name|you|me|email|someone|somebody|foo|bar|baz|test|tester|testing|example|sample|demo|jane|john|jdoe|alice|bob)$/i;
const NOT_PERSON_LOCAL_RE = /no-?reply|do-?not-?reply|\[bot\]|^\d+\+/i;
const NOT_PERSON_DOMAIN_RE = /(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost|local|internal|lan|users\.noreply\.github\.com|noreply\.github\.com|sentry\.io|iam\.gserviceaccount\.com|gserviceaccount\.com|appspot\.com|googlegroups\.com|group\.calendar\.google\.com|resource\.calendar\.google\.com|amazonaws\.com|compute\.internal|mailinator\.com|corp\.com|owner\.com|evil\.com|attacker\.com|domain\.com|email\.com|company\.com|test\.com|foo\.com|bar\.com|baz\.com|placeholder\.com|yourcompany\.com|mycompany\.com|yourdomain\.com|mydomain\.com)$/i;
// acme-corp.dev, x.com, b.co: fixture and placeholder domains.
const PLACEHOLDER_DOMAIN_RE = /^(?:[a-z0-9]\.|acme[.-]|contoso\.|fabrikam\.|northwind|initech\.|globex\.|example-)/i;
// user@2x.png, name@file.json: a file, not an address.
const FILE_TLD_RE = /\.(?:png|jpe?g|gif|svg|webp|ico|js|mjs|cjs|ts|tsx|jsx|json|md|css|scss|html?|py|rb|go|rs|sh|ya?ml|lock|txt|log|map|xml|toml|pdf|zip|gz|tgz)$/i;
// A real top-level domain: any two-letter country code, or a common generic one.
const TLD_RE = /\.(?:[a-z]{2}|com|org|net|edu|gov|mil|int|info|biz|name|pro|dev|app|xyz|tech|online|site|cloud|email|mail|page|blog|shop|store|studio|design|agency|company|group|world|life|live|news|media|team|work|works|tools|systems|software|solutions|digital|network|health|care|law|bank|finance|consulting|academy|school|university|church|club|social|community|foundation|events|travel|photo|photos|art|music|games|fun|one|top|vip|global|asia|africa|nyc|london|berlin|paris|tokyo)$/i;
const COMMON_MAIL = new Set(["gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "icloud.com", "me.com", "proton.me", "protonmail.com", "aol.com", "qq.com", "163.com"]);
// A git log, a commit trailer or a package manifest names its authors. That
// is project metadata, not personal data someone pasted in.
const AUTHORSHIP_RE = /(?:\bauthor|\bcommitter|\bcommit:|signed-off-by|co-authored-by|reviewed-by|acked-by|reported-by|tested-by|\bmaintainers?|\bcontributors?|\bcopyright|\(c\)|©)[^\n]{0,120}$/i;
// ssh host targets and URL userinfo: user@host is a login, not an address.
const LOGIN_BEFORE_RE = /(?::\/\/[^\s/@]{0,200}|(?:^|[\s;&|(])(?:ssh|scp|sftp|rsync|mosh|ssh-copy-id)\b[^\n]{0,200})$/;

function maskEmail(local, domain) {
  const d = domain.toLowerCase();
  // A one or two letter name would be given away by its first letter.
  const l = local.length >= 3 ? `${local[0]}***` : "***";
  if (COMMON_MAIL.has(d)) return `${l}@${d}`;
  const tld = d.slice(d.lastIndexOf("."));
  const first = d.slice(0, d.indexOf("."));
  return `${l}@${first.length >= 3 ? d[0] : ""}***${tld}`;
}

// 13-19 digits, optionally in groups split by single spaces or dashes.
const CARD_RE = /(?<![\dA-Za-z.+-])(?:\d[ -]?){12,18}\d(?![\dA-Za-z]|[.-]\d)/g;
const GROUPED_CARD_RE = /^\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}$|^\d{4}([ -])\d{6}\2\d{5}$/;
// Card numbers payment providers publish for testing.
const TEST_CARDS = new Set([
  "4242424242424242", "4111111111111111", "4532015112830366", "4916338506082832", "4024007103939509", "4556737586899855", "4012888888881881", "4009348888881881", "4012000033330026", "4012000077777777",
  "4217651111111119", "4500600000000061", "4005519200000004", "4444333322221111", "4917610000000000", "4988438843884305",
  "5555555555554444", "5105105105105100", "5200828282828210", "5431111111111111", "5454545454545454", "5500000000000004",
  "5577000055770004", "5136333333333335", "5585558555855583", "5399999999999999", "2223003122003222", "2223000048400011",
  "2222400010000008", "2222400030000004", "2222410740360010", "2222410700000002", "2223520443560010",
  "378282246310005", "371449635398431", "378734493671000", "370000000000002", "374245455400126", "340000000000009",
  "6011111111111117", "6011000990139424", "6011000000000004", "6011016011016011", "6011981111111113", "6555900000604105",
  "3056930009020004", "36227206271667", "3566002020360505", "6200000000000005",
]);
const CARD_WORD_RE = /\b(?:cards?|card[ _-]?(?:number|num|no)|cc|ccn|pan|visa|master ?card|amex|american express|discover|credit|debit|payment|billing)\b/i;
const TEST_WORD_RE = /\b(?:tests?|testing|fixtures?|stripe|braintree|adyen|sandbox|examples?|dummy|fake|sample|mock|demo|placeholder)\b/i;

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

/** Published test numbers and obvious placeholders. */
function testCard(d) {
  return TEST_CARDS.has(d) || /^40000\d/.test(d) || /(\d)\1{6,}/.test(d) || new Set(d).size <= 4;
}

// US Social Security number, written with dashes.
const SSN_RE = /(?<![\dA-Za-z-])(\d{3})-(\d{2})-(\d{4})(?![\dA-Za-z-])/g;
const SSN_EXAMPLES = new Set(["123-45-6789", "078-05-1120", "219-09-9999", "111-11-1111", "222-22-2222", "333-33-3333", "444-44-4444", "555-55-5555", "777-77-7777", "888-88-8888"]);
const SSN_WORD_RE = /\b(?:ssn|social(?:[ _-]?security)?|soc(?:ial)?[ _-]?sec|taxpayer|tax[ _-]?id|tin)\b/i;

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
  // Tool output often arrives JSON-escaped: a literal \n or \t before a
  // value would otherwise read as a letter glued to it.
  const s = String(text ?? "").slice(0, MAX_TEXT).replace(/\\[nrt]/g, "  ").replace(/\\u00[0-9a-fA-F]{2}/g, "      ");
  const out = [];
  if (s.length < 6) return out;
  const before = (i, n) => s.slice(Math.max(0, i - n), i);
  const around = (i, len, pre, post) => s.slice(Math.max(0, i - pre), i + len + post);

  if (s.includes("@")) {
    EMAIL_RE.lastIndex = 0;
    for (const m of s.matchAll(EMAIL_RE)) {
      const local = m[1];
      const domain = m[2];
      const full = `${local}@${domain}`.toLowerCase();
      if (own.has(full)) continue;
      if (ROLE_LOCAL_RE.test(local) || NOT_PERSON_LOCAL_RE.test(local)) continue;
      if (NOT_PERSON_DOMAIN_RE.test(domain) || PLACEHOLDER_DOMAIN_RE.test(domain) || FILE_TLD_RE.test(domain) || !TLD_RE.test(domain)) continue;
      // ssh remotes and scp targets: git@host:path, user@host:/path
      if (s[m.index + m[0].length] === ":") continue;
      const lead = before(m.index, 220);
      if (LOGIN_BEFORE_RE.test(lead) || AUTHORSHIP_RE.test(lead)) continue;
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
      const grouped = /[ -]/.test(raw);
      if (grouped && !GROUPED_CARD_RE.test(raw)) continue;
      const brand = cardBrand(d);
      if (!brand || !luhn(d) || testCard(d)) continue;
      const near = around(m.index, raw.length, 80, 30);
      // One random 16-digit id in ten passes the checksum. A bare run of
      // digits needs a word nearby that says it is a card.
      if (!grouped && !CARD_WORD_RE.test(near)) continue;
      if (TEST_WORD_RE.test(near)) continue;
      out.push({ type: "card", key: `card:${d}`, masked: `${brand} card ending ${d.slice(-4)}` });
    }

    SSN_RE.lastIndex = 0;
    for (const m of s.matchAll(SSN_RE)) {
      const [raw, area, group, serial] = m;
      if (area === "000" || area === "666" || area[0] === "9" || group === "00" || serial === "0000") continue;
      if (SSN_EXAMPLES.has(raw)) continue;
      // A bare number in this shape is as often an id or a date range. Ask
      // for a nearby word that says what it is.
      if (!SSN_WORD_RE.test(around(m.index, raw.length, 60, 20))) continue;
      out.push({ type: "ssn", key: `ssn:${raw}`, masked: "***-**-****" });
    }
  }

  for (const f of out) {
    f.label = LABEL[f.type];
    f.rank = RANK[f.type];
    // A personal mailbox before a work address, and both before a public office.
    if (f.type === "email") {
      const d = f.key.slice(f.key.indexOf("@") + 1);
      f.rank = COMMON_MAIL.has(d) ? 2 : /\.(?:gov|mil|edu|us)$/.test(d) ? 0.5 : 1;
    }
  }
  return out;
}
