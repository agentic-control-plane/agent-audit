// Host classification for agent-email-guard. Pure, no DNS.
//
// Literal addresses are classified by range; hostnames only by the names
// that never leave the machine. Anything that does not parse cleanly is
// "external" — the conservative side for a check that only ever fires on
// external destinations. Decimal/hex/octal IPv4 spellings stay external.

const SECOND_LEVEL = new Set(["co", "com", "org", "net", "ac", "gov", "edu"]);

function parseIPv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const out = [];
  for (const p of m.slice(1)) {
    if (p.length > 1 && p.startsWith("0")) return null;
    const n = Number(p);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

/** "loopback" | "private" | "link-local" | "external" */
export function classifyHost(rawHost) {
  let h = String(rawHost ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (!h) return "external";
  if (h === "localhost" || h.endsWith(".localhost")) return "loopback";
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(h);
  const v4 = parseIPv4(mapped ? mapped[1] : h);
  if (v4) {
    const [a, b] = v4;
    if (a === 127 || (a === 0 && b === 0 && v4[2] === 0 && v4[3] === 0)) return "loopback";
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
    if (a === 169 && b === 254) return "link-local";
    return "external";
  }
  if (h.includes(":")) {
    if (h === "::1") return "loopback";
    if (/^f[cd][0-9a-f]{2}:/.test(h)) return "private";
    if (/^fe[89ab][0-9a-f]:/.test(h)) return "link-local";
  }
  return "external";
}

export function isInternalHostClass(c) {
  return c === "loopback" || c === "private" || c === "link-local";
}

/** Registrable-domain-ish display form: api.data.sec.gov → sec.gov. */
export function displayHost(host) {
  const h = String(host ?? "").toLowerCase().replace(/\.$/, "");
  if (parseIPv4(h) || h.includes(":")) return h;
  const labels = h.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const take = SECOND_LEVEL.has(labels[labels.length - 2]) && labels[labels.length - 1].length === 2 ? 3 : 2;
  return labels.slice(-take).join(".");
}
