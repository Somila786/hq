// Turning an Apify export into HQ leads.
//
// Kept separate from db.js and index.js because it is pure text-in/rows-out
// with no I/O, which means it can be tested directly against real scraper
// output rather than only through an HTTP round trip.
//
// The parser is deliberately forgiving about field names and strict about the
// two things HQ actually needs: a name, and (usually) an email. Apify actors
// disagree with each other about what a business is called -- `title` for the
// Google Maps scraper, `name` or `companyName` elsewhere -- and a founder
// pasting an export should not have to rename columns first.

// ---- CSV ----
//
// Written out rather than split(",") because Apify exports quote any field
// containing a comma, and business addresses are full of commas. A naive split
// silently shifts every column after the address by one, which produces leads
// that look plausible and are wrong -- the worst possible failure here.
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];

    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"'; // escaped quote inside a quoted field
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += c;
      }
      continue;
    }

    if (c === '"') {
      quoted = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      // Swallow CRLF as one break.
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      if (row.some((v) => v !== "")) rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }
  row.push(field);
  if (row.some((v) => v !== "")) rows.push(row);

  if (!rows.length) return [];
  const headers = rows[0].map((h) => h.trim());
  return rows.slice(1).map((r) => Object.fromEntries(headers.map((h, i) => [h, (r[i] ?? "").trim()])));
}

// ---- Field mapping ----

// Matching is case- and separator-insensitive, so `contactEmail`, `contact_email`
// and `Contact Email` all land in the same place.
function normaliseKeys(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    out[String(k).toLowerCase().replace(/[\s_-]/g, "")] = v;
  }
  return out;
}

function pick(row, names) {
  for (const n of names) {
    const v = row[n];
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      const first = v.find((x) => typeof x === "string" && x.trim());
      if (first) return first.trim();
      continue;
    }
    if (typeof v === "object") continue;
    const s = String(v).trim();
    if (s) return s;
  }
  return null;
}

// A crude check on purpose. The goal is to catch "N/A", "-" and a stray phone
// number in the email column, not to adjudicate RFC 5322 -- an over-strict
// pattern would silently drop real addresses, which is worse than letting an
// odd one through for a human to notice on the lead.
export function looksLikeEmail(s) {
  return typeof s === "string" && /^[^\s@]+@[^\s@.]+\.[^\s@]+$/.test(s);
}

const NAME_KEYS = ["name", "contactname", "ownername", "fullname", "person", "title", "companyname", "businessname", "company"];
const COMPANY_KEYS = ["company", "companyname", "businessname", "title", "name"];
const EMAIL_KEYS = ["contactemail", "email", "emails", "emailaddress", "publicemail"];
const PHONE_KEYS = ["phone", "phonenumber", "phoneunformatted", "telephone", "mobile"];
const WEBSITE_KEYS = ["website", "url", "domain", "site", "web"];
const ADDRESS_KEYS = ["address", "fulladdress", "street", "location"];
const CATEGORY_KEYS = ["categoryname", "category", "type", "industry"];
const RATING_KEYS = ["totalscore", "rating", "stars", "score"];
const REVIEWS_KEYS = ["reviewscount", "reviews", "usertotalratings", "reviewcount"];
const VALUE_KEYS = ["valueestimate", "value", "dealvalue", "estimate"];

// The scraped context that decides whether a lead is worth contacting -- for
// the Apify clusters that is "no website" and the Google Business Profile
// signals -- is preserved as notes rather than dropped. Qualifying happens in
// HQ, and it cannot happen against fields the import threw away.
function buildNotes(row) {
  const bits = [];
  const website = pick(row, WEBSITE_KEYS);
  const phone = pick(row, PHONE_KEYS);
  const category = pick(row, CATEGORY_KEYS);
  const address = pick(row, ADDRESS_KEYS);
  const rating = pick(row, RATING_KEYS);
  const reviews = pick(row, REVIEWS_KEYS);

  if (category) bits.push(category);
  if (address) bits.push(address);
  if (phone) bits.push(`Phone: ${phone}`);
  // Absence is the signal, so it is stated rather than left blank.
  bits.push(website ? `Website: ${website}` : "No website found");
  if (rating) bits.push(`Rating ${rating}${reviews ? ` (${reviews} reviews)` : ""}`);

  return bits.join(" · ").slice(0, 1000) || null;
}

function toNumber(v) {
  if (v === null || v === undefined) return null;
  const n = Number(String(v).replace(/[^\d.-]/g, ""));
  return Number.isFinite(n) && n > 0 ? n : null;
}

/**
 * Parses pasted text into candidate leads.
 *
 * Returns { rows, error }. Every row carries a `status` explaining what will
 * happen to it, so the preview can show the user the decision rather than a
 * count they have to trust.
 */
export function parseLeads(text, { source = "apify" } = {}) {
  const trimmed = String(text || "").trim();
  if (!trimmed) return { rows: [], error: "Nothing pasted." };

  let raw;
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      raw = Array.isArray(parsed) ? parsed : Array.isArray(parsed.items) ? parsed.items : [parsed];
    } catch (e) {
      return { rows: [], error: `That looks like JSON but doesn't parse: ${e.message}` };
    }
  } else {
    raw = parseCsv(trimmed);
    if (!raw.length) return { rows: [], error: "Couldn't find any rows. Paste an Apify JSON export, or CSV with a header row." };
  }

  const rows = raw.map((entry) => {
    const row = normaliseKeys(entry);
    const company = pick(row, COMPANY_KEYS);
    const name = pick(row, NAME_KEYS) || company;
    const emailRaw = pick(row, EMAIL_KEYS);
    const email = emailRaw && looksLikeEmail(emailRaw) ? emailRaw.toLowerCase() : null;

    return {
      name: name ? name.slice(0, 200) : null,
      company: company ? company.slice(0, 200) : null,
      contact_email: email,
      value_estimate: toNumber(pick(row, VALUE_KEYS)),
      source,
      notes: buildNotes(row),
      // Surfaced so the preview can say *why* an email was dropped rather than
      // just showing a blank cell.
      rejected_email: emailRaw && !email ? emailRaw.slice(0, 100) : null,
      status: name ? "new" : "invalid",
    };
  });

  return { rows, error: null };
}

/**
 * Marks each parsed row against what is already in HQ and the caller's choices.
 *
 * Deduplication is by email where there is one, and by name+company otherwise.
 * That second key is weaker, which is exactly why leads with no email are
 * skipped by default -- re-pasting the same export would otherwise duplicate
 * every one of them.
 */
export function classifyLeads(rows, { existingEmails = new Set(), existingKeys = new Set(), skipNoEmail = true } = {}) {
  const seenEmails = new Set();
  const seenKeys = new Set();

  for (const r of rows) {
    if (r.status === "invalid") continue;

    if (!r.contact_email) {
      if (skipNoEmail) {
        r.status = "no_email";
        continue;
      }
      const key = `${(r.name || "").toLowerCase()}|${(r.company || "").toLowerCase()}`;
      if (existingKeys.has(key) || seenKeys.has(key)) {
        r.status = "duplicate";
        continue;
      }
      seenKeys.add(key);
      r.status = "new";
      continue;
    }

    const email = r.contact_email.toLowerCase();
    // Duplicates within the paste itself count too: an export can list the same
    // business twice, and the first insert would not be visible to the second.
    if (existingEmails.has(email) || seenEmails.has(email)) {
      r.status = "duplicate";
      continue;
    }
    seenEmails.add(email);
    r.status = "new";
  }

  const counts = { new: 0, duplicate: 0, no_email: 0, invalid: 0 };
  for (const r of rows) counts[r.status] = (counts[r.status] || 0) + 1;
  return counts;
}
