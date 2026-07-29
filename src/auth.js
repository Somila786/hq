// Auth helpers: password hashing (PBKDF2/WebCrypto), sessions, cookies, CSRF,
// login rate limiting, TOTP 2FA, ISO week math.
// No external deps -- everything here runs on Workers' built-in Web Crypto API.

export async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const saltBytes = hexToBytes(saltHex);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

export function randomToken(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}

function bytesToHex(arr) {
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export async function setPassword(env, userId, password) {
  const salt = randomToken(16);
  const hash = await hashPassword(password, salt);
  await env.DB.prepare(
    "UPDATE users SET password_hash = ?, password_salt = ?, setup_token = NULL WHERE id = ?"
  )
    .bind(hash, salt, userId)
    .run();
}

export async function verifyPassword(env, user, password) {
  if (!user.password_hash || !user.password_salt) return false;
  const hash = await hashPassword(password, user.password_salt);
  return hash === user.password_hash;
}

// ---- Weeks are anchored to Monday (UTC), formatted YYYY-MM-DD ----
export function isoWeekStart(date = new Date()) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const day = d.getUTCDay() || 7; // Sun -> 7
  if (day !== 1) d.setUTCDate(d.getUTCDate() - (day - 1));
  return d.toISOString().slice(0, 10);
}

export function addDays(isoDate, days) {
  const d = new Date(isoDate + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

// ---- Cookies ----
export function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  return Object.fromEntries(
    header
      .split(";")
      .filter(Boolean)
      .map((c) => {
        const idx = c.indexOf("=");
        return [c.slice(0, idx).trim(), decodeURIComponent(c.slice(idx + 1).trim())];
      })
  );
}

export function sessionCookie(token) {
  return `c7_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
}

export function clearCookie() {
  return `c7_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

export function pendingCookie(token) {
  return `c7_pending=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300`;
}

export function clearPendingCookie() {
  return `c7_pending=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

// UI preference only -- read server-side in index.js to pick the theme, never
// by client JS, so HttpOnly is fine. One year, survives sessions.
export function themeCookie(theme) {
  return `c7_theme=${theme}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=31536000`;
}

// ---- Sessions (CSRF token minted at session creation, lives with the session) ----
export async function createSession(env, userId) {
  const token = randomToken();
  const csrf = randomToken(24);
  const expires = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
  await env.DB.prepare(
    "INSERT INTO sessions (token, user_id, expires_at, csrf_token) VALUES (?, ?, ?, ?)"
  )
    .bind(token, userId, expires, csrf)
    .run();
  return token;
}

export async function destroySession(env, token) {
  if (!token) return;
  await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
}

export async function getSessionUser(request, env) {
  const cookies = parseCookies(request);
  const token = cookies["c7_session"];
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.*, s.csrf_token as session_csrf FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ? AND s.expires_at > datetime('now')`
  )
    .bind(token)
    .first();
  return row || null;
}

// ---- CSRF ----
// Every mutating form carries a hidden `_csrf` field. Verified against the
// session's own csrf_token before any POST route is allowed to execute.
export function verifyCsrf(user, formValue) {
  return !!user.session_csrf && !!formValue && user.session_csrf === formValue;
}

// ---- Pending 2FA logins (short-lived, separate from real sessions) ----
export async function createPendingLogin(env, userId) {
  const token = randomToken();
  const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  await env.DB.prepare("INSERT INTO pending_logins (token, user_id, expires_at) VALUES (?, ?, ?)")
    .bind(token, userId, expires)
    .run();
  return token;
}

export async function getPendingLogin(request, env) {
  const cookies = parseCookies(request);
  const token = cookies["c7_pending"];
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT p.*, u.* FROM pending_logins p JOIN users u ON u.id = p.user_id
     WHERE p.token = ? AND p.expires_at > datetime('now')`
  )
    .bind(token)
    .first();
  return row ? { ...row, pendingToken: token } : null;
}

export async function destroyPendingLogin(env, token) {
  if (!token) return;
  await env.DB.prepare("DELETE FROM pending_logins WHERE token = ?").bind(token).run();
}

// ---- Login rate limiting (D1-backed, no extra bindings needed) ----
// Blocks after 5 failed attempts for one email, or 20 failed attempts from
// one IP across any emails, within a rolling 15-minute window.
export async function checkRateLimit(env, email, ip) {
  const byEmail = await env.DB.prepare(
    `SELECT COUNT(*) as n FROM login_attempts
     WHERE email = ? AND success = 0 AND attempted_at > datetime('now', '-15 minutes')`
  )
    .bind(email)
    .first();
  if (byEmail.n >= 5) return { blocked: true, reason: "Too many attempts for this account. Try again in 15 minutes." };

  if (ip) {
    const byIp = await env.DB.prepare(
      `SELECT COUNT(*) as n FROM login_attempts
       WHERE ip = ? AND success = 0 AND attempted_at > datetime('now', '-15 minutes')`
    )
      .bind(ip)
      .first();
    if (byIp.n >= 20) return { blocked: true, reason: "Too many attempts from this network. Try again in 15 minutes." };
  }
  return { blocked: false };
}

export async function recordLoginAttempt(env, email, ip, success) {
  await env.DB.prepare("INSERT INTO login_attempts (email, ip, success) VALUES (?, ?, ?)")
    .bind(email, ip || null, success ? 1 : 0)
    .run();
}

// ---- TOTP 2FA (RFC 6238), dependency-free ----
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes) {
  let bits = "";
  for (const b of bytes) bits += b.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) {
    out += BASE32_ALPHABET[parseInt(bits.substr(i, 5), 2)];
  }
  if (bits.length % 5 !== 0) {
    const rem = bits.slice(bits.length - (bits.length % 5)).padEnd(5, "0");
    out += BASE32_ALPHABET[parseInt(rem, 2)];
  }
  return out;
}

function base32Decode(base32) {
  let bits = "";
  for (const char of base32.toUpperCase().replace(/=+$/, "")) {
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return new Uint8Array(bytes);
}

export function generateTotpSecret() {
  const arr = new Uint8Array(20);
  crypto.getRandomValues(arr);
  return base32Encode(arr);
}

async function totpCodeAt(secretBase32, counter, digits = 6) {
  const key = base32Decode(secretBase32);
  const counterBytes = new ArrayBuffer(8);
  new DataView(counterBytes).setUint32(4, counter >>> 0);
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const hmac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBytes));
  const offset = hmac[hmac.length - 1] & 0xf;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (bin % 10 ** digits).toString().padStart(digits, "0");
}

export async function totpCodeNow(secretBase32, timeStepSeconds = 30) {
  const counter = Math.floor(Date.now() / 1000 / timeStepSeconds);
  return totpCodeAt(secretBase32, counter);
}

// Accepts the current 30s window plus one step of drift either side.
export async function verifyTotp(secretBase32, userCode, timeStepSeconds = 30) {
  if (!userCode || !/^\d{6}$/.test(userCode.trim())) return false;
  const counter = Math.floor(Date.now() / 1000 / timeStepSeconds);
  for (const offset of [0, -1, 1]) {
    const code = await totpCodeAt(secretBase32, counter + offset);
    if (code === userCode.trim()) return true;
  }
  return false;
}

export function totpUri(secretBase32, email, issuer = "Catalyst7 KPI") {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secretBase32}&issuer=${encodeURIComponent(
    issuer
  )}&algorithm=SHA1&digits=6&period=30`;
}
