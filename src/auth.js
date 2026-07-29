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

export function totpUri(secretBase32, email, issuer = "Catalyst7 HQ") {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?secret=${secretBase32}&issuer=${encodeURIComponent(
    issuer
  )}&algorithm=SHA1&digits=6&period=30`;
}

// ---- 2FA backup / recovery codes ----
// Ten single-use codes, shown once at generation and stored only as hashes.
//
// Hashed with a single SHA-256 pass rather than PBKDF2, unlike passwords. That
// is deliberate: these are 50 bits of CSPRNG output from a 32-character
// alphabet, not a human-chosen secret, so there is no dictionary to stretch
// against and the login rate limiter already caps guessing. PBKDF2 here would
// cost ~1s per redemption (every stored code has to be tried) and buy nothing.
const BACKUP_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"; // no I/L/O/U/0/1 -- unambiguous when read aloud
const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_LEN = 10;

export function generateBackupCode() {
  const bytes = new Uint8Array(BACKUP_CODE_LEN);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += BACKUP_ALPHABET[b % BACKUP_ALPHABET.length];
  return out.slice(0, 5) + "-" + out.slice(5);
}

export function generateBackupCodes(n = BACKUP_CODE_COUNT) {
  return Array.from({ length: n }, generateBackupCode);
}

// Case- and format-insensitive: users retype these by hand off a printout.
export function normalizeBackupCode(code) {
  return String(code || "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "");
}

export async function hashBackupCode(code) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalizeBackupCode(code)));
  return bytesToHex(new Uint8Array(digest));
}

export function looksLikeBackupCode(input) {
  return normalizeBackupCode(input).length === BACKUP_CODE_LEN;
}

// ---- Google sign-in (OAuth 2.0 authorization code + PKCE) ----
// No library: the whole flow is two fetches and some claim checking.

export const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

export function googleConfigured(env) {
  return !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
}

function base64UrlFromBytes(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomUrlSafe(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return base64UrlFromBytes(arr);
}

export async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64UrlFromBytes(new Uint8Array(digest));
}

export function googleAuthUrl({ clientId, redirectUri, state, nonce, challenge }) {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid email profile",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256",
    // We only ever *authenticate* with Google; nothing here needs offline
    // access or a refresh token, so don't ask for one.
    prompt: "select_account",
  });
  return `${GOOGLE_AUTH_ENDPOINT}?${params.toString()}`;
}

export async function exchangeGoogleCode(env, { code, redirectUri, codeVerifier }) {
  const res = await fetch(GOOGLE_TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      code_verifier: codeVerifier,
    }),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Google token exchange failed (${res.status}): ${detail.slice(0, 300)}`);
  }
  return res.json();
}

export function decodeJwtPayload(jwt) {
  const parts = String(jwt || "").split(".");
  if (parts.length !== 3) throw new Error("Malformed ID token");
  const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return JSON.parse(atob(padded));
}

// Validates the claims of an ID token received *directly* from Google's token
// endpoint over TLS.
//
// The signature is deliberately not re-verified. Google's own guidance is that
// a token fetched server-to-server from the token endpoint over HTTPS needs no
// local signature check, because the TLS channel already authenticates the
// issuer. This never accepts a token from the browser or any other source --
// see the callback route in index.js. If that ever changes, this must grow
// full JWKS/RS256 verification first.
export function validateGoogleIdToken(payload, { clientId, nonce, now = Date.now() }) {
  const problems = [];
  const issuers = ["https://accounts.google.com", "accounts.google.com"];

  if (!issuers.includes(payload.iss)) problems.push(`unexpected issuer: ${payload.iss}`);
  if (payload.aud !== clientId) problems.push("token was issued for a different client");
  if (!payload.exp || payload.exp * 1000 <= now) problems.push("token has expired");
  if (payload.nonce !== nonce) problems.push("nonce mismatch (possible replay)");
  if (!payload.sub) problems.push("token carries no subject");
  if (!payload.email) problems.push("token carries no email");
  if (payload.email_verified !== true && payload.email_verified !== "true") {
    problems.push("Google has not verified this email address");
  }
  return { ok: problems.length === 0, problems };
}

// ---- OAuth handshake state (server-side, single-use) ----
export async function createOAuthState(env, { nonce, codeVerifier, redirectUri }) {
  const state = randomUrlSafe(24);
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  await env.DB.prepare(
    "INSERT INTO oauth_states (state, nonce, code_verifier, redirect_uri, expires_at) VALUES (?, ?, ?, ?, ?)"
  )
    .bind(state, nonce, codeVerifier, redirectUri, expires)
    .run();
  return state;
}

// Consumes the row: a given state can only ever be redeemed once.
export async function consumeOAuthState(env, state) {
  if (!state) return null;
  const row = await env.DB.prepare("SELECT * FROM oauth_states WHERE state = ? AND expires_at > datetime('now')")
    .bind(state)
    .first();
  await env.DB.prepare("DELETE FROM oauth_states WHERE state = ?").bind(state).run();
  return row || null;
}

export async function purgeExpiredOAuthStates(env) {
  await env.DB.prepare("DELETE FROM oauth_states WHERE expires_at <= datetime('now')").run();
}
