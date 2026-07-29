import {
  getSessionUser,
  createSession,
  destroySession,
  sessionCookie,
  clearCookie,
  parseCookies,
  verifyPassword,
  setPassword,
  randomToken,
  isoWeekStart,
  addDays,
  verifyCsrf,
  checkRateLimit,
  recordLoginAttempt,
  createPendingLogin,
  getPendingLogin,
  destroyPendingLogin,
  pendingCookie,
  clearPendingCookie,
  themeCookie,
  generateTotpSecret,
  totpUri,
  verifyTotp,
  generateBackupCodes,
  hashBackupCode,
  looksLikeBackupCode,
  generateInviteCode,
  hashInviteCode,
  googleConfigured,
  googleAuthUrl,
  exchangeGoogleCode,
  decodeJwtPayload,
  validateGoogleIdToken,
  randomUrlSafe,
  pkceChallenge,
  createOAuthState,
  consumeOAuthState,
  purgeExpiredOAuthStates,
} from "./auth.js";
import * as db from "./db.js";
import * as views from "./views.js";

// ---- Security response headers ----
//
// The site loads no external resources and ships no script files, so the CSP
// can be close to maximally strict. Two exceptions, both pre-existing inline
// event handlers rather than anything this pass introduced:
//
//   - `this.form.submit()`   -- lead stage <select> auto-submit
//   - `return confirm(...)`  -- retention "Erase" confirmation
//
// Inline *handlers* cannot be covered by a plain hash the way an inline
// <script> block can, so they need 'unsafe-hashes' alongside their digests.
// Despite the name that is not a wildcard: only these two exact source strings
// can run, and injected script still cannot. Deleting both handlers would let
// this drop to `script-src 'none'`; tests/run.mjs asserts these digests still
// match what views.js emits, so they cannot silently drift.
const INLINE_SCRIPT_HASHES = [
  "'sha256-osjxnKEPL/pQJbFk1dKsF7PYFmTyMWGmVSiL9inhxJY='", // this.form.submit()
  "'sha256-h8g6LCqXGbG2tO/pvAHBjSIDgOVHHT7/zXTJSzndxl0='", // retention erase confirm()
  "'sha256-sBUkWCcHNuXUK0ODUDXA2EfK7BwSPxu7JXNkACjavvM='", // team revoke-access confirm()
];

// style-src keeps 'unsafe-inline': the layout ships one big inline <style>
// block (hashable) but also uses a scattering of inline style="" attributes
// (not hashable without listing every one). Style injection is a far smaller
// prize than script injection, and script-src stays locked down regardless.
const CSP = [
  "default-src 'none'",
  `script-src 'unsafe-hashes' ${INLINE_SCRIPT_HASHES.join(" ")}`,
  "style-src 'unsafe-inline'",
  "img-src 'self' data:",
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

const SECURITY_HEADERS = {
  "Content-Security-Policy": CSP,
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  // Must stay `same-origin`, not `no-referrer`: /theme/toggle reads the
  // Referer to send you back to the page you were on. Cross-origin requests
  // (the hop to Google) still leak nothing.
  "Referrer-Policy": "same-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=(), usb=(), interest-cohort=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  // Every page is per-user and dynamic; none should sit in a shared or
  // on-disk cache where it survives logout or the back button.
  "Cache-Control": "no-store",
  // Ignored by browsers over plain http (so the local preview is unaffected)
  // and by Cloudflare's own edge on workers.dev.
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

// Set-Cookie cannot be safely comma-joined into a single header (cookie
// Expires values contain commas), so any extraHeaders["Set-Cookie"] may be
// a string or an array of strings -- each gets its own header line.
function buildHeaders(base, extraHeaders) {
  const headers = new Headers({ ...SECURITY_HEADERS, ...base });
  for (const [key, value] of Object.entries(extraHeaders)) {
    if (key === "Set-Cookie" && Array.isArray(value)) {
      for (const v of value) headers.append("Set-Cookie", v);
    } else {
      headers.set(key, value);
    }
  }
  return headers;
}

function html(body, status = 200, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: buildHeaders({ "Content-Type": "text/html; charset=utf-8" }, extraHeaders),
  });
}

function redirect(location, extraHeaders = {}) {
  return new Response(null, { status: 302, headers: buildHeaders({ Location: location }, extraHeaders) });
}

// A POST with a missing or unparseable body should fall through to the CSRF
// guard as an empty form (-> a clean 403), not throw and surface as a 500 with
// a row in error_log. Real browser submissions always parse; the ones that
// don't are junk or probing traffic, and shouldn't be able to fill the log.
async function readForm(request) {
  try {
    const form = await request.formData();
    return Object.fromEntries(form.entries());
  } catch {
    return {};
  }
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || null;
}

function csrfGuard(user, form, theme) {
  if (!verifyCsrf(user, form._csrf)) {
    return html(views.errorPage("Session expired or the form was stale. Please refresh and try again.", 403, theme), 403);
  }
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const theme = parseCookies(request)["c7_theme"] === "light" ? "light" : "dark";

    try {
      // ---------- Public: theme toggle ----------
      // Public and unauthenticated on purpose -- the login/setup pages need it
      // too. No CSRF token: it's a same-origin-checked GET that flips a UI
      // preference cookie and touches no user data.
      if (path === "/theme/toggle") {
        const next = theme === "light" ? "dark" : "light";
        let dest = "/";
        const ref = request.headers.get("Referer");
        if (ref) {
          try {
            const refUrl = new URL(ref);
            if (refUrl.origin === url.origin) dest = refUrl.pathname + refUrl.search;
          } catch {}
        }
        return redirect(dest, { "Set-Cookie": themeCookie(next) });
      }

      // ---------- Public: login ----------
      if (path === "/login" && method === "GET") {
        const existing = await getSessionUser(request, env);
        if (existing) return redirect("/");
        return html(views.loginPage({ theme, googleEnabled: googleConfigured(env) }));
      }

      // ---------- Public: Google sign-in ----------
      // Google proves *who* someone is. It never decides whether they may in:
      // that stays with the users table, checked in the callback below.
      if (path === "/auth/google" && method === "GET") {
        if (!googleConfigured(env)) {
          return html(views.errorPage("Google sign-in isn't configured on this deployment.", 404, theme), 404);
        }
        const existing = await getSessionUser(request, env);
        if (existing) return redirect("/");

        await purgeExpiredOAuthStates(env);
        const redirectUri = `${url.origin}/auth/google/callback`;
        const nonce = randomUrlSafe(16);
        const codeVerifier = randomUrlSafe(32);
        const challenge = await pkceChallenge(codeVerifier);
        const state = await createOAuthState(env, { nonce, codeVerifier, redirectUri });

        return redirect(googleAuthUrl({ clientId: env.GOOGLE_CLIENT_ID, redirectUri, state, nonce, challenge }));
      }

      if (path === "/auth/google/callback" && method === "GET") {
        if (!googleConfigured(env)) {
          return html(views.errorPage("Google sign-in isn't configured on this deployment.", 404, theme), 404);
        }
        const ip = clientIp(request);
        const googleError = url.searchParams.get("error");
        if (googleError) {
          // User cancelled at Google's consent screen, or Google refused.
          return html(
            views.loginPage({ theme, googleEnabled: true, error: "Google sign-in was cancelled." }),
            400
          );
        }

        // Single-use: consumeOAuthState deletes the row, so a replayed
        // callback URL cannot be redeemed twice.
        const handshake = await consumeOAuthState(env, url.searchParams.get("state"));
        if (!handshake) {
          return html(
            views.loginPage({
              theme,
              googleEnabled: true,
              error: "That sign-in link expired or was already used. Please try again.",
            }),
            400
          );
        }

        const code = url.searchParams.get("code");
        if (!code) {
          return html(views.loginPage({ theme, googleEnabled: true, error: "Google sign-in failed." }), 400);
        }

        let payload;
        try {
          const tokens = await exchangeGoogleCode(env, {
            code,
            redirectUri: handshake.redirect_uri,
            codeVerifier: handshake.code_verifier,
          });
          payload = decodeJwtPayload(tokens.id_token);
        } catch (err) {
          await db.logError(env, path, err.stack || err.message || String(err));
          return html(
            views.loginPage({ theme, googleEnabled: true, error: "Couldn't complete Google sign-in. Please try again." }),
            502
          );
        }

        const check = validateGoogleIdToken(payload, { clientId: env.GOOGLE_CLIENT_ID, nonce: handshake.nonce });
        if (!check.ok) {
          await db.logError(env, path, "Rejected Google ID token: " + check.problems.join("; "));
          await db.logAudit(env, null, "login_google_rejected", "user", null, check.problems.join("; "));
          return html(views.loginPage({ theme, googleEnabled: true, error: "Google sign-in failed verification." }), 401);
        }

        const email = String(payload.email).trim().toLowerCase();
        const limit = await checkRateLimit(env, email, ip);
        if (limit.blocked) {
          return html(views.loginPage({ theme, googleEnabled: true, error: limit.reason }), 429);
        }

        const user = await db.getUserByEmail(env, email);

        // The allowlist. A valid Google identity for an address we don't know
        // is still a failed login.
        if (!user) {
          await recordLoginAttempt(env, email, ip, false);
          await db.logAudit(env, null, "login_google_denied", "user", null, email);
          return html(
            views.loginPage({
              theme,
              googleEnabled: true,
              error: "That Google account isn't authorised for this app. Ask a founder to add you.",
            }),
            403
          );
        }

        // Email addresses can be reassigned inside a Google Workspace; the
        // `sub` claim cannot. Once bound, a mismatch means this is not the
        // same underlying account any more.
        if (user.google_sub && user.google_sub !== payload.sub) {
          await recordLoginAttempt(env, email, ip, false);
          await db.logAudit(env, user, "login_google_sub_mismatch", "user", user.id, email);
          return html(
            views.loginPage({
              theme,
              googleEnabled: true,
              error: "This Google account doesn't match the one linked to that address. Ask a founder to re-link it.",
            }),
            403
          );
        }
        if (!user.google_sub) {
          await db.bindGoogleSub(env, user.id, payload.sub);
          await db.logAudit(env, user, "google_account_linked", "user", user.id, email);
        }

        await recordLoginAttempt(env, email, ip, true);

        // A federated login doesn't excuse 2FA the user explicitly turned on.
        if (user.totp_enabled) {
          const pendingToken = await createPendingLogin(env, user.id);
          return redirect("/login/2fa", { "Set-Cookie": pendingCookie(pendingToken) });
        }

        await db.logAudit(env, user, "login_google", "user", user.id, null);
        const token = await createSession(env, user.id);
        return redirect("/", { "Set-Cookie": sessionCookie(token) });
      }

      if (path === "/login" && method === "POST") {
        const { email, password } = await readForm(request);
        const normalizedEmail = (email || "").trim().toLowerCase();
        const ip = clientIp(request);

        const limit = await checkRateLimit(env, normalizedEmail, ip);
        if (limit.blocked) {
          return html(views.loginPage({ error: limit.reason, theme, googleEnabled: googleConfigured(env) }), 429);
        }

        const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(normalizedEmail).first();
        const ok = user && (await verifyPassword(env, user, password || ""));
        await recordLoginAttempt(env, normalizedEmail, ip, !!ok);

        if (!ok) {
          return html(
            views.loginPage({ error: "Incorrect email or password.", theme, googleEnabled: googleConfigured(env) }),
            401
          );
        }

        if (user.totp_enabled) {
          const pendingToken = await createPendingLogin(env, user.id);
          return redirect("/login/2fa", { "Set-Cookie": pendingCookie(pendingToken) });
        }

        const token = await createSession(env, user.id);
        return redirect("/", { "Set-Cookie": sessionCookie(token) });
      }

      // ---------- Public: 2FA verification step ----------
      if (path === "/login/2fa" && method === "GET") {
        const pending = await getPendingLogin(request, env);
        if (!pending) return redirect("/login");
        return html(views.totpVerifyPage({ theme }));
      }

      if (path === "/login/2fa" && method === "POST") {
        const pending = await getPendingLogin(request, env);
        if (!pending) return redirect("/login");

        const ip = clientIp(request);
        const rlKey = "2fa:" + pending.email;
        const limit = await checkRateLimit(env, rlKey, ip);
        if (limit.blocked) return html(views.totpVerifyPage({ error: limit.reason, theme }), 429);

        const { code } = await readForm(request);

        // Either the current authenticator code, or one of the single-use
        // backup codes issued when 2FA was switched on.
        let ok = await verifyTotp(pending.totp_secret, code || "");
        let usedBackupCode = false;
        if (!ok && looksLikeBackupCode(code)) {
          ok = await db.redeemBackupCode(env, pending.user_id, await hashBackupCode(code));
          usedBackupCode = ok;
        }
        await recordLoginAttempt(env, rlKey, ip, ok);

        if (!ok) return html(views.totpVerifyPage({ error: "Incorrect code. Try again.", theme }), 401);

        if (usedBackupCode) {
          const left = await db.countUnusedBackupCodes(env, pending.user_id);
          await db.logAudit(
            env,
            { id: pending.user_id, name: pending.name },
            "2fa_backup_code_used",
            "user",
            pending.user_id,
            `${left} backup code${left === 1 ? "" : "s"} remaining`
          );
        }

        await destroyPendingLogin(env, pending.pendingToken);
        const token = await createSession(env, pending.user_id);
        return redirect("/", {
          "Set-Cookie": [sessionCookie(token), clearPendingCookie()],
        });
      }

      // ---------- Public: self-service registration ----------
      // Public, but not open: an invite code is required, and the code -- not
      // the form -- decides the role. Someone posting role=founder here gets
      // whatever their code says, which is the whole point.
      if (path === "/register" && method === "GET") {
        const existing = await getSessionUser(request, env);
        if (existing) return redirect("/");
        return html(views.registerPage({ theme }));
      }

      if (path === "/register" && method === "POST") {
        const ip = clientIp(request);
        // Codes are 75 bits, but rate limiting the endpoint stops anyone
        // grinding at it and keeps the attempt in the same audit trail as
        // failed logins.
        const rlKey = "register";
        const limit = await checkRateLimit(env, rlKey, ip);
        if (limit.blocked) {
          return html(views.registerPage({ theme, error: limit.reason }), 429);
        }

        const f = await readForm(request);
        const name = (f.name || "").trim();
        const email = (f.email || "").trim().toLowerCase();
        const password = f.password || "";
        const submitted = f.code || "";

        const reject = async (msg, status = 400, countsAsAttempt = true) => {
          if (countsAsAttempt) await recordLoginAttempt(env, rlKey, ip, false);
          return html(views.registerPage({ theme, error: msg, name, email }), status);
        };

        if (!name || !email || !password || !submitted) {
          return reject("Every field is required.", 400, false);
        }
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
          return reject("That doesn't look like a valid email address.", 400, false);
        }
        if (password.length < 8) {
          return reject("Password must be at least 8 characters.", 400, false);
        }
        if (password !== f.confirm) {
          return reject("Passwords don't match.", 400, false);
        }

        const invite = await db.findOpenInviteCode(env, await hashInviteCode(submitted));
        if (!invite) {
          // Deliberately vague: don't distinguish wrong / used / expired, or
          // this becomes an oracle for probing codes.
          return reject("That invite code isn't valid. Ask a founder for a new one.", 403);
        }

        if (await db.getUserByEmail(env, email)) {
          return reject(`${email} already has an account. Try signing in instead.`, 409, false);
        }

        // Freelancer codes carry the profile they belong to, so the account is
        // never created in the broken unlinked state.
        if (invite.role === "freelancer" && !invite.freelancer_id) {
          return reject("That code is misconfigured — ask a founder to issue a new one.", 400, false);
        }

        await db.createUser(env, {
          email,
          name,
          role: invite.role,
          freelancer_id: invite.freelancer_id,
          setup_token: null,
        });
        const created = await db.getUserByEmail(env, email);

        // Consume before issuing a session. If two requests race, the loser
        // gets nothing usable.
        if (!(await db.consumeInviteCode(env, invite.id, created.id))) {
          await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(created.id).run();
          return reject("That invite code was just used by someone else.", 409, false);
        }

        await setPassword(env, created.id, password);
        await recordLoginAttempt(env, rlKey, ip, true);
        await db.logAudit(env, created, "account_registered", "user", created.id, `${invite.role} via invite code`);

        const token = await createSession(env, created.id);
        return redirect("/", { "Set-Cookie": sessionCookie(token) });
      }

      // ---------- Public: first-time setup / invite ----------
      if (path.startsWith("/setup/") && method === "GET") {
        const token = path.split("/setup/")[1];
        const user = await env.DB.prepare("SELECT * FROM users WHERE setup_token = ?").bind(token).first();
        if (!user) return html(views.errorPage("This setup link is invalid or has already been used.", 404, theme), 404);
        return html(views.setupPage({ token, name: user.name, theme }));
      }

      if (path.startsWith("/setup/") && method === "POST") {
        const token = path.split("/setup/")[1];
        const user = await env.DB.prepare("SELECT * FROM users WHERE setup_token = ?").bind(token).first();
        if (!user) return html(views.errorPage("This setup link is invalid or has already been used.", 404, theme), 404);
        const { password, confirm } = await readForm(request);
        if (!password || password.length < 8) {
          return html(views.setupPage({ token, name: user.name, error: "Password must be at least 8 characters.", theme }), 400);
        }
        if (password !== confirm) {
          return html(views.setupPage({ token, name: user.name, error: "Passwords don't match.", theme }), 400);
        }
        await setPassword(env, user.id, password);
        await db.logAudit(env, user, "account_activated", "user", user.id, null);
        const sessionToken = await createSession(env, user.id);
        return redirect("/", { "Set-Cookie": sessionCookie(sessionToken) });
      }

      if (path === "/logout") {
        const cookies = parseCookies(request);
        await destroySession(env, cookies["c7_session"]);
        return redirect("/login", { "Set-Cookie": clearCookie() });
      }

      // ---------- Everything below requires auth ----------
      const user = await getSessionUser(request, env);
      if (!user) return redirect("/login");
      const csrf = user.session_csrf;

      if (path === "/") {
        return redirect(user.role === "founder" ? "/dashboard" : "/log");
      }

      // ================= SECURITY / 2FA SELF-SERVICE (any role) =================
      if (path === "/security" && method === "GET") {
        const fresh = await env.DB.prepare("SELECT totp_secret, totp_enabled, google_sub FROM users WHERE id = ?")
          .bind(user.id)
          .first();
        const pendingSecret = !fresh.totp_enabled && fresh.totp_secret ? fresh.totp_secret : null;
        return html(
          views.securityPage({
            user: { ...user, totp_enabled: fresh.totp_enabled },
            csrf,
            theme,
            pendingSecret,
            pendingUri: pendingSecret ? totpUri(pendingSecret, user.email) : null,
            backupCodesLeft: await db.countUnusedBackupCodes(env, user.id),
            googleLinked: !!fresh.google_sub,
            googleEnabled: googleConfigured(env),
          })
        );
      }

      if (path === "/security/2fa/start" && method === "POST") {
        const f = await readForm(request);
        const fail = csrfGuard(user, f, theme);
        if (fail) return fail;
        const secret = generateTotpSecret();
        await env.DB.prepare("UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?").bind(secret, user.id).run();
        return redirect("/security");
      }

      if (path === "/security/2fa/confirm" && method === "POST") {
        const f = await readForm(request);
        const fail = csrfGuard(user, f, theme);
        if (fail) return fail;
        const fresh = await env.DB.prepare("SELECT totp_secret FROM users WHERE id = ?").bind(user.id).first();
        const ok = fresh.totp_secret && (await verifyTotp(fresh.totp_secret, f.code || ""));
        if (!ok) {
          return html(
            views.securityPage({
              user,
              csrf,
              theme,
              pendingSecret: fresh.totp_secret,
              pendingUri: totpUri(fresh.totp_secret, user.email),
              error: "That code didn't match. Try the current code from your app.",
            }),
            400
          );
        }
        await env.DB.prepare("UPDATE users SET totp_enabled = 1 WHERE id = ?").bind(user.id).run();
        await db.logAudit(env, user, "2fa_enabled", "user", user.id, null);

        // Issue recovery codes immediately: an authenticator enrolled without
        // them is one lost phone away from a manual D1 rescue.
        const codes = generateBackupCodes();
        await db.replaceBackupCodes(env, user.id, await Promise.all(codes.map(hashBackupCode)));
        await db.logAudit(env, user, "2fa_backup_codes_generated", "user", user.id, `${codes.length} codes`);

        return html(
          views.securityPage({
            user: { ...user, totp_enabled: 1 },
            csrf,
            theme,
            message: "Two-factor authentication is now enabled.",
            newBackupCodes: codes,
            backupCodesLeft: codes.length,
            googleEnabled: googleConfigured(env),
          })
        );
      }

      // Regenerating invalidates every previous code -- that's the point when
      // a printout goes missing.
      if (path === "/security/2fa/backup-codes" && method === "POST") {
        const f = await readForm(request);
        const fail = csrfGuard(user, f, theme);
        if (fail) return fail;
        const fresh = await env.DB.prepare("SELECT totp_enabled FROM users WHERE id = ?").bind(user.id).first();
        if (!fresh.totp_enabled) {
          return html(
            views.securityPage({
              user,
              csrf,
              theme,
              error: "Turn on two-factor authentication first — backup codes only apply to it.",
              backupCodesLeft: 0,
              googleEnabled: googleConfigured(env),
            }),
            400
          );
        }
        const codes = generateBackupCodes();
        await db.replaceBackupCodes(env, user.id, await Promise.all(codes.map(hashBackupCode)));
        await db.logAudit(env, user, "2fa_backup_codes_regenerated", "user", user.id, `${codes.length} codes`);
        return html(
          views.securityPage({
            user: { ...user, totp_enabled: 1 },
            csrf,
            theme,
            message: "New backup codes generated. Your previous codes no longer work.",
            newBackupCodes: codes,
            backupCodesLeft: codes.length,
            googleEnabled: googleConfigured(env),
          })
        );
      }

      if (path === "/security/2fa/disable" && method === "POST") {
        const f = await readForm(request);
        const fail = csrfGuard(user, f, theme);
        if (fail) return fail;
        await env.DB.prepare("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?").bind(user.id).run();
        // Codes are useless without the second factor they unlock, and leaving
        // them behind would silently re-arm on the next enable.
        await db.clearBackupCodes(env, user.id);
        await db.logAudit(env, user, "2fa_disabled", "user", user.id, null);
        return html(
          views.securityPage({
            user: { ...user, totp_enabled: 0 },
            csrf,
            theme,
            message: "Two-factor authentication disabled.",
            backupCodesLeft: 0,
            googleEnabled: googleConfigured(env),
          })
        );
      }

      // ================= FREELANCER ROUTES =================
      if (user.role === "freelancer") {
        const freelancer = await db.getFreelancerById(env, user.freelancer_id);
        if (!freelancer) return html(views.errorPage("Your account isn't linked to a freelancer profile. Ask a founder to fix this.", 400, theme), 400);

        if (path === "/log" && method === "GET") {
          const weekStart = isoWeekStart();
          const entry = await db.getWeeklyEntry(env, weekStart, freelancer.id);
          return html(views.logPage({ user, weekStart, entry, freelancer, csrf, theme }));
        }

        if (path === "/log" && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const weekStart = isoWeekStart();
          await db.upsertWeeklyEntry(env, {
            week_start: weekStart,
            freelancer_id: freelancer.id,
            hours: parseFloat(f.hours || "0"),
            deliverables: f.deliverables,
            status: f.status,
            notes: f.notes,
          });
          await db.logAudit(env, user, "weekly_log_submitted", "freelancer", freelancer.id, `${f.hours}h, week ${weekStart}`);
          return redirect("/log");
        }

        if (path === "/log/history" && method === "GET") {
          const rows = await db.getFreelancerHistory(env, freelancer.id);
          return html(views.historyPage({ user, rows, theme }));
        }

        return html(views.errorPage("Not found.", 404, theme), 404);
      }

      // ================= FOUNDER ROUTES =================
      if (user.role === "founder") {
        if (path === "/dashboard" && method === "GET") {
          const weekStart = isoWeekStart();
          const prevWeekStart = addDays(weekStart, -7);
          const data = await db.getDashboard(env, weekStart, prevWeekStart);
          return html(views.dashboardPage({ user, data, theme }));
        }

        // ---- Freelancers ----
        if (path === "/freelancers" && method === "GET") {
          const freelancers = await db.getFreelancers(env);
          return html(views.freelancersPage({ user, freelancers, inviteLink: null, csrf, theme }));
        }
        if (path === "/freelancers" && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          await db.createFreelancer(env, {
            name: f.name,
            email: f.email,
            role_title: f.role_title,
            rate_type: f.rate_type,
            rate_amount: f.rate_amount ? parseFloat(f.rate_amount) : null,
          });
          await db.logAudit(env, user, "freelancer_created", "freelancer", null, f.name);
          return redirect("/freelancers");
        }
        const inviteMatch = path.match(/^\/freelancers\/(\d+)\/invite$/);
        if (inviteMatch && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const id = inviteMatch[1];
          const freelancer = await db.getFreelancerById(env, id);
          if (!freelancer) return html(views.errorPage("Freelancer not found.", 404, theme), 404);
          const token = randomToken();
          const existingUser = await env.DB.prepare("SELECT * FROM users WHERE freelancer_id = ?").bind(id).first();
          if (existingUser) {
            await env.DB.prepare("UPDATE users SET setup_token = ?, password_hash = NULL, password_salt = NULL WHERE id = ?")
              .bind(token, existingUser.id)
              .run();
          } else {
            const email = freelancer.email || `freelancer${id}@placeholder.local`;
            await env.DB.prepare(
              "INSERT INTO users (email, name, role, freelancer_id, setup_token) VALUES (?, ?, 'freelancer', ?, ?)"
            )
              .bind(email, freelancer.name, id, token)
              .run();
          }
          await db.logAudit(env, user, "freelancer_invited", "freelancer", id, null);
          const freelancers = await db.getFreelancers(env);
          const link = `${url.origin}/setup/${token}`;
          return html(views.freelancersPage({ user, freelancers, inviteLink: link, csrf, theme }));
        }
        const toggleMatch = path.match(/^\/freelancers\/(\d+)\/toggle$/);
        if (toggleMatch && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const id = toggleMatch[1];
          const freelancer = await db.getFreelancerById(env, id);
          if (freelancer) {
            await db.setFreelancerActive(env, id, !freelancer.active);
            await db.logAudit(env, user, freelancer.active ? "freelancer_deactivated" : "freelancer_activated", "freelancer", id, null);
          }
          return redirect("/freelancers");
        }

        // ---- Clients ----
        if (path === "/clients" && method === "GET") {
          const clients = await db.getClients(env);
          return html(views.clientsPage({ user, clients, csrf, theme }));
        }
        if (path === "/clients" && method === "POST") {
          const c = await readForm(request);
          const fail = csrfGuard(user, c, theme);
          if (fail) return fail;
          await db.createClient(env, c);
          await db.logAudit(env, user, "client_created", "client", null, c.name);
          return redirect("/clients");
        }
        const clientToggle = path.match(/^\/clients\/(\d+)\/toggle$/);
        if (clientToggle && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const clients = await db.getClients(env);
          const client = clients.find((c) => String(c.id) === clientToggle[1]);
          if (client) {
            const newStatus = client.status === "active" ? "past" : "active";
            await db.setClientStatus(env, client.id, newStatus);
            await db.logAudit(env, user, "client_status_changed", "client", client.id, newStatus);
          }
          return redirect("/clients");
        }

        // ---- Leads ----
        if (path === "/leads" && method === "GET") {
          const leads = await db.getLeads(env);
          return html(views.leadsPage({ user, leads, csrf, theme }));
        }
        if (path === "/leads" && method === "POST") {
          const l = await readForm(request);
          const fail = csrfGuard(user, l, theme);
          if (fail) return fail;
          await db.createLead(env, { ...l, value_estimate: l.value_estimate ? parseFloat(l.value_estimate) : null });
          await db.logAudit(env, user, "lead_created", "lead", null, l.name);
          return redirect("/leads");
        }
        const stageMatch = path.match(/^\/leads\/(\d+)\/stage$/);
        if (stageMatch && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          await db.updateLeadStage(env, stageMatch[1], f.stage);
          await db.logAudit(env, user, "lead_stage_changed", "lead", stageMatch[1], f.stage);
          return redirect("/leads");
        }

        // ---- Revenue ----
        if (path === "/revenue" && method === "GET") {
          const [entries, clients] = await Promise.all([db.getRevenueEntries(env), db.getClients(env)]);
          return html(views.revenuePage({ user, entries, clients, csrf, theme }));
        }
        if (path === "/revenue" && method === "POST") {
          const r = await readForm(request);
          const fail = csrfGuard(user, r, theme);
          if (fail) return fail;
          await db.createRevenueEntry(env, {
            week_start: r.week_start,
            client_id: r.client_id || null,
            amount: parseFloat(r.amount || "0"),
            type: r.type,
            invoice_status: r.invoice_status,
          });
          await db.logAudit(env, user, "revenue_logged", "revenue", null, `${r.amount} (${r.type})`);
          return redirect("/revenue");
        }

        // ---- Team / user accounts (founders only) ----
        // Creating a login is the highest-privilege action in the app, so every
        // path through here is audited and the role is validated server-side
        // against a fixed list -- never taken from the form as-is.
        const teamPage = async (extra = {}) =>
          views.teamPage({
            user,
            csrf,
            theme,
            users: await db.listUsers(env),
            unlinkedFreelancers: await db.getFreelancersWithoutUser(env),
            inviteCodes: await db.listInviteCodes(env),
            registerUrl: `${url.origin}/register`,
            ...extra,
          });

        if (path === "/team" && method === "GET") {
          return html(await teamPage());
        }

        if (path === "/team" && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;

          const name = (f.name || "").trim();
          const email = (f.email || "").trim().toLowerCase();
          const role = f.role === "founder" ? "founder" : f.role === "freelancer" ? "freelancer" : null;

          if (!name || !email || !role) {
            return html(await teamPage({ error: "Name, email and role are all required." }), 400);
          }
          if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
            return html(await teamPage({ error: "That doesn't look like a valid email address." }), 400);
          }

          // A freelancer login without a freelancer profile can sign in but
          // lands on an error page, so require the link up front.
          let freelancerId = null;
          if (role === "freelancer") {
            const available = await db.getFreelancersWithoutUser(env);
            const chosen = available.find((x) => String(x.id) === String(f.freelancer_id));
            if (!chosen) {
              return html(
                await teamPage({
                  error: "Pick which freelancer profile this login belongs to. Add the profile on the Freelancers page first if it isn't listed.",
                }),
                400
              );
            }
            freelancerId = chosen.id;
          }

          const existing = await db.getUserByEmail(env, email);
          if (existing) {
            return html(await teamPage({ error: `${email} already has an account.` }), 409);
          }

          const token = randomToken();
          await db.createUser(env, { email, name, role, freelancer_id: freelancerId, setup_token: token });
          await db.logAudit(env, user, role === "founder" ? "founder_created" : "user_created", "user", null, `${name} <${email}>`);

          return html(
            await teamPage({
              message: `${name} added as ${role}. Send them the link below — it works once.`,
              inviteLink: `${url.origin}/setup/${token}`,
              inviteFor: name,
            })
          );
        }

        const teamInvite = path.match(/^\/team\/(\d+)\/invite$/);
        if (teamInvite && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const target = await db.getUserById(env, teamInvite[1]);
          if (!target) return html(views.errorPage("That account no longer exists.", 404, theme), 404);

          const token = randomToken();
          await db.reissueSetupToken(env, target.id, token);
          await db.logAudit(env, user, "invite_reissued", "user", target.id, `${target.name} <${target.email}>`);
          return html(
            await teamPage({
              message: `New link for ${target.name}. Any previous link or password for this account has stopped working.`,
              inviteLink: `${url.origin}/setup/${token}`,
              inviteFor: target.name,
            })
          );
        }

        // ---- Invite codes for self-service registration ----
        if (path === "/team/codes" && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;

          const role = f.role === "founder" ? "founder" : f.role === "freelancer" ? "freelancer" : null;
          if (!role) return html(await teamPage({ error: "Pick a role for the code." }), 400);

          let freelancerId = null;
          if (role === "freelancer") {
            const available = await db.getFreelancersWithoutUser(env);
            const chosen = available.find((x) => String(x.id) === String(f.freelancer_id));
            if (!chosen) {
              return html(
                await teamPage({ error: "A freelancer code has to name which freelancer profile it's for." }),
                400
              );
            }
            freelancerId = chosen.id;
          }

          const days = Math.min(Math.max(parseInt(f.expires_days || "7", 10) || 7, 1), 30);
          const code = generateInviteCode();
          await db.createInviteCode(env, {
            code_hash: await hashInviteCode(code),
            role,
            freelancer_id: freelancerId,
            note: (f.note || "").trim() || null,
            created_by: user.id,
            expires_at: new Date(Date.now() + days * 86400000).toISOString(),
          });
          await db.logAudit(env, user, "invite_code_created", "user", null, `${role}, expires in ${days}d${f.note ? " — " + f.note : ""}`);

          return html(
            await teamPage({
              message: `Invite code created. It works once, expires in ${days} day${days === 1 ? "" : "s"}, and creates a ${role} account.`,
              newCode: code,
            })
          );
        }

        const codeRevoke = path.match(/^\/team\/codes\/(\d+)\/revoke$/);
        if (codeRevoke && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const gone = await db.revokeInviteCode(env, codeRevoke[1]);
          await db.logAudit(env, user, "invite_code_revoked", "user", null, gone ? "revoked" : "already used or gone");
          return html(
            await teamPage({
              message: gone ? "That invite code has been cancelled." : "That code was already used or no longer exists.",
            })
          );
        }

        const teamRevoke = path.match(/^\/team\/(\d+)\/revoke$/);
        if (teamRevoke && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const target = await db.getUserById(env, teamRevoke[1]);
          if (!target) return html(views.errorPage("That account no longer exists.", 404, theme), 404);

          // Two lockout guards. Neither is theoretical: without them one
          // mis-click leaves nobody able to administer the system.
          if (target.id === user.id) {
            return html(await teamPage({ error: "You can't revoke your own access." }), 400);
          }
          // Only blocks when the target is itself a *working* founder login.
          // Revoking a founder who never activated removes nothing, and
          // blocking that would strand a sole founder who mistyped an invite.
          if (target.role === "founder" && target.password_hash && (await db.countActiveFounders(env)) <= 1) {
            return html(
              await teamPage({ error: "That's the last founder with a working login — revoking it would lock everyone out." }),
              400
            );
          }

          await db.revokeUserAccess(env, target.id);
          await db.logAudit(env, user, "access_revoked", "user", target.id, `${target.name} <${target.email}>`);
          return html(await teamPage({ message: `${target.name}'s access has been revoked and their sessions ended.` }));
        }

        // ---- Audit log ----
        if (path === "/audit" && method === "GET") {
          const rows = await db.getAuditLog(env);
          return html(views.auditPage({ user, rows, theme }));
        }

        // ---- Error log ----
        if (path === "/errors" && method === "GET") {
          const rows = await db.getErrorLog(env);
          return html(views.errorsPage({ user, rows, theme }));
        }

        // ---- Retention review ----
        if (path === "/retention" && method === "GET") {
          const flags = await db.getOpenRetentionFlags(env);
          return html(views.retentionPage({ user, flags, csrf, theme }));
        }
        const retentionMatch = path.match(/^\/retention\/(\d+)\/resolve$/);
        if (retentionMatch && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const flagId = retentionMatch[1];
          const flag = await env.DB.prepare("SELECT * FROM retention_flags WHERE id = ?").bind(flagId).first();
          if (flag && f.decision === "erase") {
            if (flag.entity_type === "lead") await db.eraseLeadPII(env, flag.entity_id);
            if (flag.entity_type === "freelancer") await db.eraseFreelancerPII(env, flag.entity_id);
            await db.resolveRetentionFlag(env, flagId, "erased");
            await db.logAudit(env, user, "retention_erased", flag.entity_type, flag.entity_id, null);
          } else if (flag) {
            await db.resolveRetentionFlag(env, flagId, "kept");
            await db.logAudit(env, user, "retention_kept", flag.entity_type, flag.entity_id, null);
          }
          return redirect("/retention");
        }

        return html(views.errorPage("Not found.", 404, theme), 404);
      }

      return html(views.errorPage("Not found.", 404, theme), 404);
    } catch (err) {
      await db.logError(env, path, err.stack || err.message || String(err));
      return html(views.errorPage("Something went wrong: " + err.message, 500, theme), 500);
    }
  },

  // Monthly Cron Trigger (see wrangler.toml [triggers]) -- flags stale
  // records for a human retention decision. Never deletes anything itself.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(db.runRetentionScan(env));
  },
};
