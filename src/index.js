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
} from "./auth.js";
import * as db from "./db.js";
import * as views from "./views.js";

// Set-Cookie cannot be safely comma-joined into a single header (cookie
// Expires values contain commas), so any extraHeaders["Set-Cookie"] may be
// a string or an array of strings -- each gets its own header line.
function buildHeaders(base, extraHeaders) {
  const headers = new Headers(base);
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

async function readForm(request) {
  const form = await request.formData();
  return Object.fromEntries(form.entries());
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
        return html(views.loginPage({ theme }));
      }

      if (path === "/login" && method === "POST") {
        const { email, password } = await readForm(request);
        const normalizedEmail = (email || "").trim().toLowerCase();
        const ip = clientIp(request);

        const limit = await checkRateLimit(env, normalizedEmail, ip);
        if (limit.blocked) {
          return html(views.loginPage({ error: limit.reason, theme }), 429);
        }

        const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(normalizedEmail).first();
        const ok = user && (await verifyPassword(env, user, password || ""));
        await recordLoginAttempt(env, normalizedEmail, ip, !!ok);

        if (!ok) {
          return html(views.loginPage({ error: "Incorrect email or password.", theme }), 401);
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
        const ok = await verifyTotp(pending.totp_secret, code || "");
        await recordLoginAttempt(env, rlKey, ip, ok);

        if (!ok) return html(views.totpVerifyPage({ error: "Incorrect code. Try again.", theme }), 401);

        await destroyPendingLogin(env, pending.pendingToken);
        const token = await createSession(env, pending.user_id);
        return redirect("/", {
          "Set-Cookie": [sessionCookie(token), clearPendingCookie()],
        });
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
        const fresh = await env.DB.prepare("SELECT totp_secret, totp_enabled FROM users WHERE id = ?").bind(user.id).first();
        const pendingSecret = !fresh.totp_enabled && fresh.totp_secret ? fresh.totp_secret : null;
        return html(
          views.securityPage({
            user: { ...user, totp_enabled: fresh.totp_enabled },
            csrf,
            theme,
            pendingSecret,
            pendingUri: pendingSecret ? totpUri(pendingSecret, user.email) : null,
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
        return html(views.securityPage({ user: { ...user, totp_enabled: 1 }, csrf, theme, message: "Two-factor authentication is now enabled." }));
      }

      if (path === "/security/2fa/disable" && method === "POST") {
        const f = await readForm(request);
        const fail = csrfGuard(user, f, theme);
        if (fail) return fail;
        await env.DB.prepare("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?").bind(user.id).run();
        await db.logAudit(env, user, "2fa_disabled", "user", user.id, null);
        return html(views.securityPage({ user: { ...user, totp_enabled: 0 }, csrf, theme, message: "Two-factor authentication disabled." }));
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
