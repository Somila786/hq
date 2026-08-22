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
  MCP_SCOPE,
  MCP_PROTOCOL_VERSION,
  MCP_SUPPORTED_VERSIONS,
  mcpTokenTtl,
  hashOpaque,
  verifyPkceS256,
  authorizationServerMetadata,
  protectedResourceMetadata,
  wwwAuthenticateHeader,
  redirectUriAllowed,
  makeWebhookConfigured,
  verifyWebhookSignature,
  timestampWithinWindow,
  outreachSendingConfigured,
  callWindowHours,
  buildOutreachPayload,
  triggerOutreach,
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
  "'sha256-VPh6EmarFUR3eK8XxEE0qg1TypUlc8+8kzWciOQ26M0='", // outreach send confirm()
  // THEME_SCRIPT in views.js -- a real <script> block, so this hash alone
  // authorises it; it does not depend on 'unsafe-hashes'.
  "'sha256-HL1QaYdiRLv5+16Djw9KPpJ60rNx9rKFZ0S5NRqVCA0='",
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

// Idempotency for HTML forms. Post/Redirect/Get already stops a refresh from
// resubmitting; this stops the other case -- an impatient double-click firing
// two requests before the first redirect lands, which would otherwise create
// two revenue rows or two leads.
//
// Returns true if this submission is the first to claim its nonce. A repeat
// gets `false` and the caller redirects as though it had succeeded, because
// from the user's point of view it did.
async function claimOnce(env, form) {
  return db.claimSubmission(env, form._nonce);
}

// Only a same-origin *path* is ever accepted as a post-login destination.
// A full URL, or anything starting "//", would make /login an open redirector
// that phishing could point at another site.
function safeNext(raw) {
  if (typeof raw !== "string" || !raw.startsWith("/") || raw.startsWith("//")) return null;
  return raw;
}

function json(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: buildHeaders({ "Content-Type": "application/json" }, extraHeaders),
  });
}

// ---- MCP tool surface (read-only) ----
//
// Every tool runs with the HQ user the token was issued for, and reuses the
// same role rules as the web UI: a founder sees the business, a freelancer
// sees only their own log. Nothing here writes.
const MCP_TOOLS = [
  {
    name: "get_week_summary",
    description:
      "This week's Catalyst 7 numbers: freelancer hours, revenue, open pipeline value, deals won, active clients, and who has not submitted their weekly log yet. Compares against last week. Founders only.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "list_leads",
    description:
      "The sales pipeline: every lead with its stage, owner and estimated value. Won and lost leads sort last. Founders only.",
    inputSchema: {
      type: "object",
      properties: {
        stage: {
          type: "string",
          enum: ["new", "contacted", "qualified", "proposal", "won", "lost"],
          description: "Optional: return only leads at this stage.",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_clients",
    description: "Client roster with status (active or past), contact name and how they were acquired. Founders only.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "list_revenue",
    description:
      "Recent revenue entries: week, client, type and amount in rand, plus invoice status. Newest first. Founders only.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "integer", minimum: 1, maximum: 100, description: "How many entries to return. Default 20." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "list_freelancers",
    description: "The freelancer roster with role, rate and whether they are currently active. Founders only.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "get_my_weekly_log",
    description:
      "Your own weekly log history — hours, deliverables and status for recent weeks. Works for any signed-in user; a freelancer sees only their own entries.",
    inputSchema: {
      type: "object",
      properties: {
        weeks: { type: "integer", minimum: 1, maximum: 52, description: "How many weeks back. Default 12." },
      },
      additionalProperties: false,
    },
  },
];

const FOUNDER_ONLY = new Set(["get_week_summary", "list_leads", "list_clients", "list_revenue", "list_freelancers"]);

const money = (n) => "R" + Number(n || 0).toLocaleString("en-ZA", { maximumFractionDigits: 0 });

async function runMcpTool(name, args, { env, user }) {
  if (FOUNDER_ONLY.has(name) && user.role !== "founder") {
    // Same rule as the web UI, enforced server-side rather than by hiding the
    // tool: a freelancer's token cannot read business data.
    return `That information is only available to founders. You're signed in as ${user.name} (freelancer).`;
  }

  if (name === "get_week_summary") {
    const weekStart = isoWeekStart();
    const d = await db.getDashboard(env, weekStart, addDays(weekStart, -7));
    const missing = d.missingFreelancers.map((f) => f.name);
    return [
      `Week of ${d.weekStart} (compared with ${d.prevWeekStart})`,
      ``,
      `Freelancer hours: ${Number(d.hoursThis).toFixed(1)} (last week ${Number(d.hoursPrev).toFixed(1)})`,
      `Revenue: ${money(d.revThis)} (last week ${money(d.revPrev)})`,
      `Open pipeline: ${money(d.pipelineValue)} across ${d.leadsByStage.reduce((n, s) => n + s.n, 0)} leads`,
      `New leads this week: ${d.newLeads}`,
      `Deals won this week: ${d.wonThis.n} worth ${money(d.wonThis.val)}`,
      `Active clients: ${d.activeClients} (${d.newClients} new this week)`,
      `Weekly logs submitted: ${d.submittedCount} of ${d.activeFreelancerCount}`,
      missing.length ? `Not yet logged: ${missing.join(", ")}` : `Everyone has logged this week.`,
    ].join("\n");
  }

  if (name === "list_leads") {
    let leads = await db.getLeads(env);
    if (args.stage) leads = leads.filter((l) => l.stage === args.stage);
    if (!leads.length) return args.stage ? `No leads at stage "${args.stage}".` : "No leads yet.";
    return leads
      .map(
        (l) =>
          `${l.name}${l.company ? ` (${l.company})` : ""} — ${l.stage}` +
          `${l.value_estimate ? `, ${money(l.value_estimate)}` : ""}${l.owner ? `, owner ${l.owner}` : ""}`
      )
      .join("\n");
  }

  if (name === "list_clients") {
    const clients = await db.getClients(env);
    if (!clients.length) return "No clients yet.";
    return clients
      .map((c) => `${c.name} — ${c.status}${c.contact_name ? `, contact ${c.contact_name}` : ""}${c.source ? `, via ${c.source}` : ""}`)
      .join("\n");
  }

  if (name === "list_revenue") {
    const rows = await db.getRevenueEntries(env, Math.min(Math.max(args.limit || 20, 1), 100));
    if (!rows.length) return "No revenue logged yet.";
    return rows
      .map((r) => `${r.week_start} — ${r.client_name || "no client"} — ${r.type} — ${money(r.amount)} (${r.invoice_status})`)
      .join("\n");
  }

  if (name === "list_freelancers") {
    const rows = await db.getFreelancers(env);
    if (!rows.length) return "No freelancers on the roster yet.";
    return rows
      .map(
        (f) =>
          `${f.name}${f.role_title ? ` — ${f.role_title}` : ""} — ${f.rate_type}` +
          `${f.rate_amount ? ` ${money(f.rate_amount)}` : ""} — ${f.active ? "active" : "inactive"}`
      )
      .join("\n");
  }

  if (name === "get_my_weekly_log") {
    if (!user.freelancer_id) {
      return `${user.name} isn't linked to a freelancer profile, so there's no weekly log to read. Founders track the team's logs with get_week_summary.`;
    }
    const rows = await db.getFreelancerHistory(env, user.freelancer_id, Math.min(Math.max(args.weeks || 12, 1), 52));
    if (!rows.length) return "No weekly entries logged yet.";
    return rows
      .map((r) => `${r.week_start} — ${r.hours}h — ${r.status}${r.deliverables ? ` — ${r.deliverables}` : ""}`)
      .join("\n");
  }

  return `Unknown tool: ${name}`;
}

// JSON-RPC dispatch. Notifications get 202 with no body; requests get a single
// JSON object. No SSE: every tool here answers in milliseconds, so streaming
// would add machinery for nothing.
async function handleMcp(rpc, ctx) {
  const reply = (result) => json({ jsonrpc: "2.0", id: rpc.id, result });
  const fail = (code, message, status = 200) => json({ jsonrpc: "2.0", id: rpc.id ?? null, error: { code, message } }, status);

  if (!rpc || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") {
    return fail(-32600, "Invalid Request", 400);
  }

  // A notification has no id and expects no response body.
  if (rpc.id === undefined || rpc.id === null) {
    return new Response(null, { status: 202, headers: buildHeaders({}, {}) });
  }

  switch (rpc.method) {
    case "initialize": {
      const asked = rpc.params?.protocolVersion;
      return reply({
        protocolVersion: MCP_SUPPORTED_VERSIONS.includes(asked) ? asked : MCP_PROTOCOL_VERSION,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: "Catalyst 7 HQ", version: "1.0.0" },
        instructions:
          "Catalyst 7 HQ tracks the studio's weekly numbers: freelancer hours, revenue, clients and sales pipeline. " +
          "All tools are read-only. Money is in South African rand. Weeks run Monday to Sunday (UTC).",
      });
    }
    case "ping":
      return reply({});
    case "tools/list":
      return reply({ tools: MCP_TOOLS });
    case "resources/list":
      return reply({ resources: [] });
    case "prompts/list":
      return reply({ prompts: [] });
    case "tools/call": {
      const name = rpc.params?.name;
      const tool = MCP_TOOLS.find((t) => t.name === name);
      if (!tool) return fail(-32602, `Unknown tool: ${name}`);
      try {
        const text = await runMcpTool(name, rpc.params?.arguments || {}, ctx);
        // Cap well under Claude's ~150k character ceiling.
        const capped = text.length > 100000 ? text.slice(0, 100000) + "\n…(truncated)" : text;
        return reply({ content: [{ type: "text", text: capped }], isError: false });
      } catch (err) {
        await db.logError(ctx.env, "/mcp:" + name, err.stack || err.message || String(err));
        // Tool failures are results, not protocol errors -- the model should
        // see them and can explain or retry.
        return reply({ content: [{ type: "text", text: `That lookup failed: ${err.message}` }], isError: true });
      }
    }
    default:
      return fail(-32601, `Method not found: ${rpc.method}`, 404);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const theme = parseCookies(request)["c7_theme"] === "light" ? "light" : "dark";
    // Captured once so every audit entry can record where the action came
    // from, per the C7 standard's audit field list.
    const reqIp = clientIp(request);

    try {
      // ---------- Inbound webhook from Make (C7 webhook standard) ----------
      // Public by necessity -- Make posts from its own infrastructure. All
      // authenticity comes from the HMAC over the raw body. Dormant until
      // MAKE_WEBHOOK_SECRET is set, exactly like Google sign-in.
      if (path === "/webhooks/make" && method === "POST") {
        if (!makeWebhookConfigured(env)) {
          return json({ success: false, message: "Webhook not configured." }, 404);
        }

        // Read the body ONCE as text and verify against those exact bytes.
        // Re-serialising parsed JSON reorders keys and breaks every signature.
        const raw = await request.text();
        const signature = request.headers.get("X-Signature-256") || request.headers.get("x-signature-256");
        if (!(await verifyWebhookSignature(env.MAKE_WEBHOOK_SECRET, raw, signature))) {
          await db.logAudit(env, null, "webhook_rejected", "outreach", null, "bad or missing signature", reqIp, "failure");
          return json({ success: false, message: "Invalid signature." }, 401);
        }

        let payload;
        try {
          payload = JSON.parse(raw);
        } catch {
          return json({ success: false, message: "Body must be JSON." }, 400);
        }

        // C7 envelope: { event_id, timestamp, source, form_name, data }
        const eventId = payload.event_id;
        const timestamp = payload.timestamp;
        const data = payload.data || {};
        if (!eventId || typeof eventId !== "string") {
          return json({ success: false, message: "event_id is required." }, 400);
        }
        // A valid signature proves authenticity, not freshness. event_id
        // uniqueness stops duplicates; this stops an old capture being replayed.
        if (!timestampWithinWindow(timestamp)) {
          return json({ success: false, message: "timestamp missing, malformed, or outside the accepted window." }, 400);
        }

        const kindRaw = String(data.kind || payload.form_name || "").toLowerCase();
        const kind = ["sent", "reply", "bounce", "failed"].includes(kindRaw) ? kindRaw : null;
        if (!kind) {
          return json(
            { success: false, message: "data.kind must be one of: sent, reply, bounce, failed." },
            400
          );
        }

        const email = typeof data.email === "string" ? data.email.trim().toLowerCase() : null;
        const lead = await db.findLeadByEmail(env, email);

        const stored = await db.recordOutreachEvent(env, {
          event_id: eventId,
          lead_id: lead ? lead.id : null,
          lead_email: email,
          kind,
          sequence: typeof data.sequence === "string" ? data.sequence.slice(0, 120) : null,
          step: data.step === undefined || data.step === null ? null : String(data.step).slice(0, 60),
          subject: typeof data.subject === "string" ? data.subject.slice(0, 300) : null,
          detail: typeof data.detail === "string" ? data.detail.slice(0, 1000) : null,
          occurred_at: new Date(timestamp).toISOString(),
          source: typeof payload.source === "string" ? payload.source.slice(0, 80) : null,
        });

        // An email actually went out, so the Sequence B call window opens --
        // whoever pressed send. Only on a first delivery: replaying a stored
        // event must not reset a window or discard a call already logged.
        if (stored && lead && kind === "sent") {
          const opened = await db.openCallWindowFromEvent(
            env,
            lead.id,
            new Date(timestamp).toISOString(),
            callWindowHours(env)
          );
          if (opened) {
            await db.logAudit(env, null, "call_window_opened", "lead", lead.id, lead.name, reqIp);
          }
        }

        // A duplicate is a success from Make's point of view -- returning an
        // error would make it retry forever.
        return json({
          success: true,
          message: stored ? "Payload received" : "Payload received (already recorded)",
          matched_lead: lead ? lead.id : null,
        });
      }

      // ================= MCP CONNECTOR =================
      // Everything Claude touches lives here: discovery, the OAuth endpoints,
      // and the JSON-RPC endpoint itself. Placed above the browser routes
      // because none of it uses cookies -- it authenticates with a bearer
      // token, and the discovery documents are deliberately public.

      // RFC 9728. Claude probes the path-suffixed form first, then the bare
      // one; serve both so either probe succeeds.
      if (
        path === "/.well-known/oauth-protected-resource" ||
        path === "/.well-known/oauth-protected-resource/mcp"
      ) {
        return json(protectedResourceMetadata(url.origin));
      }

      // RFC 8414. The OIDC path is included because some clients look there.
      if (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/openid-configuration") {
        return json(authorizationServerMetadata(url.origin));
      }

      // RFC 7591 dynamic client registration. Open by design: registration
      // creates no access on its own, and nothing is issued until a real HQ
      // user signs in and consents at /oauth/authorize.
      if (path === "/oauth/register" && method === "POST") {
        let body;
        try {
          body = await request.json();
        } catch {
          return json({ error: "invalid_client_metadata", error_description: "Body must be JSON." }, 400);
        }
        const uris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter((u) => typeof u === "string") : [];
        if (!uris.length) {
          return json({ error: "invalid_redirect_uri", error_description: "redirect_uris is required." }, 400);
        }
        for (const u of uris) {
          let parsed;
          try {
            parsed = new URL(u);
          } catch {
            return json({ error: "invalid_redirect_uri", error_description: `Not a URL: ${u}` }, 400);
          }
          const loopback = ["localhost", "127.0.0.1", "[::1]", "::1"].includes(parsed.hostname);
          if (parsed.protocol !== "https:" && !loopback) {
            return json(
              { error: "invalid_redirect_uri", error_description: "Redirect URIs must be https, or loopback for native clients." },
              400
            );
          }
        }
        const clientId = randomUrlSafe(24);
        await db.registerOAuthClient(env, {
          clientId,
          clientName: typeof body.client_name === "string" ? body.client_name.slice(0, 120) : null,
          redirectUris: uris,
        });
        return json(
          {
            client_id: clientId,
            client_name: body.client_name || null,
            redirect_uris: uris,
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
            // Public client: PKCE, not a secret, is what protects the code.
            token_endpoint_auth_method: "none",
            client_id_issued_at: Math.floor(Date.now() / 1000),
          },
          201
        );
      }

      // Consent screen. Reuses the ordinary HQ session, so whoever is signed
      // in here is exactly who the token gets bound to -- including having
      // passed 2FA.
      if (path === "/oauth/authorize" && (method === "GET" || method === "POST")) {
        const q = url.searchParams;
        const clientId = q.get("client_id") || "";
        const redirectUri = q.get("redirect_uri") || "";
        const state = q.get("state") || "";
        const challenge = q.get("code_challenge") || "";
        const challengeMethod = q.get("code_challenge_method") || "";
        const requestedScope = q.get("scope") || MCP_SCOPE;

        const client = await db.getOAuthClient(env, clientId);
        // Errors before the redirect_uri is validated must NOT redirect --
        // bouncing to an unverified URI would make this an open redirector.
        if (!client) {
          return html(views.errorPage("Unknown OAuth client. Try removing and re-adding the connector.", 400, theme), 400);
        }
        if (!redirectUriAllowed(client.redirect_uris, redirectUri)) {
          return html(views.errorPage("That redirect URI isn't registered for this connector.", 400, theme), 400);
        }

        const bounce = (params) => {
          const dest = new URL(redirectUri);
          for (const [k, v] of Object.entries(params)) dest.searchParams.set(k, v);
          if (state) dest.searchParams.set("state", state);
          return redirect(dest.toString());
        };

        if (q.get("response_type") !== "code") return bounce({ error: "unsupported_response_type" });
        // S256 only. `plain` is not accepted and Claude never sends it.
        if (challengeMethod !== "S256" || !challenge) {
          return bounce({ error: "invalid_request", error_description: "S256 PKCE is required" });
        }

        const consentUser = await getSessionUser(request, env);
        if (!consentUser) {
          // Sign in first, then come back to this exact authorize URL.
          return redirect(`/login?next=${encodeURIComponent(path + url.search)}`);
        }

        if (method === "GET") {
          return html(
            views.consentPage({
              user: consentUser,
              theme,
              csrf: consentUser.session_csrf,
              clientName: client.client_name,
              scope: requestedScope,
              query: url.search,
            })
          );
        }

        // POST = the user pressed Allow.
        const f = await readForm(request);
        const fail = csrfGuard(consentUser, f, theme);
        if (fail) return fail;
        if (f.decision !== "allow") return bounce({ error: "access_denied" });

        const code = randomUrlSafe(32);
        const ttl = mcpTokenTtl();
        await db.createAuthCode(env, {
          code_hash: await hashOpaque(code),
          client_id: clientId,
          user_id: consentUser.id,
          redirect_uri: redirectUri,
          code_challenge: challenge,
          scope: MCP_SCOPE,
          expires_at: new Date(Date.now() + ttl.code * 1000).toISOString(),
        });
        await db.logAudit(env, consentUser, "mcp_access_granted", "user", consentUser.id, client.client_name || clientId, reqIp);
        return bounce({ code });
      }

      // RFC 6749 token endpoint. Must accept form-urlencoded.
      if (path === "/oauth/token" && method === "POST") {
        const f = await readForm(request);
        const grant = f.grant_type;
        const ttl = mcpTokenTtl();

        const issue = async ({ clientId, userId, scope }) => {
          const access = randomUrlSafe(32);
          const refresh = randomUrlSafe(32);
          await db.storeMcpToken(env, {
            token_hash: await hashOpaque(access),
            kind: "access",
            client_id: clientId,
            user_id: userId,
            scope,
            expires_at: new Date(Date.now() + ttl.access * 1000).toISOString(),
          });
          await db.storeMcpToken(env, {
            token_hash: await hashOpaque(refresh),
            kind: "refresh",
            client_id: clientId,
            user_id: userId,
            scope,
            expires_at: new Date(Date.now() + ttl.refresh * 1000).toISOString(),
          });
          return json({
            access_token: access,
            token_type: "Bearer",
            expires_in: ttl.access,
            refresh_token: refresh,
            scope,
          });
        };

        if (grant === "authorization_code") {
          const row = await db.consumeAuthCode(env, await hashOpaque(f.code || ""));
          if (!row) return json({ error: "invalid_grant", error_description: "Code is unknown, expired or already used." }, 400);
          if (row.client_id !== f.client_id) return json({ error: "invalid_grant", error_description: "Client mismatch." }, 400);
          if (row.redirect_uri !== f.redirect_uri) return json({ error: "invalid_grant", error_description: "redirect_uri mismatch." }, 400);
          if (!(await verifyPkceS256(f.code_verifier || "", row.code_challenge))) {
            return json({ error: "invalid_grant", error_description: "PKCE verification failed." }, 400);
          }
          return issue({ clientId: row.client_id, userId: row.user_id, scope: row.scope });
        }

        if (grant === "refresh_token") {
          // Rotating: consuming deletes the old token, so a stolen copy dies
          // the moment the real client refreshes.
          const row = await db.consumeRefreshToken(env, await hashOpaque(f.refresh_token || ""));
          // RFC 6749 code exactly -- Claude keys its retry behaviour off this.
          if (!row) return json({ error: "invalid_grant", error_description: "Refresh token is no longer valid." }, 400);
          return issue({ clientId: row.client_id, userId: row.user_id, scope: row.scope });
        }

        return json({ error: "unsupported_grant_type" }, 400);
      }

      // Human-readable page describing the connector, linked from the
      // discovery documents.
      if (path === "/mcp/about") {
        return html(views.mcpAboutPage({ theme, origin: url.origin }));
      }

      // ---------- The MCP endpoint ----------
      if (path === "/mcp") {
        // This revision offers no standalone SSE stream and no sessions.
        if (method === "GET" || method === "DELETE") {
          return new Response(null, { status: 405, headers: buildHeaders({ Allow: "POST" }, {}) });
        }
        if (method !== "POST") return new Response(null, { status: 405 });

        // DNS-rebinding guard: a browser-originated request carries Origin.
        // Claude's server-side calls carry none, which is what we expect.
        const origin = request.headers.get("Origin");
        if (origin && origin !== url.origin) {
          return json({ jsonrpc: "2.0", error: { code: -32600, message: "Origin not allowed" } }, 403);
        }

        const auth = request.headers.get("Authorization") || "";
        const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : null;
        // The 401 + WWW-Authenticate pair is what starts Claude's OAuth flow.
        // A WWW-Authenticate on a 200 is ignored, so the status matters.
        if (!bearer) {
          return json({ jsonrpc: "2.0", error: { code: -32001, message: "Authentication required" } }, 401, {
            "WWW-Authenticate": wwwAuthenticateHeader(url.origin),
          });
        }
        const tokenUser = await db.getMcpTokenUser(env, await hashOpaque(bearer));
        if (!tokenUser) {
          return json({ jsonrpc: "2.0", error: { code: -32001, message: "Token invalid or expired" } }, 401, {
            "WWW-Authenticate": wwwAuthenticateHeader(url.origin, "invalid_token"),
          });
        }

        let rpc;
        try {
          rpc = await request.json();
        } catch {
          return json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }, 400);
        }

        return handleMcp(rpc, { env, user: tokenUser, origin: url.origin, ip: reqIp });
      }

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
        return html(views.loginPage({ theme, googleEnabled: googleConfigured(env), next: safeNext(url.searchParams.get("next")) }));
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
          await db.logAudit(env, null, "login_google_denied", "user", null, email, reqIp);
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
          await db.logAudit(env, user, "login_google_sub_mismatch", "user", user.id, email, reqIp);
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
          await db.logAudit(env, user, "google_account_linked", "user", user.id, email, reqIp);
        }

        await recordLoginAttempt(env, email, ip, true);

        // A federated login doesn't excuse 2FA the user explicitly turned on.
        if (user.totp_enabled) {
          const pendingToken = await createPendingLogin(env, user.id);
          return redirect("/login/2fa", { "Set-Cookie": pendingCookie(pendingToken) });
        }

        await db.logAudit(env, user, "login_google", "user", user.id, null, reqIp);
        const token = await createSession(env, user.id);
        return redirect("/", { "Set-Cookie": sessionCookie(token) });
      }

      if (path === "/login" && method === "POST") {
        const f = await readForm(request);
        const { email, password } = f;
        const normalizedEmail = (email || "").trim().toLowerCase();
        const ip = clientIp(request);

        const limit = await checkRateLimit(env, normalizedEmail, ip);
        if (limit.blocked) {
          return html(views.loginPage({ error: limit.reason, theme, googleEnabled: googleConfigured(env) }), 429);
        }

        const user = await db.getUserCredentials(env, normalizedEmail);
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
          const nx = safeNext(f.next);
          return redirect(nx ? `/login/2fa?next=${encodeURIComponent(nx)}` : "/login/2fa", {
            "Set-Cookie": pendingCookie(pendingToken),
          });
        }

        const token = await createSession(env, user.id);
        return redirect(safeNext(f.next) || "/", { "Set-Cookie": sessionCookie(token) });
      }

      // ---------- Public: 2FA verification step ----------
      if (path === "/login/2fa" && method === "GET") {
        const pending = await getPendingLogin(request, env);
        if (!pending) return redirect("/login");
        return html(views.totpVerifyPage({ theme, next: safeNext(url.searchParams.get("next")) }));
      }

      if (path === "/login/2fa" && method === "POST") {
        const pending = await getPendingLogin(request, env);
        if (!pending) return redirect("/login");

        const ip = clientIp(request);
        const rlKey = "2fa:" + pending.email;
        const limit = await checkRateLimit(env, rlKey, ip);
        if (limit.blocked) return html(views.totpVerifyPage({ error: limit.reason, theme }), 429);

        const f = await readForm(request);
        const { code } = f;

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
        return redirect(safeNext(f.next) || safeNext(url.searchParams.get("next")) || "/", {
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
          // Like the role, the title comes from the code a founder issued,
          // not from anything the person registering typed.
          title: invite.title,
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
        await db.logAudit(env, created, "account_registered", "user", created.id, `${invite.role} via invite code`, reqIp);

        const token = await createSession(env, created.id);
        return redirect("/", { "Set-Cookie": sessionCookie(token) });
      }

      // ---------- Public: first-time setup / invite ----------
      if (path.startsWith("/setup/") && method === "GET") {
        const token = path.split("/setup/")[1];
        const user = await env.DB.prepare(
          "SELECT id, email, name, role FROM users WHERE setup_token = ?"
        ).bind(token).first();
        if (!user) return html(views.errorPage("This setup link is invalid or has already been used.", 404, theme), 404);
        return html(views.setupPage({ token, name: user.name, theme }));
      }

      if (path.startsWith("/setup/") && method === "POST") {
        const token = path.split("/setup/")[1];
        const user = await env.DB.prepare(
          "SELECT id, email, name, role FROM users WHERE setup_token = ?"
        ).bind(token).first();
        if (!user) return html(views.errorPage("This setup link is invalid or has already been used.", 404, theme), 404);
        const { password, confirm } = await readForm(request);
        if (!password || password.length < 8) {
          return html(views.setupPage({ token, name: user.name, error: "Password must be at least 8 characters.", theme }), 400);
        }
        if (password !== confirm) {
          return html(views.setupPage({ token, name: user.name, error: "Passwords don't match.", theme }), 400);
        }
        await setPassword(env, user.id, password);
        await db.logAudit(env, user, "account_activated", "user", user.id, null, reqIp);
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
            mcpGrants: await db.listMcpGrants(env, user.id),
            mcpUrl: `${url.origin}/mcp`,
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
        await db.logAudit(env, user, "2fa_enabled", "user", user.id, null, reqIp);

        // Issue recovery codes immediately: an authenticator enrolled without
        // them is one lost phone away from a manual D1 rescue.
        const codes = generateBackupCodes();
        await db.replaceBackupCodes(env, user.id, await Promise.all(codes.map(hashBackupCode)));
        await db.logAudit(env, user, "2fa_backup_codes_generated", "user", user.id, `${codes.length} codes`, reqIp);

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
        await db.logAudit(env, user, "2fa_backup_codes_regenerated", "user", user.id, `${codes.length} codes`, reqIp);
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

      // Withdraw a connector's access. Deletes its tokens outright, so the
      // next request Claude makes gets a 401 and the connection is dead.
      if (path === "/security/connectors/revoke" && method === "POST") {
        const f = await readForm(request);
        const fail = csrfGuard(user, f, theme);
        if (fail) return fail;
        const removed = await db.revokeMcpGrant(env, user.id, f.client_id || "");
        await db.logAudit(env, user, "mcp_access_revoked", "user", user.id, `${removed} token(s)`, reqIp);
        return html(
          await (async () =>
            views.securityPage({
              user,
              csrf,
              theme,
              message: removed ? "Connector access withdrawn. It can no longer read your data." : "That connector was already disconnected.",
              backupCodesLeft: await db.countUnusedBackupCodes(env, user.id),
              googleEnabled: googleConfigured(env),
              mcpGrants: await db.listMcpGrants(env, user.id),
              mcpUrl: `${url.origin}/mcp`,
            }))()
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
        await db.logAudit(env, user, "2fa_disabled", "user", user.id, null, reqIp);
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
          await db.logAudit(env, user, "weekly_log_submitted", "freelancer", freelancer.id, `${f.hours}h, week ${weekStart}`, reqIp);
          return redirect("/log");
        }

        if (path === "/log/history" && method === "GET") {
          const rows = await db.getFreelancerHistory(env, freelancer.id);
          return html(views.historyPage({ user, rows, theme }));
        }

        return html(views.restrictedPage({ user, theme }), 404);
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
          if (!(await claimOnce(env, f))) return redirect("/freelancers");
          await db.createFreelancer(env, {
            name: f.name,
            email: f.email,
            role_title: f.role_title,
            rate_type: f.rate_type,
            rate_amount: f.rate_amount ? parseFloat(f.rate_amount) : null,
          });
          await db.logAudit(env, user, "freelancer_created", "freelancer", null, f.name, reqIp);
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
          const existingUser = await env.DB.prepare(
            "SELECT id FROM users WHERE freelancer_id = ?"
          ).bind(id).first();
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
          await db.logAudit(env, user, "freelancer_invited", "freelancer", id, null, reqIp);
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
            await db.logAudit(env, user, freelancer.active ? "freelancer_deactivated" : "freelancer_activated", "freelancer", id, null, reqIp);
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
          if (!(await claimOnce(env, c))) return redirect("/clients");
          await db.createClient(env, c);
          await db.logAudit(env, user, "client_created", "client", null, c.name, reqIp);
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
            await db.logAudit(env, user, "client_status_changed", "client", client.id, newStatus, reqIp);
          }
          return redirect("/clients");
        }

        // ---- Leads ----
        if (path === "/leads" && method === "GET") {
          const [leads, outreach] = await Promise.all([db.getLeads(env), db.getOutreachSummary(env)]);
          return html(views.leadsPage({ user, leads, csrf, theme, outreach }));
        }

        // Single lead + its outreach timeline. Placed before the /leads/:id/stage
        // matcher so the bare id doesn't fall through to it.
        const leadDetail = path.match(/^\/leads\/(\d+)$/);
        if (leadDetail && method === "GET") {
          const lead = await db.getLeadById(env, leadDetail[1]);
          if (!lead) return html(views.errorPage("That lead no longer exists.", 404, theme), 404);
          return html(
            views.leadDetailPage({
              user,
              lead,
              events: await db.getOutreachForLead(env, lead.id),
              theme,
              csrf,
              webhookReady: makeWebhookConfigured(env),
              sendingReady: outreachSendingConfigured(env),
            })
          );
        }
        if (path === "/leads" && method === "POST") {
          const l = await readForm(request);
          const fail = csrfGuard(user, l, theme);
          if (fail) return fail;
          if (!(await claimOnce(env, l))) return redirect("/leads");
          await db.createLead(env, { ...l, value_estimate: l.value_estimate ? parseFloat(l.value_estimate) : null });
          await db.logAudit(env, user, "lead_created", "lead", null, l.name, reqIp);
          return redirect("/leads");
        }
        const stageMatch = path.match(/^\/leads\/(\d+)\/stage$/);
        if (stageMatch && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          await db.updateLeadStage(env, stageMatch[1], f.stage);
          await db.logAudit(env, user, "lead_stage_changed", "lead", stageMatch[1], f.stage, reqIp);
          return redirect("/leads");
        }

        // ---- Outreach approval gate ----
        // Nothing is emailed without a founder explicitly approving it. The
        // decision is recorded against them, not against "the system".
        const leadDecision = path.match(/^\/leads\/(\d+)\/outreach\/(approve|reject)$/);
        if (leadDecision && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const lead = await db.getLeadById(env, leadDecision[1]);
          if (!lead) return html(views.errorPage("That lead no longer exists.", 404, theme), 404);

          const decision = leadDecision[2] === "approve" ? "approved" : "rejected";
          if (decision === "approved" && !lead.contact_email) {
            return html(
              views.errorPage("That lead has no email address, so it can't be approved for outreach. Add one first.", 400, theme),
              400
            );
          }
          await db.setOutreachStatus(env, lead.id, decision, user.name);
          await db.logAudit(env, user, `outreach_${decision}`, "lead", lead.id, `${lead.name}${lead.company ? " (" + lead.company + ")" : ""}`, reqIp);
          return redirect(f.back === "queue" ? "/outreach" : `/leads/${lead.id}`);
        }

        // ---- Trigger the send ----
        const leadSend = path.match(/^\/leads\/(\d+)\/outreach\/send$/);
        if (leadSend && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          // Double-clicking "Send" must not send twice.
          if (!(await claimOnce(env, f))) return redirect(`/leads/${leadSend[1]}`);

          const lead = await db.getLeadById(env, leadSend[1]);
          if (!lead) return html(views.errorPage("That lead no longer exists.", 404, theme), 404);

          if (!outreachSendingConfigured(env)) {
            return html(
              views.errorPage("Outreach sending isn't configured yet — MAKE_OUTREACH_URL and MAKE_WEBHOOK_SECRET both need setting.", 400, theme),
              400
            );
          }
          // Two independent guards, because an accidental send can't be undone.
          if (lead.outreach_status !== "approved") {
            return html(views.errorPage("That lead hasn't been approved for outreach yet.", 400, theme), 400);
          }
          if (!lead.contact_email) {
            return html(views.errorPage("That lead has no email address.", 400, theme), 400);
          }

          const payload = buildOutreachPayload(lead, user.name);
          const result = await triggerOutreach(env, payload);

          // Record the outcome either way, using the payload's own event_id so
          // the ledger and what Make received refer to the same thing.
          await db.recordOutreachEvent(env, {
            event_id: payload.event_id,
            lead_id: lead.id,
            lead_email: lead.contact_email,
            kind: result.ok ? "sent" : "failed",
            sequence: "hq_manual",
            step: null,
            subject: result.ok ? "Outreach email triggered" : "Send failed",
            detail: result.ok ? null : `Make returned ${result.status || "no response"}: ${result.body}`.slice(0, 1000),
            occurred_at: payload.timestamp,
            source: "catalyst7_hq",
          });

          if (result.ok) {
            // Opens the Sequence B call window in the same statement.
            await db.markOutreachSent(env, lead.id, callWindowHours(env));
            await db.logAudit(env, user, "outreach_sent", "lead", lead.id, `${lead.name} <${lead.contact_email}>`, reqIp);
          } else {
            await db.logAudit(
              env,
              user,
              "outreach_send_failed",
              "lead",
              lead.id,
              `${lead.name}: ${result.status || "no response"}`,
              reqIp,
              "failure"
            );
          }
          return redirect(`/leads/${lead.id}`);
        }

        // ---- The approval queue ----
        if (path === "/outreach" && method === "GET") {
          return html(
            views.outreachQueuePage({
              user,
              csrf,
              theme,
              queue: await db.getLeadsAwaitingApproval(env),
              counts: await db.countOutreachQueue(env),
              recent: await db.getRecentOutreach(env, 25),
              unmatched: await db.getUnmatchedOutreach(env, 10),
              sendingReady: outreachSendingConfigured(env),
              webhookReady: makeWebhookConfigured(env),
            })
          );
        }

        // ---- The call window (CRM step 3) ----
        //
        // Sequence B's step 9 -- wait a short window, then call regardless of
        // whether they replied, then log the outcome. Before this existed the
        // step happened, but nothing recorded that it had.
        if (path === "/calls" && method === "GET") {
          return html(
            views.callQueuePage({
              user,
              csrf,
              theme,
              queue: await db.getCallQueue(env),
              counts: await db.countCallQueue(env),
              stats: await db.getCallOutcomeStats(env),
              windowHours: callWindowHours(env),
            })
          );
        }

        const callLog = path.match(/^\/leads\/(\d+)\/call\/log$/);
        if (callLog && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          // A double submit would put two calls on the timeline for one call.
          if (!(await claimOnce(env, f))) return redirect(f.back === "calls" ? "/calls" : `/leads/${callLog[1]}`);

          const lead = await db.getLeadById(env, callLog[1]);
          if (!lead) return html(views.errorPage("That lead no longer exists.", 404, theme), 404);

          if (!db.CALL_OUTCOMES.includes(f.outcome)) {
            return html(views.errorPage("Pick one of the listed call outcomes.", 400, theme), 400);
          }
          // Logging a call for a lead that was never sent to would create a
          // window that no send opened, and the outcome stats are only
          // meaningful across leads that actually went through the sequence.
          if (!lead.call_due_at) {
            return html(
              views.errorPage("No outreach has been sent to that lead yet, so there is no call window to close.", 400, theme),
              400
            );
          }

          await db.logCallOutcome(env, {
            leadId: lead.id,
            leadEmail: lead.contact_email,
            outcome: f.outcome,
            notes: f.notes,
            actor: user.name,
          });
          await db.logAudit(env, user, "call_logged", "lead", lead.id, `${lead.name}: ${f.outcome}`, reqIp);
          return redirect(f.back === "calls" ? "/calls" : `/leads/${lead.id}`);
        }

        const callReopen = path.match(/^\/leads\/(\d+)\/call\/reopen$/);
        if (callReopen && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const lead = await db.getLeadById(env, callReopen[1]);
          if (!lead) return html(views.errorPage("That lead no longer exists.", 404, theme), 404);

          await db.reopenCallWindow(env, lead.id);
          // Audited because it changes what the outcome stats say. The logged
          // call stays on the timeline either way.
          await db.logAudit(env, user, "call_reopened", "lead", lead.id, `${lead.name}`, reqIp);
          return redirect(`/leads/${lead.id}`);
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
          if (!(await claimOnce(env, r))) return redirect("/revenue");
          await db.createRevenueEntry(env, {
            week_start: r.week_start,
            client_id: r.client_id || null,
            amount: parseFloat(r.amount || "0"),
            type: r.type,
            invoice_status: r.invoice_status,
          });
          await db.logAudit(env, user, "revenue_logged", "revenue", null, `${r.amount} (${r.type})`, reqIp);
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
          await db.createUser(env, {
            email,
            name,
            role,
            title: (f.title || "").trim() || null,
            freelancer_id: freelancerId,
            setup_token: token,
          });
          await db.logAudit(env, user, role === "founder" ? "founder_created" : "user_created", "user", null, `${name} <${email}>`, reqIp);

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
          await db.logAudit(env, user, "invite_reissued", "user", target.id, `${target.name} <${target.email}>`, reqIp);
          return html(
            await teamPage({
              message: `New link for ${target.name}. Any previous link or password for this account has stopped working.`,
              inviteLink: `${url.origin}/setup/${token}`,
              inviteFor: target.name,
            })
          );
        }

        // Titles are a display label. This route deliberately cannot touch
        // `role`, so editing one can never change what anyone may see.
        const teamTitle = path.match(/^\/team\/(\d+)\/title$/);
        if (teamTitle && method === "POST") {
          const f = await readForm(request);
          const fail = csrfGuard(user, f, theme);
          if (fail) return fail;
          const target = await db.getUserById(env, teamTitle[1]);
          if (!target) return html(views.errorPage("That account no longer exists.", 404, theme), 404);

          const title = (f.title || "").trim().slice(0, 60);
          await db.setUserTitle(env, target.id, title);
          await db.logAudit(env, user, "title_changed", "user", target.id, `${target.name}: ${title || "(cleared)"}`, reqIp);
          return html(await teamPage({ message: `Updated ${target.name}'s title.` }));
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
            title: (f.title || "").trim() || null,
            created_by: user.id,
            expires_at: new Date(Date.now() + days * 86400000).toISOString(),
          });
          await db.logAudit(env, user, "invite_code_created", "user", null, `${role}, expires in ${days}d${f.note ? " — " + f.note : ""}`, reqIp);

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
          await db.logAudit(env, user, "invite_code_revoked", "user", null, gone ? "revoked" : "already used or gone", reqIp);
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
          if (target.role === "founder" && target.has_password && (await db.countActiveFounders(env)) <= 1) {
            return html(
              await teamPage({ error: "That's the last founder with a working login — revoking it would lock everyone out." }),
              400
            );
          }

          await db.revokeUserAccess(env, target.id);
          await db.logAudit(env, user, "access_revoked", "user", target.id, `${target.name} <${target.email}>`, reqIp);
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
          const flag = await env.DB.prepare(
            "SELECT id, entity_type, entity_id FROM retention_flags WHERE id = ?"
          ).bind(flagId).first();
          if (flag && f.decision === "erase") {
            if (flag.entity_type === "lead") await db.eraseLeadPII(env, flag.entity_id);
            if (flag.entity_type === "freelancer") await db.eraseFreelancerPII(env, flag.entity_id);
            await db.resolveRetentionFlag(env, flagId, "erased");
            await db.logAudit(env, user, "retention_erased", flag.entity_type, flag.entity_id, null, reqIp);
          } else if (flag) {
            await db.resolveRetentionFlag(env, flagId, "kept");
            await db.logAudit(env, user, "retention_kept", flag.entity_type, flag.entity_id, null, reqIp);
          }
          return redirect("/retention");
        }

        return html(views.restrictedPage({ user, theme }), 404);
      }

      return html(views.restrictedPage({ user, theme }), 404);
    } catch (err) {
      await db.logError(env, path, err.stack || err.message || String(err));
      return html(views.errorPage("Something went wrong: " + err.message, 500, theme), 500);
    }
  },

  // Monthly Cron Trigger (see wrangler.toml [triggers]) -- flags stale
  // records for a human retention decision. Never deletes anything itself.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        await db.runRetentionScan(env);
        await db.purgeOldSubmissions(env);
      })()
    );
  },
};
