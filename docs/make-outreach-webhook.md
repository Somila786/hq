# Wiring your Make outreach scenario into HQ

**Step 1 of the CRM work.** HQ records what your Make scenario actually does —
what went out, who replied, what bounced — and shows it on the lead.

Make still owns sending and the email copy. HQ owns the record. That split is
deliberate: HQ has no email capability at all, and adding one would be a large
new dependency surface for something Make already does well.

---

## 1. Set the shared secret

The endpoint is public — Make posts from its own infrastructure, with no session
and no fixed IP. Authenticity comes entirely from an HMAC signature, so the
secret is the only thing standing between your pipeline data and the internet.

In the Cloudflare dashboard: **Workers & Pages → catalyst7-kpi → Settings →
Variables and Secrets → Add**, type **Secret**:

| | |
|---|---|
| Name | `MAKE_WEBHOOK_SECRET` |
| Value | a long random string — 32+ characters |

Until this is set, `/webhooks/make` returns 404 and the feature is dormant.
Nothing else in HQ is affected.

Keep the same value to hand — Make needs it in step 3.

## 2. The endpoint

```
POST https://hq.catalyst7.co.za/webhooks/make
Content-Type: application/json
X-Signature-256: sha256=<hex HMAC of the raw body>
```

## 3. What Make should send

The C7 webhook envelope, with the event details in `data`:

```json
{
  "event_id": "evt_a1b2c3",
  "timestamp": "2026-08-06T09:15:00.000Z",
  "source": "make_outreach",
  "form_name": "outreach_event_v1",
  "data": {
    "kind": "sent",
    "email": "thandi@bakery.co.za",
    "sequence": "cold_outreach_v2",
    "step": 1,
    "subject": "Quick question about Braamfontein Bakery",
    "detail": null
  }
}
```

| Field | Required | Notes |
|---|---|---|
| `event_id` | yes | Any unique string. **This is what makes retries safe** — see below. |
| `timestamp` | yes | ISO 8601. Must be within the last 7 days and not more than 5 minutes in the future. |
| `data.kind` | yes | One of `sent`, `reply`, `bounce`, `failed`. Anything else is refused. |
| `data.email` | yes | The lead's address. Matched case-insensitively. |
| `data.sequence` | no | Your sequence name, e.g. `cold_outreach_v2`. |
| `data.step` | no | Which step fired. |
| `data.subject` | no | Shown as the timeline headline. |
| `data.detail` | no | Bounce reason, reply snippet, error text. |

### Signing it in Make

Add an **HMAC SHA-256** step (or a Tools → Set variable with the crypto
function) over the **exact JSON body string** you are about to send, keyed with
`MAKE_WEBHOOK_SECRET`. Put the hex result in the `X-Signature-256` header,
either bare or prefixed `sha256=` — HQ accepts both.

> **The single most common mistake:** signing a *re-serialised* copy of the
> payload. HQ verifies against the raw bytes it receives. If Make builds the
> JSON, signs it, then rebuilds it before sending, key order or whitespace can
> differ and every request will fail with 401. Sign the exact string you send.

## 4. What you get back

```json
{ "success": true, "message": "Payload received", "matched_lead": 3 }
```

- `matched_lead` is the lead id, or `null` if no lead has that address. An
  unmatched event is still recorded — usually a typo or a lead removed
  mid-sequence, and easier to spot than to hunt for later.
- A repeat of the same `event_id` also returns **200**, with
  `"Payload received (already recorded)"`. That is deliberate: an error would
  make Make retry forever. **Send a stable `event_id` per real event** and
  retries become harmless.

### Failures

| Status | Meaning |
|---|---|
| 404 | `MAKE_WEBHOOK_SECRET` isn't set |
| 401 | Signature missing or wrong — check step 3 |
| 400 | Missing `event_id`, bad timestamp, or unsupported `kind` |

Rejections are written to the audit log with the calling IP, so a
misconfigured scenario is visible rather than silent.

## 5. Where it shows up

- **Leads** — an Outreach column summarising sends, replies and failures
- **Any lead** — click through for the full timeline, newest first, with counts

---

# Step 2 — approving and triggering sends from HQ

The pipeline: **Apify scrapes → you qualify in HQ → you approve → HQ triggers Make.**

## Set the outbound URL

Add a second Worker variable alongside the secret:

| Name | Type | Value |
|---|---|---|
| `MAKE_OUTREACH_URL` | Secret | your scenario's custom-webhook URL |

Until both this and `MAKE_WEBHOOK_SECRET` are set, the Send button stays hidden
and the send route refuses outright.

## What HQ posts to your scenario

Same C7 envelope, signed the same way, with the lead in `data`:

```json
{
  "event_id": "evt_…",
  "timestamp": "2026-08-06T09:15:00.000Z",
  "source": "catalyst7_hq",
  "form_name": "outreach_send_v1",
  "data": {
    "lead_id": 3,
    "name": "Thandi Mokoena",
    "first_name": "Thandi",
    "company": "Braamfontein Bakery",
    "email": "thandi@bakery.co.za",
    "stage": "qualified",
    "owner": "Somila",
    "source": "apify",
    "value_estimate": 25000,
    "notes": "",
    "approved_by": "Somila Tenza Sogaxa"
  }
}
```

`first_name` is split out because Gmail merge fields usually want it.

## ⚠️ Your scenario currently expects Apify's payload

This is the thing most likely to break. Your Gmail module's field mappings are
bound to whatever Apify sends. When HQ posts the shape above, those mappings
won't resolve and the email will send blank or fail.

Two ways to handle it:

- **Clone the scenario** (recommended) — one copy triggered by Apify for
  scraping, one triggered by HQ for sending, each with its own mappings.
  Nothing that currently works gets touched.
- **Re-map in place** — point the existing Gmail module at
  `data.email`, `data.first_name`, `data.company`. Simpler, but you lose the
  Apify path unless it also sends the same shape.

## What HQ does with the response

Your scenario ends in a **Webhook response** module, so HQ gets the answer
synchronously:

- **2xx** → recorded as `sent` on the lead, and `outreach_last_sent_at` stamped
- **Anything else, or no reply within 20 seconds** → recorded as `failed`, with
  the status and body, and audited as a failure

Either way it lands on the lead's timeline. A send that fails is visible rather
than silent.

## Guards worth knowing about

- **Nothing sends without an explicit approval.** Approval is separate from
  `stage` on purpose — moving a deal along the pipeline must never quietly
  authorise an email.
- A lead with **no email address** can't be approved at all.
- **Double-clicking Send sends once.** An email can't be unsent, so the send
  route uses the same one-time nonce as the other create forms.
- Approve, reject and send are **founder-only** and CSRF-guarded.

Opens and clicks were deliberately excluded. Apple Mail Privacy Protection
pre-fetches images, so open rates are badly inflated and act on nobody's
behalf; replies and bounces are the signals worth acting on.

---

# Step 3 — the call window and outcome log

**This is Sequence B's step 9**, the one the Call-Timing Decision Log lists as
having *"no tool — human, off the tracker"*, and whose only stated drawback is
*"needs a tracked window per lead — a scheduling/reminder mechanism not yet
built."* This is that mechanism.

Nothing to configure. It switches itself on the first time a send succeeds.

## How it works

1. A send succeeds → HQ stamps a **call window** on the lead, closing 18 hours
   later. The window and the send are written in one statement, so there is no
   path that records a send without also putting the call on the tracker.
2. The lead appears on **`/calls`**, sorted by how overdue it is.
3. You call, pick an outcome, and hit **Log call**.

A failed send opens **no** window. If the email never left, calling would be a
cold call, not Sequence B.

## Changing the window

| Name | Type | Value |
|---|---|---|
| `CALL_WINDOW_HOURS` | Variable | hours from send to call, default `18` |

18 hours is the default because the decision log says "same day or next
morning", and 18 hours lands there from either a morning or an afternoon send.
Values are clamped to 1–168: a window of 0 would make every lead due instantly
and the queue meaningless, and 100000 would hide the queue forever. Both fail
quietly, which is worse than failing loudly.

## The outcomes

| Outcome | Means |
|---|---|
| `picked_up_cold` | Answered the call, had not replied to the email first |
| `replied_first` | Had already replied before the call landed |
| `no_response` | No reply, and the call went unanswered |
| `skipped` | Deliberately not called |

The first three are the comparable data the sequence exists to produce. The
page counts `skipped` but keeps it out of that comparison — a call that never
happened says nothing about whether calling works.

## Two things it deliberately does not do

- **It does not hide leads who replied.** Sequence B calls everyone, and that
  is what makes the three buckets comparable. Filtering repliers out would bias
  the data toward the least engaged half of every batch. The queue flags them
  as *replied — call anyway* instead.
- **It does not refuse an early call.** A window still open shows as waiting,
  but the log form is live the whole time. A tool that blocked a same-day call
  would be fighting the operator.

## Corrections

**Logged by mistake — reopen** on the lead clears the outcome and puts it back
in the queue. It keeps the original window, because a correction is not a new
send, and it leaves the logged call on the timeline. A correction doesn't get
to rewrite what was done. Both the log and the reopen are audited.

## Still not built

- **Multi-step sequences** — HQ triggers one send per press. Your scenario
  sends one email, so there is no drip yet on either side.
- **Apify → HQ** — scraped leads still have to be added by hand.
- **Stop conditions** — a reply doesn't halt anything. Under Sequence B that is
  correct for the call, which happens regardless; it would matter for a drip.
- **Reminders that reach you** — `/calls` has to be opened. There is no push,
  no email, no calendar entry.
