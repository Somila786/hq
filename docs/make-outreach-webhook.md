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

## Not built yet

Deliberately out of scope for step 1, in the order planned:

2. **Outbound trigger** — a "Start sequence" button that posts to Make
3. **Sequence definitions** — naming steps and delays inside HQ
4. **The CRM tab proper** — leads, sequences and activity in one view
5. **Stop conditions** — a reply drops the lead out of its sequence

Opens and clicks were deliberately excluded. Apple Mail Privacy Protection
pre-fetches images, so open rates are badly inflated and act on nobody's
behalf; replies and bounces are the signals worth acting on.
