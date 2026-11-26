# Auth and Access Control

## Contents

- [Object and Tenant Authorization](#object-and-tenant-authorization)
- [Server Actions and BaaS (RLS)](#server-actions-and-baas-rls)
- [Account Lifecycle and Sessions](#account-lifecycle-and-sessions)
- [Passwords and Rate Limiting](#passwords-and-rate-limiting)
- [JWT Security](#jwt-security)
- [OAuth 2.0](#oauth-20)
- [Incoming Webhooks](#incoming-webhooks)

## Object and Tenant Authorization

- Enforce ownership in the data query (`WHERE id = $1 AND owner_id = $2` or `org_id = $2`), not only in route middleware.
- Verify **parent-resource ownership** on nested endpoints (for example, deleting or editing a comment, attachment, or line item must verify the caller has access to the parent post, project, or org).
- Return `404` rather than `403` when an object belongs to another user or tenant so attackers cannot enumerate valid IDs.
- Re-check current database roles and membership before sensitive admin, billing, or destructive actions — do not rely solely on stale JWT claims.
- Derive actor and tenant identity from the verified server-side session, never from request bodies, query strings, or custom headers.

## Server Actions and BaaS (RLS)

- **Next.js Server Actions / RPC handlers:** Treat every Server Action as a public HTTP POST endpoint. Authenticate and authorize inside the action itself — layout checks, client-hidden buttons, and route middleware do not protect direct POSTs. Never trust hidden inputs or bound client arguments as proof of ownership.
- **Supabase / Firebase / BaaS:** Enable Row-Level Security (RLS) on every client-accessible table with explicit `SELECT`, `INSERT`, `UPDATE`, and `DELETE` policies scoped to `auth.uid()` and tenant membership. Never expose `service_role` or admin SDK credentials to client code, and when using a service role server-side, replicate ownership checks manually.

## Account Lifecycle and Sessions

- Immediately invalidate active sessions, refresh tokens, and API keys when a user is removed from an org, loses a role, resets their password, or deletes/deactivates their account.
- Regenerate the session ID on login and privilege changes to prevent session fixation.
- Generate password reset and magic-link tokens with at least 128 bits of cryptographic randomness, store only a hash in the database, enforce single-use and short TTL (15–60 minutes), and invalidate prior tokens when issuing a new one.
- Prevent account enumeration on login, signup, and password reset by returning uniform responses and avoiding obvious timing differences (hash a dummy password when the account does not exist).

## Passwords and Rate Limiting

- Hash passwords with Argon2id (preferred), scrypt, or bcrypt; never MD5, SHA-1, or plain SHA-256.
- Require at least 12 characters (8 minimum), allow all characters, and avoid low max lengths. If using bcrypt, account for its 72-byte input truncation or switch to Argon2id.
- Rate-limit login, signup, password reset, MFA/OTP verification, and magic-link endpoints by **both account identifier and client IP**.
- Do not trust client-supplied `X-Forwarded-For` headers unless extracted from a configured trusted proxy hop.
- Cap verification attempts per OTP/reset code and make recovery codes strictly single-use.

## JWT Security

| Failure mode | Required defense |
| --- | --- |
| `alg: none` or algorithm confusion (`RS256` verified as `HS256`) | Pass an explicit algorithm allowlist on `verify()`; never trust the token header `alg` |
| Weak or fallback signing secret | Use >= 256-bit cryptographically random secrets from env; fail startup if unset (no `\|\| 'secret'` fallback) |
| Missing or long-lived `exp` | Keep access tokens short-lived (e.g., 15 min) and validate `exp` |
| Stolen refresh tokens | Rotate refresh tokens on every use; invalidate the token family if a rotated token is replayed |
| Token in `localStorage` / `sessionStorage` | Store session tokens in `HttpOnly; SameSite=Lax` cookies (with `Secure` in production/HTTPS); use `SameSite=Strict` only when cross-site redirects (OAuth, Stripe Checkout, email links) are not needed |

```javascript
// Critical verification and cookie defaults
const payload = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ['HS256'], // explicit allowlist; rejects alg:none and RS/HS confusion
});

res.cookie('session', token, {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax', // preserves session on OAuth/Stripe/email redirects
});
```

## OAuth 2.0

- Require exact-match `redirect_uri` validation against a server-side allowlist (no wildcards or prefix matching).
- Require PKCE (`S256`) and a cryptographically random, session-bound `state` parameter on every flow; reject callbacks with missing or mismatched `state`.
- Use Authorization Code + PKCE; never use the implicit flow (`response_type=token`).
- Verify `email_verified === true` from the identity provider before linking an OAuth login to an existing local account by email (prevents pre-account takeover).

## Incoming Webhooks

- Verify the provider's HMAC signature (Stripe, GitHub, Clerk, Svix, etc.) against the **exact raw request bytes** before JSON parsing — re-serializing parsed JSON breaks verification or leads developers to skip it.
- Compare signatures using constant-time equality (`crypto.timingSafeEqual`, `hmac.compare_digest`), never `===` or `==`.
- Reject missing or stale timestamps (e.g., older than 5 minutes) when the provider signs a timestamp to block replay attacks.
- Fail closed if the signing secret env var is missing, and deduplicate processed event IDs so retried webhooks are idempotent.
