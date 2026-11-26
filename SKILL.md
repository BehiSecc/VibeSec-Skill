---
name: vibesec
description: Bug-hunter secure coding rules and audit workflow for web applications. Use when writing, modifying, or reviewing web code that handles authentication, authorization, database queries, APIs, user input rendered in HTML/SVG/Markdown, redirects, outbound URL fetching, file uploads, or XML parsing, or when the user asks for a security review or audit. Do not load for pure styling, copy, or static layout edits.
---

# VibeSec

Approach web code from a bug hunter's perspective: prevent exploitable vulnerabilities without breaking functionality or adding unnecessary complexity.

## Modes

### Building or modifying code

1. Identify which security surfaces the change touches using the routing table below.
2. Read only the matching file(s) in `references/` before writing code.
3. Apply the always-on invariants below plus the edge cases in those references.
4. Before finishing, re-check every new or changed endpoint, mutation, query, render sink, and outbound fetch against those rules.

### Auditing or reviewing code

1. Map entry points and trust boundaries first: routes, Server Actions, API resolvers, auth middleware, database queries, outbound HTTP calls, file handlers, and client render sinks.
2. Read only the `references/` files matching surfaces present in the codebase.
3. Trace real data flows from untrusted input to sink and verify whether an existing defense already blocks exploitation.
4. Report only verified, exploitable findings ordered by severity. For each finding, include `file:line`, vulnerability class, concrete exploit path, and minimal fix. Skip generic advice and theoretical hardening unless asked.

## Always-On Invariants

Apply these on every security-relevant web change:

- **Authorize at the data layer, not only middleware.** Scope every read or mutation by the authenticated user or tenant (and parent resource where nested). Never trust client-supplied `userId`, `orgId`, or `role`.
- **Return `404` instead of `403` on unauthorized object lookups** to prevent ID enumeration.
- **Use non-guessable IDs (UUIDv4, ULID, or CUID2)** for user-accessible records unless sequential IDs are explicitly required.
- **Fail closed on auth and permission errors.** Missing tokens, invalid signatures, or unexpected roles must deny access — never fall through.
- **Keep secrets strictly server-side.** Never put API keys, DB URLs, JWT secrets, OAuth client secrets, or service-role keys in `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, client bundles, source maps, or SSR hydration payloads.
- **Allowlist mutable fields explicitly.** Never pass raw request bodies or form data straight into ORM `.create()` or `.update()`.
- **Parameterize all queries and commands.** Never interpolate user input into SQL, shell commands, or template strings; strictly allowlist identifiers that cannot be parameterized (`ORDER BY`, column or table names).
- **Validate input server-side** even when client-side validation exists.
- **Keep errors opaque to callers.** Log full details server-side; never expose stack traces, SQL errors, or internal paths in responses.
- **Set baseline response headers:** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`), `Referrer-Policy: strict-origin-when-cross-origin`, `Strict-Transport-Security`, and `Cache-Control: no-store` on sensitive responses.
- **Default to the stricter option when uncertain** and briefly note the security trade-off in a comment.

## Reference Routing

Load a reference file only when the task touches its surface:

| Surface touched | Reference file |
| --- | --- |
| Auth, sessions, JWT, OAuth, passwords, RBAC, IDOR, multi-tenancy, RLS, Server Actions, rate limiting | [references/auth-and-access.md](references/auth-and-access.md) |
| User-controlled HTML/Markdown/SVG/PDF rendering, `postMessage`, CSP, CSRF, CORS, client-side secret leaks | [references/client-and-browser.md](references/client-and-browser.md) |
| SQL/ORM queries, mass assignment, GraphQL, path traversal, command execution, SSTI, race conditions | [references/server-and-data.md](references/server-and-data.md) |
| Webhooks, URL previews/fetching (SSRF), redirects, file uploads, archives, SVG/DOCX/XLSX/XML parsing (XXE) | [references/urls-files.md](references/urls-files.md) |
