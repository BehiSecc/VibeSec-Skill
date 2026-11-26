# Client and Browser Security

## Contents

- [XSS Beyond Standard Escaping](#xss-beyond-standard-escaping)
- [Content Security Policy](#content-security-policy)
- [CSRF Edge Cases](#csrf-edge-cases)
- [CORS Misconfiguration](#cors-misconfiguration)
- [Client-Side Secret and PII Leaks](#client-side-secret-and-pii-leaks)

## XSS Beyond Standard Escaping

Framework escaping (React JSX, Vue `{{ }}`) protects text nodes, not dangerous sinks or indirect rendering paths. Check these specifically:

- **URL attributes (`href`, `src`, `action`, `formaction`, `window.open`):** Frameworks do not block `javascript:` or `data:` URLs. Parse and allow only `http:`, `https:`, or relative `/` paths.
- **Raw HTML sinks (`dangerouslySetInnerHTML`, `v-html`, `{@html}`, `innerHTML`):** Sanitize with DOMPurify using an explicit tag/attribute allowlist. Never write regex-based HTML sanitizers.
- **Markdown renderers:** Disable raw HTML passthrough and sanitize both rendered HTML and link protocols.
- **SVG files:** SVGs can execute embedded `<script>` and event handlers (`onload`) when rendered inline or opened directly on the app's origin. Treat user SVGs as active content.
- **PDF / screenshot generators and email templates:** User input interpolated into HTML rendered by headless browsers (Puppeteer/Playwright/wkhtmltopdf) executes JS on the server side, often escalating to SSRF or local file read.
- **`window.postMessage`:** Validate `event.origin === expectedOrigin` using exact string equality (never `.includes()` or unanchored regex) before acting on incoming messages. Pass an explicit `targetOrigin`, never `'*'`, when sending sensitive data.
- **Overlooked reflection surfaces:** Admin log viewers, error messages reflecting query parameters, and JSON responses accidentally served with `Content-Type: text/html`.

## Content Security Policy

- Avoid `script-src 'unsafe-inline'` and `'unsafe-eval'`; use per-request nonces or hashes when inline scripts are unavoidable.
- Always include `base-uri 'self'` (blocks `<base>` URL hijacking), `object-src 'none'`, `frame-ancestors 'none'`, and `form-action 'self'`.
- Pair CSP with `X-Content-Type-Options: nosniff`.

```http
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';
```

## CSRF Edge Cases

- **Protect pre-auth endpoints too:** Login, signup, password reset, email/phone verification, and OAuth callbacks all need CSRF protection (prevents login CSRF and account linking attacks).
- **Missing-token bypass:** Never skip CSRF verification when the token header or body parameter is absent. A missing token must reject the request.
- **JSON APIs are not automatically safe:** If the server parses JSON regardless of `Content-Type` (allowing `text/plain` simple requests) or allows overly broad CORS, browsers can still send cross-site requests. Require a custom header + CSRF token or strictly validate `Origin` / `Sec-Fetch-Site` alongside `SameSite=Lax` or `Strict` cookies.
- **No state changes on `GET`:** Never mutate state on `GET` endpoints.
- **No CSRF tokens in URLs:** Send tokens via custom headers (`X-CSRF-Token`) or POST bodies, never query strings where they leak via `Referer` and logs.
- **Session binding and subdomains:** Bind CSRF tokens to the user session, regenerate them on auth state changes, and be cautious with wildcard subdomain cookies (a compromised subdomain can set cookies or forge requests).

## CORS Misconfiguration

| Misconfiguration | Why it breaks security | Fix |
| --- | --- | --- |
| Reflecting `Origin` + `Access-Control-Allow-Credentials: true` | Any website can make authenticated requests and read responses | Exact-match `Origin` against a static allowlist before echoing it |
| Allowing `Origin: null` with credentials | Sandboxed iframes (`<iframe sandbox>`) send `Origin: null` | Reject `null` when credentials are enabled |
| Unanchored regex or substring match (`origin.includes('app.com')`) | Bypassed by `app.com.evil.com` or `evilapp.com` | Compare full normalized origin (`scheme://host[:port]`) against an allowlist |
| Wildcard `*` on authenticated/internal APIs | Exposes sensitive data to arbitrary origins | Restrict to explicit trusted origins |

## Client-Side Secret and PII Leaks

Check all places server data silently leaks into browser code:

- Build-time public env prefixes: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `NUXT_PUBLIC_*`.
- SSR hydration payloads (`__NEXT_DATA__`, Remix loaders, Server-to-Client Component props) where entire ORM rows get serialized into HTML.
- Production JavaScript source maps uploaded publicly.
- HTML comments, hidden form inputs, `data-*` attributes, and `localStorage` / `sessionStorage`.

Explicitly project only the exact fields required for UI rendering before returning API responses or passing props to client components (strip password hashes, tokens, internal flags, and unnecessary PII).
