# URLs, File Uploads, and XML Parsing

## Contents

- [SSRF (Server-Side Request Forgery)](#ssrf-server-side-request-forgery)
- [Open Redirect](#open-redirect)
- [File Uploads and Archives](#file-uploads-and-archives)
- [XML Parsing and XXE](#xml-parsing-and-xxe)

## SSRF (Server-Side Request Forgery)

High-risk surfaces: webhooks, URL/link previews, image/file import from URL, RSS/feed readers, HTML-to-PDF or headless browser renderers, and proxy endpoints.

- **Preferred defense:** Restrict outbound fetches to an explicit allowlist of approved domains/origins.
- **When arbitrary public URLs must be fetched:**
  1. Allow only `http:` and `https:` schemes (reject `file:`, `gopher:`, `ftp:`, `dict:`).
  2. Resolve DNS and verify **every** returned IP is globally routable. Block loopback (`127.0.0.0/8`, `::1`), private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), ULA (`fc00::/7`), unspecified (`0.0.0.0`, `::`), and IPv4-mapped IPv6 (`::ffff:0:0/96`).
  3. **Pin the validated IP** on the outbound connection so the HTTP client does not re-resolve DNS (prevents DNS rebinding).
  4. Explicitly block cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, `metadata`).
  5. Disable redirects, or re-run full URL, DNS, and IP validation on **every redirect hop**.
  6. Set strict connect/read timeouts and cap maximum response size.

### SSRF Bypasses to Block

| Technique | Example | Why naive filters miss it |
| --- | --- | --- |
| Alternate IP encodings | `http://2130706433`, `http://0177.0.0.1`, `http://0x7f000001`, `http://127.1` | All resolve to `127.0.0.1` |
| IPv6 representations | `http://[::1]`, `http://[::]`, `http://[::ffff:127.0.0.1]`, `http://[fe80::1%25eth0]` | Bypass IPv4-only string or regex blocklists |
| DNS rebinding / CNAME | Attacker domain resolves to public IP, then internal IP (or CNAMEs internally) | Validating hostname or resolving twice lets second lookup hit localhost/metadata |
| Redirect chains | Public URL returns `302` to `http://169.254.169.254/...` | Only initial URL was validated |
| URL parser confusion | `http://public.com@127.0.0.1`, `http://attacker.com#@internal` | Validator and HTTP client disagree on host |

## Open Redirect

- Prefer indirect lookup keys (`?next=dashboard` -> `/dashboard`) or strict relative paths (must start with a single `/`; reject `//`, `/\`, `\\`, and control characters).
- When external redirect targets are needed, parse with a standard URL parser, enforce `http:`/`https:`, normalize the hostname to ASCII Punycode (blocks IDN homographs), and exact-match against an allowlist.

### Redirect Bypasses to Block

| Technique | Example | Why it bypasses |
| --- | --- | --- |
| `@` userinfo | `https://legit.com@evil.com` | Browser navigates to `evil.com` with `legit.com` as username |
| Suffix / subdomain abuse | `https://legit.com.evil.com` | Prefix or substring checks treat `legit.com` as valid |
| Protocol-relative & backslash | `//evil.com`, `/\evil.com`, `https://legit.com\@evil.com` | Browsers normalize `\` to `/` and inherit scheme |
| Dangerous schemes | `javascript:alert(1)`, `data:text/html,...` | Executes script when scheme is not allowlisted |
| Encoding / whitespace / null | `%252f%252fevil.com`, `https://legit.com%09.evil.com`, `%00` | Double decoding or parser truncation shifts the host |
| Fragment confusion | `https://legit.com#@evil.com` | Different parsers disagree on authority vs fragment |
| IDN homographs | Unicode lookalike characters in domain | Spoofs trusted hostname unless converted to Punycode |

## File Uploads and Archives

- **Validate type and content:** Allowlist a single expected extension, verify magic bytes, and parse/re-encode images with a media library (Sharp, Pillow, libvips) to neutralize polyglots, embedded scripts, and metadata exploits. Enforce size limits at both the app and reverse proxy.
- **Rename and isolate:** Discard the original filename and store files under a random UUID outside the webroot or in object storage. Serve user uploads from a **separate origin/domain** so uploaded HTML, SVG, or polyglots cannot access app cookies.
- **Response headers for downloads:** Always send `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, and a validated `Content-Type`. Never allow execution permissions on upload directories.

### Upload Attacks to Block

| Attack | Example / Vector | Required defense |
| --- | --- | --- |
| Double or null-byte extension | `shell.php.jpg`, `shell.php%00.jpg` | Allow single allowlisted extension and rename to UUID |
| MIME spoofing & polyglots | `Content-Type: image/jpeg` on script, or valid JPEG+JS polyglot | Parse and re-encode file content rather than trusting headers or magic bytes alone |
| SVG with script | `<svg onload="alert(1)">` | Disallow SVG uploads, or sanitize and serve on a separate origin as attachment |
| Archive slip & bombs | ZIP entry `../../../etc/passwd`, symlinks, or huge expansion ratio | Canonicalize every extracted path against target dir, reject symlinks, cap file count and total uncompressed bytes |
| Filename metacharacters | Shell metacharacters (`;`, `|`, `$()`, backticks) in uploaded name | Replace filename with UUID; never pass filenames to shell commands |
| Office / image parser bugs | Malicious DOCX/XLSX XML or crafted ImageMagick inputs | Disable XML external entities (below); strip macros; keep image processors patched with strict `policy.xml` |

## XML Parsing and XXE

Watch indirect XML surfaces too: **DOCX/XLSX/PPTX** (ZIP archives containing XML), **SVG**, **SAML assertions**, **RSS/Atom feeds**, **SOAP**, and **PDF XFA forms**. Prefer JSON when XML is unnecessary.

Safe parser configuration by runtime:

- **Java:** Set `disallow-doctype-decl = true`, `external-general-entities = false`, `external-parameter-entities = false`, and `setExpandEntityReferences(false)` on `DocumentBuilderFactory`.
- **Python:** Use `defusedxml`, or `lxml.etree.XMLParser(resolve_entities=False, no_network=True)`.
- **PHP:** PHP 8+ (`libxml` 2.9+) disables external entity loading by default — **never pass `LIBXML_NOENT` or `LIBXML_DTDLOAD`**. Only PHP 7 and older require `libxml_disable_entity_loader(true)` (deprecated in PHP 8.0).
- **Node.js:** Use parsers that disable DTD processing by default; if using `libxmljs`, explicitly set `{ noent: false, dtdload: false }`.
- **.NET:** Configure `XmlReaderSettings` with `DtdProcessing = DtdProcessing.Prohibit` and `XmlResolver = null`.
