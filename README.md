# VibeSec-Skill

> **Stop vibe coding vulnerabilities into production.**

An AI skill that brings 5+ years of bug bounty hunting experience into your AI coding workflow — structured for modern agents with a lightweight `SKILL.md` router and targeted reference files loaded on demand.

## Introduction

Vibe coding is fun until your app ends up on social media for all the wrong reasons:

* API keys exposed in client bundles or `NEXT_PUBLIC_*` variables
* IDOR vulnerabilities and missing RLS policies leaking user data
* Unprotected Server Actions and admin endpoints
* Subtle SSRF, redirect, or upload bypasses

Current models already know textbook OWASP definitions, so VibeSec skips boilerplate and focuses on **build/audit workflows, universal invariants, and non-obvious bug-hunter bypasses** — loaded progressively so agents do not burn context on unrelated tasks.

## Table of Contents

- [VibeSec-Skill](#vibesec-skill)
  - [How It Works](#how-it-works)
  - [Installation](#installation)
  - [Covered Vulnerabilities](#covered-vulnerabilities)
  - [Quick Start](#quick-start)
  - [Contribution](#contribution)
  - [Contact](#contact)

> [!TIP]
> This skill covers the most common high-impact web vulnerabilities. If you need a more robust version with broader coverage, visit [vibesec.sh](https://vibesec.sh/).

## How It Works

```text
vibesec/
├── SKILL.md                        # Lightweight router, modes, and always-on invariants
└── references/
    ├── auth-and-access.md          # IDOR, RLS, Server Actions, sessions, JWT, OAuth, webhooks, rate limits
    ├── client-and-browser.md       # Indirect XSS sinks, CSP, CSRF edge cases, CORS, client leaks
    ├── server-and-data.md          # Non-obvious SQLi, mass assignment, GraphQL, traversal, SSTI, races
    └── urls-files.md               # SSRF bypasses, open redirects, uploads/archives, XXE
```

`SKILL.md` stays compact and loads only the matching file in `references/` when your task touches that surface — staying quiet on pure styling or copy edits.

## Installation

Clone the repository into a `vibesec` folder inside your agent's skills directory (the folder name matches `name: vibesec` in `SKILL.md` per the [Agent Skills specification](https://agentskills.io/specification)):

<details>
<summary>Claude Code</summary>

Global:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill ~/.claude/skills/vibesec
```

Project-only:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill .claude/skills/vibesec
```

</details>

<details>
<summary>Cursor</summary>

Global:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill ~/.cursor/skills/vibesec
```

Project-only:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill .cursor/skills/vibesec
```

</details>

<details>
<summary>Codex</summary>

Global:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill ~/.agents/skills/vibesec
```

Project-only:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill .agents/skills/vibesec
```

</details>

<details>
<summary>GitHub Copilot</summary>

Global:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill ~/.copilot/skills/vibesec
```

Project-only:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill .github/skills/vibesec
```

</details>

<details>
<summary>Antigravity</summary>

Global:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill ~/.gemini/antigravity/skills/vibesec
```

Project-only:

```bash
git clone https://github.com/BehiSecc/VibeSec-Skill .agent/skills/vibesec
```

</details>

## Covered Vulnerabilities

| Category | Covered Areas |
| --- | --- |
| **Auth & Access Control** | IDOR / tenant isolation, parent-resource checks, Next.js Server Actions, BaaS RLS, session lifecycle & revocation, password hashing, rate limiting, JWT, OAuth 2.0 (PKCE, `state`, email verification), incoming webhook HMAC verification |
| **Client & Browser** | Indirect XSS sinks (URL schemes, Markdown, SVG, PDFs, `postMessage`), CSP, pre-auth & missing-token CSRF, CORS misconfiguration, client-side & SSR hydration secret leaks |
| **Server & Data** | Non-parameterizable SQLi (`ORDER BY`, ORM raw escapes), mass assignment, GraphQL limits & alias batching, path traversal, command & argument injection, SSTI, race conditions / TOCTOU |
| **URLs, Files & XML** | SSRF bypasses & DNS rebinding, cloud metadata protection, open redirect parser bypasses, file upload polyglots & ZIP slip, XXE (including PHP 8+ guidance) |

## Quick Start

```markdown
# Build mode:
"Add a webhook callback endpoint and profile avatar upload. Follow VibeSec rules."

# Audit mode:
"Run a VibeSec security review on the auth and API routes in this repo."
```

## Contribution

If you have suggestions, improvements, or new bug-hunter edge cases to add:

1. Fork this repo
2. Make your changes (keep `SKILL.md` concise and place domain-specific checks in `references/`)
3. Submit a Pull Request

You can also open an **Issue** if you spot something that needs fixing.

## Contact

If you want to contact me, you can reach me on [X](https://x.com/Behi_Sec).
