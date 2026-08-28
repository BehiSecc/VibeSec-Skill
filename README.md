# VibeSec-Skill

> **Stop vibe coding vulnerabilities into production.**

An AI skill that brings 5+ years of bug bounty hunting experience directly into your AI coding workflow - so LLM models write secure code from the start.

## Introduction

Vibe coding is fun until your app ends up on social media for all the wrong reasons.

We have all seen the posts/memes:

* API keys hardcoded in JavaScript bundles
* IDOR vulnerabilities allowing user data dumps
* No authentication for sensitive pages
* Weak passwords for admin panels

Security gaps aren't obvious until someone exploits them. Without the right guidance, AI will confidently ship vulnerable patterns alongside your features.

VibeSec is an AI Skill that acts as a security-first co-pilot. It teaches your selected model to approach your code from a bug hunter's perspective, catching vulnerabilities before they ship.

## 📚 Table of Contents  
- [VibeSec-Skill](#VibeSec-Skill)
  - [📥 Installation](#-installation)
  - [🛡️ Covered Vulnerabilities](#️-covered-vulnerabilities)
  - [🚀 Quick Start](#-quick-start)
  - [🤝 Contribution](#-contribution)
  - [📬 Contact](#-contact)


>[!Tip]
>This skill already covers 60-70% of the common vulnerabilities. However, if you need a more robust version with more vulnerability coverage, please visit [vibesec.sh](https://vibesec.sh/)


## 📥 Installation

- <details><summary>Claude Code</summary>

  * Clone this repository: `git clone https://github.com/BehiSecc/VibeSec-Skill`

  * Add it to `~/.claude/skills` (global) or `.claude/skills` in your project directory (project-only).
</details>

- <details><summary>Cursor</summary>

  * Clone this repository: `git clone https://github.com/BehiSecc/VibeSec-Skill`

  * Add it to `~/.cursor/skills` (global) or `.cursor/skills` in your project directory (project-only).
</details>

- <details><summary>Codex</summary>

  * Clone this repository: `git clone https://github.com/BehiSecc/VibeSec-Skill`

  * Add it to `~/.agents/skills` (global) or `.agents/skills` in your project directory (project-only).

</details>

- <details><summary>Github Copilot</summary>

  * Clone this repository: `git clone https://github.com/BehiSecc/VibeSec-Skill`

  * Add it to `~/.copilot/skills` (global) or `.github/skills` in your project directory (project-only).

</details>

- <details><summary>Antigravity</summary>

  * Clone this repository: `git clone https://github.com/BehiSecc/VibeSec-Skill`

  * Add it to `~/.gemini/antigravity/skills/` (global) or `.agent/skills/` in your project directory (project-only).

</details>




## 🛡️ Covered Vulnerabilities

VibeSec provides comprehensive protection against:

| Category | Covered Vulnerabilities |
|----------|-----------------|
| **Access Control** | IDOR, Privilege Escalation, Horizontal/Vertical Access, Mass Assignment, Token Revocation |
| **Client-Side** | XSS (Stored, Reflected, DOM), CSRF, Secret Key Exposure, Open Redirect |
| **Server-Side** | SSRF, SQL Injection, Command Injection, SSTI, Insecure Deserialization, XXE, Path Traversal, Insecure File Upload |
| **Authentication** | Weak Passwords, Brute Force / Rate Limiting, Account Enumeration, Session Fixation, Password Reset, MFA, Account Lifecycle, JWT Security |
| **API Security** | Mass Assignment, GraphQL Security, CORS Misconfiguration, Race Conditions (TOCTOU) |


### Deep Coverage Includes:

- ✅ **Bypass techniques** - Not just "sanitize input" but specific bypasses attackers use
- ✅ **Edge cases** - URL fragments, DNS rebinding, polyglot files, Unicode tricks
- ✅ **Framework-aware** - Patterns for React, Vue, Node.js, Python, Java, .NET
- ✅ **Cloud-aware** - Metadata endpoint protection for AWS, GCP, Azure
- ✅ **Checklists** - Actionable verification steps for each vulnerability class



## 🚀 Quick Start

```markdown
# Add the skill to your project dir:

"I'm building a [web app description]. Please follow secure coding practices."

# Claude/Codex/etc will now automatically:
# - Implement proper access controls  
# - Add security headers
# - Validate and sanitize all inputs
# - Flag potential security issues
```



## 🤝 Contribution

If you have suggestions, improvements, or new resources to add:

1. Fork this repo
2. Make your changes
3. Submit a Pull Request

You can also open an **Issue** 🐛 if you spot something that needs fixing.



## 📬 Contact

If you want to contact me, you can reach me on [X](https://x.com/Behi_Sec).
