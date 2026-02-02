# VibeSec-Skill

> **Stop vibe coding vulnerabilities into production.**

A Claude Skill that brings 5+ years of bug bounty hunting experience directly into your AI coding workflow - so Claude writes secure code from the start.

## Introduction

Vibe coding is fun until your app ends up on social media for all the wrong reasons.

We have all seen the posts/memes:

* API keys hardcoded in JavaScript bundles
* IDOR vulnerabilities allowing user data dumps
* No authentication for sensitive pages
* Weak passwords for admin panels

Security gaps aren't obvious until someone exploits them. Without the right guidance, AI will confidently ship vulnerable patterns alongside your features.

VibeSec is a Claude Skill that acts as a security-first co-pilot. It teaches Claude to approach your code from a bug hunter's perspective, catching vulnerabilities before they ship.

## 📚 Table of Contents  
- [VibeSec-Skill](#VibeSec-Skill)
  - [📥 Installation](#-installation)
  - [🛡️ Covered Vulnerabilities](#️-covered-vulnerabilities)
  - [🚀 Quick Start](#-quick-start)
  - [🤝 Contribution](#-contribution)
  - [📬 Contact](#-contact)



## 📥 Installation

1. Download the `SKILL.md` file from this repository
2. Add it to your Claude Project(or to `~/.claude/skills`)
3. Start coding - Claude will automatically load the skill



## 🛡️ Covered Vulnerabilities

VibeSec provides comprehensive protection against:

| Category | Vulnerabilities |
|----------|-----------------|
| **Access Control** | IDOR, Privilege Escalation, Horizontal/Vertical Access, Mass Assignment, Token Revocation |
| **Client-Side** | XSS (Stored, Reflected, DOM), CSRF, Secret Key Exposure, Open Redirect |
| **Server-Side** | SSRF, SQL Injection, XXE, Path Traversal, Insecure File Upload |
| **Authentication** | Weak Passwords, Session Management, Account Lifecycle |

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

# Claude will now automatically:
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
