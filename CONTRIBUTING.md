# Contributing to AppSec Atlas

Thank you for helping make AppSec Atlas the world's best open-source security knowledge base! Every contribution — big or small — matters.

---

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [Ways to Contribute](#ways-to-contribute)
- [Getting Started](#getting-started)
- [Guide Standards](#guide-standards)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Review Process](#review-process)

---

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to providing a welcoming and inclusive environment for everyone.

---

## Ways to Contribute

### 1. Write a New Guide
- Check the [open issues](https://github.com/AnimeshShaw/AppSec-Atlas/issues) for guides marked `content-request`
- Use the [guide template](community/templates/guide-template.md) as your starting point
- Follow the [Guide Standards](#guide-standards) below

### 2. Improve Existing Guides
- Fix technical inaccuracies
- Update outdated information (tools, CVEs, API changes)
- Add missing code examples
- Improve clarity and readability

### 3. Fix Typos & Errors
- Even small fixes are valuable! No contribution is too small.
- Look for issues labeled [`good first issue`](https://github.com/AnimeshShaw/AppSec-Atlas/issues?q=label%3A%22good+first+issue%22)

### 4. Add Lab Exercises
- Docker-based vulnerable apps
- CTF challenges with solutions
- Code samples demonstrating vulnerabilities and fixes

### 5. Review Pull Requests
- Technical review of new guides for accuracy
- Ensure content meets quality standards
- Test code examples and lab exercises

### 6. Translate Guides
- Help make AppSec Atlas accessible in more languages
- See our [translation guidelines](CONTRIBUTING.md)

---

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/AnimeshShaw/AppSec-Atlas.git
cd appsec-atlas
```

### 2. Create a Branch

```bash
git checkout -b add-api-security-guide
# or
git checkout -b fix/owasp-top-10-typos
```

### 3. Make Your Changes

Follow the [Guide Standards](#guide-standards) below.

### 4. Commit Your Changes

```bash
git add .
git commit -m "docs: add API security guide - GraphQL section"
```

**Commit Message Format:**
- `docs:` — Guide additions or updates
- `fix:` — Corrections to existing content
- `feat:` — New features (website, tooling)
- `chore:` — Maintenance tasks

### 5. Submit a Pull Request

Push to your fork and open a PR against the `main` branch. Fill out the PR template completely.

---

## Guide Standards

Every guide in AppSec Atlas must meet these standards:

### Structure
Every guide must follow this structure:
```
module-name/
├── README.md           ← Overview, prerequisites, what you will learn
├── 01-introduction.md
├── 02-core-concepts.md
├── 03-attack-scenarios.md
├── 04-defenses.md
├── 05-tools.md
├── 06-labs.md
├── 07-references.md
└── assets/
```

### Content Requirements
- **No theory-only content.** Every concept must have a practical code example.
- **Attack scenarios must include fixes.** Never show a vulnerability without also showing the correct mitigation.
- **Code must be tested.** All code examples must be working and verified.
- **Be specific.** "Use a WAF" is not actionable. "Configure Nginx rate limiting as follows..." is.
- **Cite your sources.** Link to CVEs, papers, official documentation.
- **Stay current.** Include the year when referencing versions or dates.

### Code Example Standards
```python
# BAD - what NOT to do (label clearly)
query = "SELECT * FROM users WHERE id = " + user_input  # SQL Injection!

# GOOD - the correct approach
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_input,))
```

### Formatting
- Use **sentence case** for headers (not Title Case For Every Word)
- Code blocks must specify the language: ` ```python `, ` ```bash `, etc.
- Keep line length under 120 characters in prose
- Use tables for comparisons, not long lists

---

## Submitting a Pull Request

### PR Checklist
- [ ] I have read the [Guide Standards](#guide-standards)
- [ ] All code examples are tested and working
- [ ] I have followed the standard module structure
- [ ] I have cited sources in `07-references.md`
- [ ] I have not included any proprietary or copyrighted content without permission
- [ ] My contribution is licensed under CC BY 4.0

### PR Title Format
```
docs(section): short description of the guide or change

Examples:
docs(ai-ml): add LLM prompt injection guide
fix(owasp): correct SQL injection example for Python 3.12
docs(cloud): add AWS S3 bucket security section
```

---

## Review Process

1. **Automated checks** run first (link checker, spellcheck, Docusaurus build)
2. **Technical review** — A maintainer or core contributor reviews for accuracy
3. **Editorial review** — Clarity, formatting, and standards check
4. **Merge** — Usually within 7 days for good-quality PRs

We will always explain any requested changes clearly. Our goal is to help contributors succeed, not gatekeep.

---

## Recognition

All contributors are credited in:
- [CONTRIBUTORS.md](community/CONTRIBUTORS.md) — The Hall of Fame
- The website's Contributors page
- Release notes when their guide ships

---

## Questions?

- 💬 Open a [GitHub Discussion](https://github.com/AnimeshShaw/AppSec-Atlas/discussions)
- 🎮 Join our [Discord](https://discord.gg/appsecatlas)
- 📧 Email: contribute@appsecatlas.com

Thank you for making security knowledge more accessible! 🔐
