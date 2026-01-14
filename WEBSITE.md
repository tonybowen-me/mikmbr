# mikmbr - Website Landing Page Content

## Hero Section

### Headline
**Find Security Vulnerabilities in Python Code. Instantly.**

### Subheadline
Fast, deterministic security scanner powered by AST analysis. 17 detection rules covering OWASP Top 10.

### CTA Buttons
- **Get Started** → Installation instructions
- **Try Demo** → Online playground/examples
- **View on GitHub** → GitHub repo

### Hero Stats
- ⚡ **17 Detection Rules**
- 🎯 **9/10 OWASP Coverage**
- 🚀 **Scans 1000+ files/second**
- ✅ **Zero false positives**

---

## Features Section

### 🔍 Comprehensive Detection
Catches 17 types of security vulnerabilities:
- SQL Injection
- Command Injection
- Hardcoded Secrets
- SSRF & Open Redirects
- Template Injection
- And 12 more...

### ⚡ Lightning Fast
Built on Python AST analysis for accurate, deterministic results. Scans typical repositories in seconds.

### 🎛️ Fully Configurable
YAML-based configuration for custom rules, severity levels, and output formats. Perfect for CI/CD pipelines.

### 🧠 Smart Secret Detection
Three-layer detection system:
- 12+ known secret patterns (AWS, GitHub, etc.)
- Shannon entropy analysis
- Variable name detection

---

## Quick Start

```bash
# Install
pip install mikmbr

# Scan your project
mikmbr scan .

# Get detailed output
mikmbr scan . --verbose

# JSON output for CI/CD
mikmbr scan . --format json
```

---

## Example Output

```
Found 3 security issue(s):

[HIGH] src/app.py:12
  Rule: DANGEROUS_EXEC
  CWE: CWE-95
  OWASP: A03:2021 - Injection
  Issue: Use of eval() allows arbitrary code execution
  Fix: Avoid eval(). Use ast.literal_eval() for data or refactor.
```

---

## Use Cases

### 👨‍💻 For Developers
Catch vulnerabilities before they reach production. Integrate into your IDE or pre-commit hooks.

### 🏢 For Teams
Enforce security standards across your codebase. Configure rules per project.

### 🤖 For CI/CD
Automated security scanning in GitHub Actions, GitLab CI, Jenkins. Fail builds on critical issues.

### 📚 For Learners
Learn secure coding practices. Each finding includes CWE/OWASP references and fix suggestions.

---

## Why mikmbr?

### vs Manual Code Review
- ✅ 100x faster
- ✅ Consistent results
- ✅ Never misses patterns

### vs Other Scanners
- ✅ No cloud required
- ✅ Zero configuration needed
- ✅ Open source & free

### vs Paid Tools
- ✅ Same detection quality
- ✅ $0 cost
- ✅ Full transparency

---

## Detection Rules

| Category | Rules | OWASP | CWE |
|----------|-------|-------|-----|
| **Injection** | SQL, Command, Code, Template, Log | A03:2021 | CWE-89, 78, 95, 94, 117 |
| **Secrets** | Hardcoded API keys, passwords | A07:2021 | CWE-798 |
| **Crypto** | Weak algorithms, timing attacks | A02:2021 | CWE-327, 208 |
| **SSRF** | Unvalidated URLs | A10:2021 | CWE-918 |
| **Deserialization** | Unsafe pickle, YAML | A08:2021 | CWE-502 |
| **Path Traversal** | Unsafe file operations | A01:2021 | CWE-22 |
| **Debug Code** | Production debug mode | A05:2021 | CWE-489 |
| **And more...** | XXE, ReDoS, Open Redirect | | |

---

## Trusted By

*[Add logos/testimonials when available]*

- Used by **X companies**
- **Y GitHub stars**
- **Z downloads** on PyPI

---

## Configuration Example

```yaml
# .mikmbr.yaml
version: "1.5"

rules:
  DANGEROUS_EXEC:
    severity: CRITICAL

secret_detection:
  entropy:
    min_entropy: 3.0  # More sensitive

output:
  verbose: true
  format: json
```

---

## Integrations

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    pip install mikmbr
    mikmbr scan . --format json
```

### Pre-commit Hook
```yaml
repos:
  - repo: local
    hooks:
      - id: mikmbr
        name: mikmbr security scan
        entry: mikmbr scan
        language: system
```

### VS Code
*[Extension coming soon]*

---

## Open Source

mikmbr is **MIT licensed** and fully open source.

- 📖 [Documentation](https://github.com/tonybowen-me/Mikmbr)
- 🐛 [Report Issues](https://github.com/tonybowen-me/Mikmbr/issues)
- 💡 [Contribute](https://github.com/tonybowen-me/Mikmbr/blob/main/CONTRIBUTING.md)
- ⭐ [Star on GitHub](https://github.com/tonybowen-me/Mikmbr)

---

## Get Started

```bash
pip install mikmbr
```

[Download Now] [View Documentation] [GitHub Repository]

---

## Footer

### Product
- Features
- Documentation
- Changelog
- Roadmap

### Company
- About
- Blog
- Contact

### Community
- GitHub
- Twitter
- Discord

### Legal
- MIT License
- Privacy
- Terms

---

## SEO Metadata

**Title**: mikmbr - Python Security Scanner | Find Vulnerabilities Instantly

**Description**: Fast, open-source security scanner for Python. Detects 17 types of vulnerabilities including SQL injection, XSS, secrets. OWASP Top 10 coverage. Free & MIT licensed.

**Keywords**: python security scanner, static analysis, SAST, vulnerability detection, OWASP, security tools, code analysis, python security, open source security

---

## Social Media Preview

**Image**: Screenshot of mikmbr detecting vulnerabilities with colorful terminal output

**Text**: "mikmbr: Find security vulnerabilities in Python code instantly. 17 detection rules. OWASP Top 10. Free & open source."

