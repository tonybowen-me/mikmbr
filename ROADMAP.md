# Mikmbr Development Roadmap

## Completed Features ✅

### v1.1 - Enhanced Verbosity
- Verbose output mode with `--verbose` flag
- CWE IDs, OWASP mappings, and references
- Code snippets in findings
- Confidence levels (HIGH/MEDIUM/LOW)

### v1.2 - Additional Detection Rules
- INSECURE_DESERIALIZATION (pickle, yaml)
- PATH_TRAVERSAL (unsafe file paths)
- INSECURE_RANDOM (random for security)
- REGEX_DOS (catastrophic backtracking)
- XXE (XML external entities)

### v1.3 - Smart Secret Detection
- Entropy-based secret detection
- Known pattern matching (AWS, GitHub, Slack, etc.)
- Variable name-based detection
- Test file auto-exclusion
- Placeholder filtering

### v1.4 - Configuration System
- YAML-based configuration (`.mikmbr.yaml`)
- Rule enable/disable and severity overrides
- Secret detection tuning (entropy thresholds)
- Custom placeholders and path exclusions
- Output and scan configuration
- Automatic config discovery

### v1.5 - Extended Coverage
- SSRF (Server-Side Request Forgery)
- Open Redirect vulnerability detection
- Log Injection detection
- Template Injection (SSTI) detection
- Timing Attack detection
- Bare Except detection
- Debug Code detection

### v1.6 - Production Features
- **Inline Suppression System** - Mark false positives with comments
- **Framework-Specific Rules** - Django, Flask, FastAPI detection (17 checks)
- **SARIF Output Format** - GitHub Code Scanning integration

---

## Planned Features

### High Priority

#### 1. Exit Code Configuration
```bash
mikmbr scan . --fail-on high  # Exit 1 only on HIGH+ findings
mikmbr scan . --fail-on critical  # Exit 1 only on CRITICAL
```

**Why:** Essential for CI/CD pipelines to control build failures

#### 2. Basic Taint Tracking
```python
# Track data flow to reduce false positives
user_id = request.GET['id']
safe_id = int(user_id)  # Sanitized
query = f"SELECT * FROM users WHERE id = {safe_id}"  # Should NOT flag
```

**Why:** Dramatically reduces false positives

**Implementation:**
- Track 1-2 hops for common sanitizers
- Simple single-file analysis
- Common patterns: int(), str.isdigit(), validate_*()

#### 3. Dependency Vulnerability Scanning
```bash
mikmbr scan . --check-deps
```

**Features:**
- Parse requirements.txt, Pipfile, pyproject.toml
- Query OSV API (free, no auth needed)
- Report known CVEs with fixes
- Suggest version upgrades

**Why:** Complete security picture (code + dependencies)

### Medium Priority

#### 4. Suppression Reporting
```bash
mikmbr scan . --show-suppressions
```

**Output:**
```
Active Findings (3):
[HIGH] src/app.py:12 - SQL_INJECTION
...

Suppressed Findings (2):
[HIGH] src/config.py:5 - HARDCODED_SECRET (reason: test key)
[MED] src/legacy.py:105 - INSECURE_RANDOM (block disabled)
```

**Why:** Audit trail for suppressed findings

#### 5. Code Context Lines
```bash
mikmbr scan . --context 3  # Show 3 lines before/after
```

**Output:**
```
[HIGH] src/app.py:12
  10 | def process_input(data):
  11 |     # Process user input
> 12 |     result = eval(data)  # DANGEROUS!
  13 |     return result
  14 |
```

**Why:** Better UX without opening files

#### 6. Auto-Fix Suggestions (Interactive)
```bash
mikmbr scan . --interactive
```

**Features:**
- Show finding
- Offer to apply fix automatically
- Allow marking as false positive
- Generate suppression comments

**Why:** Saves developer time

#### 7. Pre-commit Hook Template
Create easy-to-use pre-commit integration:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/tonybowen-me/Mikmbr
    rev: v1.6.0
    hooks:
      - id: mikmbr
```

**Why:** Prevent vulnerabilities before commit

### Long-term

#### 8. Advanced Taint Tracking
- Multi-hop data flow analysis
- Cross-function tracking
- Track through framework abstractions (Django ORM, etc.)

**Why:** Industry-leading accuracy

#### 9. Multi-Language Support

**Phase 1: JavaScript/TypeScript**
- eval(), Function constructor
- Dangerous innerHTML assignments
- SQL injection in Node.js
- Command injection in child_process

**Phase 2: Go, Java, Rust**

**Why:** Expand addressable market

#### 10. IDE Extensions

**VS Code Extension:**
- Real-time scanning as you type
- Inline warnings with quick fixes
- Right-click "Scan for vulnerabilities"

**PyCharm/IntelliJ Plugin**

**Why:** Catch issues earlier in dev cycle

#### 11. GitHub Action
```yaml
- name: Run mikmbr
  uses: mikmbr/action@v1
  with:
    fail_on: high
    format: sarif
```

**Why:** One-click setup for GitHub repos

#### 12. Custom Rules DSL
```yaml
# Allow users to define custom rules
rules:
  - id: CUSTOM_DANGEROUS_FUNC
    pattern: dangerous_function($...ARGS)
    message: "Avoid dangerous_function"
    severity: HIGH
```

**Why:** Extensibility for org-specific patterns

#### 13. Performance Optimizations
- Parallel file processing
- Incremental scanning (only changed files)
- Caching AST parsing results
- Skip binary/generated files automatically

**Why:** Handle enterprise-scale codebases

#### 14. Web Dashboard
- Historical trend analysis
- Team/project comparisons
- Rule effectiveness metrics
- False positive management
- Security posture scoring

**Why:** SaaS revenue, enterprise features

---

## Feature Prioritization

### Next 3 Features to Build:
1. **Exit code configuration** - Quick win, high CI/CD value
2. **Dependency scanning** - High impact, differentiator
3. **Basic taint tracking** - Reduces false positives significantly

### Not Building Yet:
- CI/CD (user doesn't want yet)
- Web dashboard (too early)
- Multi-language (focus on Python first)

---

## Community Requests

Track user requests here as they come in:
- (None yet - pre-release)

---

## Technical Debt

### Current Limitations to Address:
1. No data-flow analysis (can't track validated inputs)
2. Framework detection is pattern-based (not semantic)
3. No tests for v1.6 features yet
4. No benchmark data documented
5. Documentation still has some inconsistencies

### Breaking Changes to Consider:
- (None planned for v2.0 yet)

---

**Updated:** 2026-01-14 (v1.6.0)
