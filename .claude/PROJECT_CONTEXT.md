# Mikmbr Project Context

**Last Updated:** 2026-01-14
**Current Version:** v1.6.0 (unreleased)
**Status:** Active development, pre-publication

---

## Project Overview

**Name:** Mikmbr (pronounced "mik-m-ber")
**Type:** Python security scanner / SAST tool
**Purpose:** Fast, deterministic security vulnerability detection for Python code
**Target Users:** Python developers, security teams, CI/CD pipelines
**Unique Selling Points:**
- Framework-specific rules (Django, Flask, FastAPI)
- Zero configuration required
- Fully offline operation
- GitHub Code Scanning integration via SARIF
- Educational approach with detailed remediation

---

## Architecture

### Core Components

```
src/mikmbr/
├── cli.py                    # CLI entry point with argparse
├── scanner.py                # Main orchestration - scans files/dirs
├── models.py                 # Data models (Finding, Severity, Confidence)
├── formatters.py             # Output formatters (human, json, sarif)
├── config.py                 # YAML configuration system
├── rules/                    # Detection rules (25 total)
│   ├── base.py              # Abstract Rule class
│   ├── dangerous_exec.py    # eval(), exec() detection
│   ├── command_injection.py # os.system(), subprocess
│   ├── sql_injection.py     # SQL string concatenation
│   ├── hardcoded_secrets.py # Smart secret detection (entropy + patterns)
│   ├── weak_crypto.py       # MD5, SHA1 usage
│   ├── insecure_deserialization.py  # pickle, yaml
│   ├── path_traversal.py    # Unsafe file operations
│   ├── insecure_random.py   # random for security
│   ├── regex_dos.py         # Catastrophic backtracking
│   ├── xxe.py              # XML External Entity
│   ├── ssrf.py             # Server-Side Request Forgery
│   ├── open_redirect.py    # Unvalidated redirects
│   ├── log_injection.py    # Unsanitized logs
│   ├── template_injection.py # SSTI
│   ├── timing_attack.py    # Non-constant-time comparisons
│   ├── bare_except.py      # Catch-all exceptions
│   ├── debug_code.py       # Debug mode, breakpoints
│   ├── weak_password_hash.py # Weak password hashing
│   ├── insecure_cookie.py  # Missing cookie flags
│   ├── jwt_security.py     # JWT vulnerabilities
│   ├── session_security.py # Session management
│   ├── django_security.py  # Django-specific (NEW v1.6)
│   ├── flask_security.py   # Flask-specific (NEW v1.6)
│   └── fastapi_security.py # FastAPI-specific (NEW v1.6)
├── utils/
│   ├── secret_detection.py  # Entropy calculation, pattern matching
│   └── suppression.py       # Inline suppression parser (NEW v1.6)
└── formatters/
    └── sarif.py             # SARIF 2.1.0 formatter (NEW v1.6)
```

### Data Flow

1. **CLI** (`cli.py`) parses arguments
2. **Config** loads `.mikmbr.yaml` if present
3. **Scanner** (`scanner.py`) orchestrates:
   - Finds all `.py` files recursively
   - Filters based on config (exclude patterns, file size)
   - For each file:
     - Reads source code
     - Parses suppression comments (NEW v1.6)
     - Parses AST with Python's `ast` module
     - Runs all enabled rules
     - Filters suppressed findings (NEW v1.6)
     - Applies severity overrides from config
4. **Formatters** convert findings to output format
5. **CLI** prints results and exits with appropriate code

### AST-Based Detection

**Core Principle:** Parse Python source into Abstract Syntax Tree, walk tree to find vulnerable patterns.

**Example:**
```python
# Source code
result = eval(user_input)

# AST representation
Call(
  func=Name(id='eval'),
  args=[Name(id='user_input')]
)

# Rule matches: Call node with func.id == 'eval'
```

**Benefits:**
- Zero false positives from formatting
- Works with any valid Python syntax
- Fast (single pass)
- No code execution needed

---

## Current Feature Set (v1.6.0)

### Detection Rules (25 Total)

**By Severity:**
- **CRITICAL (1):** Template Injection
- **HIGH (10):** Code/Command/SQL Injection, SSRF, Path Traversal, Hardcoded Secrets, Debug Code, Django/Flask security issues
- **MEDIUM (11):** Deserialization, Open Redirect, Log Injection, Timing Attacks, Weak Crypto, Insecure Random, Cookie/CORS/Session issues
- **LOW (3):** Bare Except, ReDoS, Missing Auth (low confidence)

**By Category:**
- **Core Rules (21):** General Python security
- **Framework Rules (17):** Django (6), Flask (6), FastAPI (5)

**OWASP Coverage:** 9/10 OWASP Top 10 2021 categories

### Configuration System

**File:** `.mikmbr.yaml` (auto-discovered by walking up directory tree)

**Features:**
- Enable/disable rules
- Override severity levels
- Configure secret detection (entropy thresholds, custom patterns)
- Set output format and verbosity
- Exclude paths/files
- Configure scanning behavior (file size limits, include patterns)

**Example:**
```yaml
version: "1.6"

rules:
  SQL_INJECTION: true
  BARE_EXCEPT: false

  HARDCODED_SECRET:
    severity: HIGH

secret_detection:
  entropy:
    min_entropy: 3.0

output:
  format: sarif
  verbose: true

scan:
  exclude_patterns:
    - "*/tests/*"
    - "*/migrations/*"
  max_file_size_kb: 500
```

### Output Formats (3)

1. **Human** (default): Readable terminal output
2. **JSON**: Machine-readable, structured data
3. **SARIF**: GitHub Code Scanning integration (NEW v1.6)

### Inline Suppression (NEW v1.6)

**Suppress all rules:**
```python
api_key = "test_key"  # mikmbr: ignore
```

**Suppress specific rules:**
```python
query = f"SELECT * FROM data WHERE id = {safe_id}"  # mikmbr: ignore[SQL_INJECTION]
```

**Multiple rules:**
```python
code = "test"  # mikmbr: ignore[RULE1, RULE2]
```

**Block suppression:**
```python
# mikmbr: disable
# Everything here is suppressed
api_key = "test"
password = "pass"
# mikmbr: enable
```

**Previous line suppression:**
```python
# mikmbr: ignore[HARDCODED_SECRET]
api_key = "sk_test_123"
```

**Implementation:** Regex-based parser in `utils/suppression.py`, integrated into scanner

### Framework-Specific Rules (NEW v1.6)

**Django (6 rules):**
- `Model.objects.raw()` without parameterization → SQL injection
- `mark_safe()` usage → XSS risk
- `QuerySet.extra()` → SQL injection
- `DEBUG = True` → Information disclosure
- Empty/wildcard `ALLOWED_HOSTS` → Host header attacks
- Hardcoded `SECRET_KEY` → Session compromise

**Flask (6 rules):**
- `send_file()` with user input → Path traversal
- `render_template_string()` → SSTI
- Hardcoded `app.secret_key` → Session compromise
- `app.debug = True` → Information disclosure
- `set_cookie()` without secure flags → Cookie theft
- Wildcard CORS → CSRF attacks

**FastAPI (5 rules):**
- `dict` or `Any` parameters → Input validation bypass
- `FileResponse` with user path → Path traversal
- `HTMLResponse` with user content → XSS
- Wildcard CORS → CSRF attacks
- Missing authentication on endpoints → Unauthorized access

**Detection Method:** Pattern matching on imports, decorators, and API usage

### SARIF Output (NEW v1.6)

**Standard:** SARIF 2.1.0 (Static Analysis Results Interchange Format)

**Features:**
- Full GitHub Code Scanning integration
- CWE and OWASP tagging
- Severity level mapping (HIGH→error, MEDIUM→warning, LOW→note)
- Optional code snippets
- Relative file paths for portability

**Usage:**
```bash
mikmbr scan . --format sarif > results.sarif

# Upload to GitHub via Actions
- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

**Benefits:**
- Findings appear in GitHub PRs as annotations
- Security tab shows all vulnerabilities
- Works with VS Code SARIF Viewer
- Industry-standard format

---

## Development History

### Version Timeline

**v1.0.0** (2025-01-13) - Initial Release
- 5 core rules
- Human and JSON output
- Basic CLI

**v1.1.0** (2025-01-13) - Verbose Mode
- Added CWE IDs, OWASP mappings
- Code snippets in output
- Confidence levels

**v1.2.0** (2025-01-13) - Additional Rules
- Added 5 rules: Deserialization, Path Traversal, Insecure Random, ReDoS, XXE
- Total: 10 rules

**v1.3.0** (2025-01-13) - Smart Secrets
- Three-layer secret detection (patterns, entropy, variable names)
- 12+ known secret patterns
- Test file auto-exclusion

**v1.4.0** (2025-01-13) - Configuration System
- YAML-based configuration
- Auto-discovery of config files
- Rule enable/disable

**v1.5.0** (2025-01-13) - Extended Coverage
- Added 7 rules: SSRF, Open Redirect, Log Injection, SSTI, Timing Attack, Bare Except, Debug Code
- Total: 17 rules
- 9/10 OWASP coverage

**v1.6.0** (2026-01-14) - **CURRENT** (unreleased)
- **Inline suppression system**
- **Framework-specific rules** (Django, Flask, FastAPI)
- **SARIF output format**
- Total: 25 rules (21 core + 17 framework-specific, with 13 overlap)

### Key Design Decisions

1. **AST-based detection** - Chosen over regex for accuracy and maintainability
2. **Zero configuration** - Works out of box, config is optional
3. **Offline operation** - No cloud dependencies, privacy-first
4. **Educational focus** - Every finding includes remediation guidance
5. **Framework-aware** - Specialized rules beat generic patterns
6. **Suppression-friendly** - Production codebases need escape hatches

---

## Project Status

### Not Yet Done

**Critical for v1.6 release:**
- [ ] Test all new features (suppression, framework rules, SARIF)
- [ ] Update README.md with v1.6 features
- [ ] Update CHANGELOG.md
- [ ] Update pyproject.toml version to 1.6.0
- [ ] Test on real Django/Flask/FastAPI projects
- [ ] Verify SARIF output with GitHub Code Scanning
- [ ] Create demo video/screenshots

**Not implemented yet:**
- CI/CD (GitHub Actions for testing) - User doesn't want this yet
- PyPI publication - Waiting for "super verbose v1"
- Real-world validation - Need to test on popular projects
- Benchmark data - No performance metrics documented
- Comparison with Bandit/Semgrep - Claims but no proof
- Exit code configuration (`--fail-on high`)
- Suppression reporting (`--show-suppressions`)
- Basic taint tracking - Would reduce false positives
- Dependency scanning - Check for vulnerable packages
- IDE extensions - VS Code, PyCharm

### Known Issues

1. **Documentation mismatch** - Many docs still say "17 rules" but code has 25
2. **No tests for new features** - Framework rules, suppression, SARIF need test coverage
3. **False positives** - Framework rules may flag safe code (by design, user can suppress)
4. **No data-flow analysis** - Can't track if input is validated across statements
5. **Framework detection is naive** - Pattern-based, not semantic

---

## File Inventory

### Core Implementation Files
- `src/mikmbr/cli.py` - 93 lines
- `src/mikmbr/scanner.py` - 142 lines (modified for suppression)
- `src/mikmbr/models.py` - 52 lines
- `src/mikmbr/formatters.py` - 86 lines (integrated SARIF)
- `src/mikmbr/config.py` - ~200 lines
- `src/mikmbr/utils/suppression.py` - 119 lines (NEW)
- `src/mikmbr/formatters/sarif.py` - 230 lines (NEW)

### Rule Files (25 rules across 22 files)
- Core rules: 21 files
- Framework rules: 3 files (NEW)

### Test Files
- `tests/test_rules.py`
- `tests/test_scanner.py`
- `tests/test_config.py`
- `tests/test_smart_secrets.py`
- `tests/test_new_rules.py`
- `tests/test_verbose.py`
- `tests/test_suppression.py` (NEW)
- **Missing:** tests for framework rules, SARIF output

### Documentation Files
- `README.md` - Main documentation (needs v1.6 update)
- `CHANGELOG.md` - Version history (needs v1.6 entry)
- `CONFIGURATION.md` - Config guide
- `SMART_SECRETS.md` - Secret detection technical doc
- `V1.5_NEW_RULES.md` - v1.5 rules documentation
- `VERBOSE_MODE.md` - Verbose output guide
- `HOW_IT_WORKS.md` - AST analysis explanation
- `ROADMAP.md` - Future plans
- `DEPLOYMENT_CHECKLIST.md` - Pre-release checklist
- `WEBSITE.md` - Landing page content
- `DEPLOY_RENDER.md` - Website deployment guide
- `SUPPRESSION.md` (NEW)
- `FRAMEWORK_RULES.md` (NEW)
- `SARIF_FORMAT.md` (NEW)
- `V1.6_RELEASE_NOTES.md` (NEW)

### Example Files
- `examples/new_rules_demo.py`
- `examples/secrets_demo.py`
- `examples/framework_vulnerabilities.py` (NEW)

### Demo Files
- `demo.py`
- `demo_all_rules.py`
- `demo_config.py`
- `demo_smart_secrets.py`
- `demo_verbose.py`

### Config Files
- `pyproject.toml` - Package metadata (version: 1.5.0, needs update to 1.6.0)
- `.mikmbr.yaml` - Example configuration
- `.gitignore`
- `LICENSE` - MIT License

### Website
- `website/index.html` - Landing page
- `website/style.css`
- `website/script.js`

---

## Technical Details

### Dependencies

**Runtime:**
- `pyyaml>=6.0` - Configuration parsing

**Development:**
- `pytest>=7.0.0` - Testing
- `pytest-cov>=4.0.0` - Coverage

**Python:** 3.9+ (uses `ast` module, type hints)

### Entry Points

```toml
[project.scripts]
mikmbr = "mikmbr.cli:main"
```

Installed as command-line tool: `mikmbr scan .`

### Exit Codes

- `0` - No issues found
- `1` - Security issues found
- `2` - Error during scanning (syntax errors, file not found, etc.)

### Performance Characteristics

- **Speed:** ~1000 files/second (claimed, not benchmarked)
- **Memory:** <100MB for typical projects (claimed)
- **Scanning:** Single-pass AST analysis
- **Scalability:** No known limits, tested up to 10k files

---

## Competitive Landscape

### Main Competitors

**Bandit:**
- Pros: Mature, widely adopted, good docs
- Cons: Limited framework support, some false positives
- Mikmbr advantage: Better framework rules, suppression system

**Semgrep:**
- Pros: Multi-language, powerful rule language, active development
- Cons: Complex setup, requires writing rules, commercial focus
- Mikmbr advantage: Zero config, Python-focused, free forever

**Pylint:**
- Pros: General-purpose, many checks
- Cons: Not security-focused, noisy, complex config
- Mikmbr advantage: Security-only, clear remediation

### Unique Positioning

"**The only Python security scanner built for web frameworks**"

- First tool with FastAPI-specific security rules
- Best-in-class Django and Flask detection
- GitHub Code Scanning ready out of box
- Zero configuration required
- Educational approach (not just "flag and forget")

---

## User Intent & Vision

### What User Wants

**Short-term:** Add more features and value before publishing
- ✅ Inline suppression (DONE)
- ✅ Framework rules (DONE)
- ✅ SARIF output (DONE)
- Next: More validation, testing, polish

**Not interested in right now:**
- CI/CD setup (too early)
- Publishing to PyPI (waiting for "super verbose v1")

**Long-term vision:**
- Production-ready security scanner for Python web apps
- Used by Django/Flask/FastAPI developers worldwide
- GitHub Code Scanning integration drives adoption
- Eventually: IDE extensions, SaaS offering

### Success Criteria for "Super Verbose v1"

1. **Comprehensive testing** - Works on real projects
2. **Benchmark data** - Documented performance
3. **PyPI package** - Installable with `pip install mikmbr`
4. **CI/CD for project** - Automated testing
5. **Contributing guide** - Lower barrier to contributors
6. **Comparison matrix** - Proof it's better than Bandit/Semgrep
7. **Suppression system** - Production-ready (DONE in v1.6)
8. **Exit code config** - `--fail-on high` for CI
9. **SARIF output** - GitHub integration (DONE in v1.6)
10. **Pre-commit example** - Easy integration

---

## Common Patterns & Conventions

### Code Style

- Type hints throughout
- Docstrings for all public methods
- AST node type checking with `isinstance()`
- Dataclasses for models
- Enums for constants (Severity, Confidence)

### Rule Implementation Pattern

```python
class MyRule(Rule):
    @property
    def rule_id(self) -> str:
        return "RULE_NAME"

    def check(self, tree: ast.AST, source: str, filepath: str) -> List[Finding]:
        findings = []
        for node in ast.walk(tree):
            if self._is_vulnerable(node):
                findings.append(Finding(
                    file=filepath,
                    line=node.lineno,
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    message="Description of issue",
                    remediation="How to fix it",
                    cwe_id="CWE-XXX",
                    owasp_category="AXX:2021 - Category",
                    code_snippet=self.extract_code_snippet(source, node.lineno)
                ))
        return findings
```

### Testing Pattern

```python
def test_rule_detects_vulnerability(tmp_path):
    test_file = tmp_path / "test.py"
    test_file.write_text("vulnerable_code_here")

    scanner = Scanner()
    findings = scanner.scan_file(str(test_file))

    assert len(findings) == 1
    assert findings[0].rule_id == "EXPECTED_RULE"
    assert findings[0].severity == Severity.HIGH
```

### Documentation Pattern

Each feature has:
1. User-facing guide (FEATURE.md)
2. Examples in `examples/`
3. Tests in `tests/`
4. Entry in CHANGELOG.md
5. Mention in README.md

---

## Quick Reference Commands

### Development

```bash
# Install for development
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=mikmbr --cov-report=html

# Scan project itself
python -m mikmbr.cli scan src/

# Test specific feature
python -m mikmbr.cli scan examples/framework_vulnerabilities.py --verbose
```

### User Commands

```bash
# Basic scan
mikmbr scan .

# Verbose output
mikmbr scan . --verbose

# JSON output
mikmbr scan . --format json

# SARIF output
mikmbr scan . --format sarif > results.sarif

# With config
mikmbr scan . --config my-config.yaml
```

---

## Next Steps (Priority Order)

1. **Test new features** - Ensure suppression, framework rules, SARIF work
2. **Update documentation** - README, CHANGELOG for v1.6
3. **Real-world validation** - Test on Django/Flask/FastAPI projects
4. **Fix documentation inconsistencies** - Update rule counts everywhere
5. **Consider next features** - Exit code config, dependency scanning, taint tracking

---

## Notes for Future Claude

- User is building this to publish, not yet published
- Focus is on adding value before release, not on marketing/CI yet
- Framework rules are a key differentiator vs competitors
- Suppression system was essential for production use
- SARIF enables GitHub integration (major adoption driver)
- User will ask for more features - prioritize those that make tool more valuable
- Don't suggest CI/CD unless user asks - they explicitly don't want it yet
- Project renamed from "airisk" to "mikmbr" at some point (check utils/__init__.py comment)

---

**End of Context Document**
