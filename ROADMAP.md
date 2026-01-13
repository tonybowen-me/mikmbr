# mikmbr Expansion Roadmap

## Completed Features

### ✅ v1.1 - Enhanced Verbosity (Option 1)
- Verbose output mode with `--verbose` flag
- CWE IDs, OWASP mappings, and references
- Code snippets in findings
- Confidence levels (HIGH/MEDIUM/LOW)

### ✅ v1.2 - Additional Detection Rules (Option 2)
- INSECURE_DESERIALIZATION (pickle, yaml)
- PATH_TRAVERSAL (unsafe file paths)
- INSECURE_RANDOM (random for security)
- REGEX_DOS (catastrophic backtracking)
- XXE (XML external entities)

### ✅ v1.3 - Smart Secret Detection (Option 3)
- Entropy-based secret detection
- Known pattern matching (AWS, GitHub, Slack, etc.)
- Variable name-based detection
- Test file auto-exclusion
- Placeholder filtering

### ✅ v1.4 - Configuration System (Option 4)
- YAML-based configuration (`.mikmbr.yaml`)
- Rule enable/disable and severity overrides
- Secret detection tuning (entropy thresholds)
- Custom placeholders and path exclusions
- Output and scan configuration
- Automatic config discovery
- CLI overrides

## Immediate Enhancements (v1.5+)

### 1. More Verbose Output Options

**CLI Flags:**
- `--verbose` / `-v`: Show additional context (code snippets, CWE IDs, OWASP references)
- `--explain`: Detailed explanation of each finding with examples
- `--confidence`: Show confidence level (HIGH/MEDIUM/LOW) for each detection
- `--context N`: Show N lines of code context around each finding

**Enhanced Finding Model:**
```python
@dataclass
class Finding:
    file: str
    line: int
    rule_id: str
    severity: Severity
    confidence: Confidence  # NEW
    message: str
    remediation: str
    cwe_id: str            # NEW: CWE-89, CWE-78, etc.
    owasp_category: str    # NEW: A03:2021-Injection
    code_snippet: str      # NEW: Actual vulnerable code
    references: List[str]  # NEW: Links to docs
```

### 2. Additional Detection Rules

**Security Rules:**
- `INSECURE_DESERIALIZATION`: pickle.loads(), yaml.load() without SafeLoader
- `PATH_TRAVERSAL`: os.path.join() with user input, open() with concatenated paths
- `XXE`: XML parsing without secure defaults (defusedxml)
- `SSRF`: requests.get() with user-controlled URLs
- `OPEN_REDIRECT`: redirect() with unvalidated user input
- `INSECURE_RANDOM`: random.random() for security purposes instead of secrets module
- `TIMING_ATTACK`: String comparison with == for secrets/tokens
- `INSECURE_TEMP_FILE`: tempfile usage without proper cleanup
- `MISSING_CRYPTO_SALT`: Hashing passwords without salt
- `WEAK_TLS`: SSL/TLS version checks
- `REGEX_DOS`: Catastrophic backtracking patterns
- `LOG_INJECTION`: Logging user input without sanitization

**Code Quality Rules:**
- `BARE_EXCEPT`: except: without exception type
- `ASSERT_IN_PROD`: assert statements (removed in -O mode)
- `MUTABLE_DEFAULT_ARG`: def foo(x=[]):
- `UNUSED_IMPORTS`: Imported but never used

### 3. Enhanced SQL Injection Detection

**Current:** Basic string concatenation
**Enhanced:**
- Track variable taint flow (if var comes from user input)
- Detect ORM query construction (Django, SQLAlchemy)
- Check for proper escaping functions
- Detect second-order SQL injection patterns

### 4. Smarter Secret Detection

**Pattern Improvements:**
- Entropy analysis (high-entropy strings likely secrets)
- Known secret formats (AWS keys, GitHub tokens, JWT)
- Git history scanning (detect committed secrets)
- .env file checking
- Base64-encoded secrets

**Exclude False Positives:**
- Test fixtures
- Example/placeholder values
- Comments with examples

## Medium-Term Features (v1.2-1.3)

### 5. Configuration File

**`.mikmbr.yaml`:**
```yaml
rules:
  enabled:
    - DANGEROUS_EXEC
    - SQL_INJECTION
  disabled:
    - WEAK_CRYPTO

  HARDCODED_SECRET:
    exclude_patterns:
      - test_*
      - */tests/*
    custom_patterns:
      - "CUSTOM_API_.*"

severity_threshold: MEDIUM  # Only report MEDIUM and above

output:
  format: json
  verbose: true
  show_context: 3

ignore:
  paths:
    - "*/migrations/*"
    - "*/vendor/*"
  files:
    - "legacy_code.py"
```

### 6. Data Flow Analysis (Taint Tracking)

**Basic Taint Analysis:**
```python
# Track if data originates from untrusted source
user_input = request.GET['id']  # TAINTED
safe_id = int(user_input)        # SANITIZED
query = f"SELECT * FROM users WHERE id = {safe_id}"  # OK

user_name = request.GET['name']  # TAINTED
query = f"SELECT * FROM users WHERE name = '{user_name}'"  # VULNERABLE!
```

**Implementation:**
- Track taint sources: request.*, input(), sys.argv, os.environ
- Track sanitizers: int(), validate_*(), escape_*()
- Track sinks: execute(), system(), eval()
- Report only if tainted data reaches sink unsanitized

### 7. Dependency Scanning

**Check for vulnerable dependencies:**
```bash
mikmbr scan --check-deps
```

**Features:**
- Parse requirements.txt, Pipfile, pyproject.toml
- Check against vulnerability databases (OSV, PyPI Advisory)
- Report CVEs with severity and fix versions
- Suggest dependency updates

### 8. Multi-Language Support

**Phase 1: JavaScript/TypeScript**
- eval(), Function constructor
- Dangerous innerHTML assignments
- SQL injection in Node.js
- Command injection in child_process

**Phase 2: Go, Java, etc.**

## Advanced Features (v2.0+)

### 9. Interactive Mode

```bash
mikmbr scan --interactive
```

**Features:**
- Show finding
- Offer to apply fix automatically
- Allow user to mark as false positive
- Generate suppression comments

### 10. CI/CD Integration

**GitHub Actions:**
```yaml
- name: Run mikmbr
  uses: mikmbr/action@v1
  with:
    fail_on: high
    format: sarif
```

**Exit Codes:**
- 0: Clean
- 1: Issues found below threshold
- 2: Issues found above threshold (fail build)

**SARIF Output:** For GitHub Code Scanning integration

### 11. Fix Suggestions & Auto-Remediation

```bash
mikmbr scan --fix
```

**Auto-fix examples:**
```python
# Before
result = eval(user_input)

# After (with --fix)
import ast
result = ast.literal_eval(user_input)
```

### 12. IDE Integration

**VS Code Extension:**
- Real-time scanning as you type
- Inline warnings with quick fixes
- Right-click "Scan for vulnerabilities"

**PyCharm/IntelliJ Plugin**

### 13. Web Dashboard

**Features:**
- Historical trend analysis
- Team/project comparisons
- Rule effectiveness metrics
- False positive management

### 14. Custom Rules DSL

**Allow users to define rules:**
```yaml
rules:
  - id: CUSTOM_DANGEROUS_FUNC
    pattern: |
      dangerous_function($...ARGS)
    message: "Avoid dangerous_function"
    severity: HIGH
```

### 15. Performance Optimizations

**For large codebases:**
- Parallel file processing
- Incremental scanning (only changed files)
- Caching AST parsing results
- Skip binary/generated files automatically

### 16. Reporting & Metrics

```bash
mikmbr report --format html > report.html
```

**Include:**
- Executive summary
- Breakdown by severity
- Breakdown by rule type
- Trend over time
- Compliance mapping (OWASP Top 10, CWE Top 25)

## Implementation Priority

### Quick Wins (1-2 days each):
1. ✅ Add `--verbose` flag with code snippets
2. ✅ Add CWE/OWASP mappings to findings
3. ✅ Add confidence levels
4. ✅ Implement 5 new rules (INSECURE_DESERIALIZATION, PATH_TRAVERSAL, etc.)
5. ✅ Configuration file support

### Medium Effort (1 week each):
6. Enhanced secret detection with entropy
7. Basic dependency scanning
8. SARIF output format
9. Auto-fix for simple cases
10. Taint tracking (basic)

### Large Projects (2-4 weeks each):
11. Advanced taint analysis
12. Multi-language support
13. IDE extensions
14. Web dashboard

## Community & Ecosystem

- **Plugin system** for custom rules
- **Rule marketplace** for sharing detection rules
- **Integration with security tools** (Snyk, Dependabot, etc.)
- **Training mode** to help developers learn secure coding

---

## Getting Started with Expansion

Pick one area and let's implement it! Recommended starting points:

1. **More verbose output** - Quick win, immediate value
2. **5 new detection rules** - Expands coverage significantly
3. **Configuration file** - Enables customization
4. **Dependency scanning** - High value for security teams
