# Verbose Mode - Enhanced Security Scanning Output

## What's New in v1.1

We've significantly enhanced mikmbr with **verbose mode** (`--verbose` or `-v`), which provides comprehensive security intelligence for each finding.

## Enhanced Finding Information

### Standard Output (default)
```
[HIGH] test.py:8
  Rule: DANGEROUS_EXEC
  Issue: Use of eval() allows arbitrary code execution
  Fix: Avoid eval(). Use safer alternatives like ast.literal_eval()
```

### Verbose Output (`--verbose`)
```
[HIGH] test.py:8
  Rule: DANGEROUS_EXEC
  Confidence: HIGH
  CWE: CWE-95
  OWASP: A03:2021 - Injection
  Issue: Use of eval() allows arbitrary code execution
  Fix: Avoid eval(). Use safer alternatives like ast.literal_eval()
  Code:
    >>> result = eval("1 + 1")
  References:
    - https://cwe.mitre.org/data/definitions/95.html
    - https://owasp.org/Top10/A03_2021-Injection/
    - https://docs.python.org/3/library/ast.html#ast.literal_eval
```

## New Metadata Fields

### 1. Confidence Level
Indicates how certain we are about the detection:
- **HIGH**: Definitely a security issue
- **MEDIUM**: Likely an issue, may have false positives
- **LOW**: Possible issue, needs human review

### 2. CWE ID (Common Weakness Enumeration)
Industry-standard vulnerability classification:
- CWE-78: OS Command Injection
- CWE-89: SQL Injection
- CWE-95: Code Injection (eval/exec)
- CWE-327: Broken Cryptography
- CWE-798: Hardcoded Credentials

### 3. OWASP Top 10 Category
Maps to OWASP Top 10 2021:
- A02:2021 - Cryptographic Failures
- A03:2021 - Injection
- A07:2021 - Identification and Authentication Failures

### 4. Code Snippet
Shows the actual vulnerable line with context:
- `>>>` marks the exact vulnerable line
- Helps quickly identify the issue without opening the file

### 5. References
Educational links for learning more:
- CWE definition and examples
- OWASP documentation
- Python security best practices
- Framework-specific guides

## Usage Examples

### Basic Scan (no verbose)
```bash
mikmbr scan myproject/
```

### Verbose Scan
```bash
mikmbr scan myproject/ --verbose
# or
mikmbr scan myproject/ -v
```

### Verbose with JSON Output
```bash
mikmbr scan myproject/ --verbose --format json
```

## Complete Metadata by Rule

### DANGEROUS_EXEC
- **CWE**: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
- **OWASP**: A03:2021 - Injection
- **Confidence**: HIGH
- **References**: CWE-95, OWASP Injection, ast.literal_eval docs

### COMMAND_INJECTION
- **CWE**: CWE-78 (OS Command Injection)
- **OWASP**: A03:2021 - Injection
- **Confidence**: HIGH
- **References**: CWE-78, OWASP Injection, subprocess security

### SQL_INJECTION
- **CWE**: CWE-89 (SQL Injection)
- **OWASP**: A03:2021 - Injection
- **Confidence**: MEDIUM (heuristic-based)
- **References**: CWE-89, OWASP Injection, SQL Injection Prevention

### WEAK_CRYPTO
- **CWE**: CWE-327 (Use of Broken Cryptographic Algorithm)
- **OWASP**: A02:2021 - Cryptographic Failures
- **Confidence**: HIGH
- **References**: CWE-327, OWASP Crypto Failures, hashlib docs

### HARDCODED_SECRET
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
- **OWASP**: A07:2021 - Identification and Authentication Failures
- **Confidence**: MEDIUM (pattern-based)
- **References**: CWE-798, OWASP Auth Failures, Secrets Management

## Benefits of Verbose Mode

### For Developers
- **Faster Understanding**: See the vulnerable code immediately
- **Learn Security**: Follow references to understand why it's dangerous
- **Context**: Confidence levels help prioritize fixes

### For Security Teams
- **Compliance**: CWE/OWASP mappings for reporting
- **Risk Assessment**: Severity + Confidence = better prioritization
- **Documentation**: References for explaining issues to developers

### For CI/CD
- **Detailed Logs**: Full context in build logs
- **JSON Format**: Machine-readable with all metadata
- **Audit Trail**: Complete vulnerability information

## JSON Output Example

```json
{
  "findings": [
    {
      "file": "test.py",
      "line": 8,
      "rule_id": "DANGEROUS_EXEC",
      "severity": "HIGH",
      "confidence": "HIGH",
      "message": "Use of eval() allows arbitrary code execution",
      "remediation": "Avoid eval(). Use safer alternatives...",
      "cwe_id": "CWE-95",
      "owasp_category": "A03:2021 - Injection",
      "code_snippet": ">>> result = eval(\"1 + 1\")",
      "references": [
        "https://cwe.mitre.org/data/definitions/95.html",
        "https://owasp.org/Top10/A03_2021-Injection/",
        "https://docs.python.org/3/library/ast.html#ast.literal_eval"
      ]
    }
  ],
  "total": 1
}
```

## Testing

Run the demos to see verbose mode in action:

```bash
# Standard demo
python demo.py

# Verbose demo
python demo_verbose.py

# Full CLI test
py -m mikmbr.cli scan tests/fixtures/vulnerable_code.py --verbose
```

## What's Next?

Future enhancements planned:
- Context lines configuration (`--context N`)
- Severity filtering (`--min-severity HIGH`)
- Custom output templates
- HTML report generation
- IDE integration with inline tooltips

---

**Try it now**: `mikmbr scan --verbose <path>`
