# mikmbr v1.2 - 5 New Detection Rules

## What's New

We've doubled our detection capabilities from 5 to 10 security rules!

## New Rules Summary

### 1. INSECURE_DESERIALIZATION (CWE-502)
**Severity**: HIGH | **Confidence**: HIGH
**OWASP**: A08:2021 - Software and Data Integrity Failures

Detects insecure deserialization vulnerabilities:
- `pickle.loads()` / `pickle.load()` - Can execute arbitrary code
- `yaml.load()` without SafeLoader - Allows code execution

**Why it matters**: Deserializing untrusted data can allow attackers to execute arbitrary code.

**Example Detection**:
```python
# Detected
import pickle
data = pickle.loads(user_data)  # HIGH risk

import yaml
config = yaml.load(file)  # HIGH risk

# Safe alternatives recommended
import json
data = json.loads(user_data)
config = yaml.safe_load(file)
```

---

### 2. PATH_TRAVERSAL (CWE-22)
**Severity**: HIGH/MEDIUM | **Confidence**: MEDIUM/LOW
**OWASP**: A01:2021 - Broken Access Control

Detects path traversal vulnerabilities:
- `open()` with string concatenation
- `os.path.join()` with variables (heuristic)

**Why it matters**: Attackers can use `../../../etc/passwd` to access files outside intended directories.

**Example Detection**:
```python
# Detected
filename = request.GET['file']
file = open("/uploads/" + filename)  # HIGH - concat
path = os.path.join("/uploads", user_file)  # MEDIUM - heuristic

# Safe pattern
from pathlib import Path
base = Path("/uploads")
safe_path = (base / filename).resolve()
if safe_path.is_relative_to(base):
    file = open(safe_path)
```

---

### 3. INSECURE_RANDOM (CWE-338)
**Severity**: HIGH/MEDIUM | **Confidence**: HIGH/MEDIUM/LOW
**OWASP**: A02:2021 - Cryptographic Failures

Detects usage of `random` module for security purposes:
- Context-aware detection (looks for security keywords like "token", "password", "key")
- HIGH confidence when security context detected
- LOW confidence otherwise (may require manual review)

**Why it matters**: `random` is not cryptographically secure. Attackers can predict values.

**Example Detection**:
```python
# Detected with HIGH confidence
session_token = random.randint(1000, 9999)  # 'token' keyword
password = str(random.randint(100000, 999999))  # 'password' keyword

# Detected with LOW confidence
number = random.randint(1, 100)  # No security context

# Safe alternative
import secrets
session_token = secrets.token_hex(16)
password = secrets.token_urlsafe(16)
```

---

### 4. REGEX_DOS (CWE-1333)
**Severity**: MEDIUM | **Confidence**: MEDIUM
**OWASP**: A05:2021 - Security Misconfiguration

Detects regex patterns vulnerable to catastrophic backtracking (ReDoS):
- Nested quantifiers: `(a+)+`, `(a*)*`, `(a+)*`, `(a*)+`
- Patterns that can cause exponential time complexity

**Why it matters**: Malicious input can cause regex to hang, leading to denial of service.

**Example Detection**:
```python
# Detected
import re
pattern = re.compile(r'(a+)+b')  # Catastrophic backtracking
pattern = re.compile(r'(a*)*b')  # Exponential complexity

# Safe patterns
pattern = re.compile(r'a+b')  # Linear
```

---

### 5. XXE (CWE-611)
**Severity**: HIGH/MEDIUM | **Confidence**: HIGH/MEDIUM/LOW
**OWASP**: A05:2021 - Security Misconfiguration

Detects XML External Entity (XXE) vulnerabilities:
- `xml.etree.ElementTree` parsing
- `xml.sax` / `xml.dom.minidom` parsing
- `lxml` without security settings

**Why it matters**: XXE can allow attackers to read local files, perform SSRF, or cause DoS.

**Example Detection**:
```python
# Detected
import xml.etree.ElementTree as ET
tree = ET.parse(untrusted_xml)  # HIGH risk

# Safe alternative
import defusedxml.ElementTree as ET
tree = ET.parse(untrusted_xml)  # Protected against XXE
```

## Complete Detection Matrix

| Rule ID | CWE | OWASP | Severity | Confidence | What It Detects |
|---------|-----|-------|----------|------------|-----------------|
| DANGEROUS_EXEC | CWE-95 | A03 Injection | HIGH | HIGH | eval(), exec() |
| COMMAND_INJECTION | CWE-78 | A03 Injection | HIGH | HIGH | os.system(), shell=True |
| SQL_INJECTION | CWE-89 | A03 Injection | HIGH | MEDIUM | String concat in SQL |
| WEAK_CRYPTO | CWE-327 | A02 Crypto | MEDIUM | HIGH | MD5, SHA1 |
| HARDCODED_SECRET | CWE-798 | A07 Auth | HIGH | MEDIUM | Hardcoded credentials |
| **INSECURE_DESERIALIZATION** | **CWE-502** | **A08 Integrity** | **HIGH** | **HIGH** | **pickle, yaml.load** |
| **PATH_TRAVERSAL** | **CWE-22** | **A01 Access** | **HIGH** | **MED/LOW** | **File path concat** |
| **INSECURE_RANDOM** | **CWE-338** | **A02 Crypto** | **HIGH** | **VAR** | **random for security** |
| **REGEX_DOS** | **CWE-1333** | **A05 Config** | **MEDIUM** | **MEDIUM** | **Catastrophic backtracking** |
| **XXE** | **CWE-611** | **A05 Config** | **HIGH** | **MED/LOW** | **Unsafe XML parsing** |

## Testing the New Rules

Run the demo to see all rules in action:

```bash
python demo_all_rules.py
```

Scan the new vulnerabilities fixture:

```bash
py -m mikmbr.cli scan tests/fixtures/new_vulnerabilities.py --verbose
```

Run the test suite:

```bash
pytest tests/test_new_rules.py -v
```

## Migration Guide

No breaking changes! All existing functionality is preserved. The new rules are automatically included in scans.

### Before (v1.1)
```bash
mikmbr scan myproject/
# Detected 5 categories
```

### After (v1.2)
```bash
mikmbr scan myproject/
# Now detects 10 categories!
```

## Implementation Details

All new rules follow the same architecture:
- AST-based detection (no regex on source)
- CWE and OWASP mappings
- Confidence levels
- Code snippets
- Educational references

### Example: InsecureDeserializationRule

```python
class InsecureDeserializationRule(Rule):
    def check(self, tree, source, filepath):
        for node in ast.walk(tree):
            if self._is_pickle_load(node):
                return Finding(
                    cwe_id="CWE-502",
                    owasp_category="A08:2021",
                    confidence=Confidence.HIGH,
                    ...
                )
```

## Performance

Added rules have minimal performance impact:
- Average scan time increase: <5%
- All rules use single AST pass
- No external dependencies required

## What's Next?

Future enhancements:
- Configuration file support (enable/disable rules)
- Custom rule creation
- Enhanced taint analysis
- Multi-language support

---

**Current Version**: v1.2
**Total Rules**: 10
**CWE Coverage**: 10 weakness types
**OWASP Top 10 Coverage**: 6 of 10 categories
