# Exit Code Configuration

Control when Mikmbr fails CI/CD builds based on severity levels.

## Usage

### Default Behavior

By default, Mikmbr exits with code `1` if **any** security findings are detected:

```bash
mikmbr scan .
echo $?  # 1 if findings, 0 if clean
```

### Exit Codes

- `0` - No issues found (or all findings below threshold)
- `1` - Security issues found (above threshold if --fail-on specified)
- `2` - Error during scanning (file not found, syntax error, etc.)

## --fail-on Flag

Control the severity threshold for build failures:

### Fail on HIGH or above

```bash
mikmbr scan . --fail-on high
```

Exit code `1` only if HIGH or CRITICAL findings exist.
MEDIUM and LOW findings won't fail the build.

### Fail on MEDIUM or above

```bash
mikmbr scan . --fail-on medium
```

Exit code `1` if MEDIUM, HIGH, or CRITICAL findings exist.
LOW findings won't fail the build.

### Fail on CRITICAL only

```bash
mikmbr scan . --fail-on critical
```

Exit code `1` only if CRITICAL findings exist.
HIGH, MEDIUM, and LOW won't fail the build.

### Fail on any findings (including LOW)

```bash
mikmbr scan . --fail-on low
```

This is the same as default behavior - any finding fails the build.

## Severity Levels

Mikmbr uses four severity levels:

| Severity | Description | Example Rules |
|----------|-------------|---------------|
| **CRITICAL** | Immediate remote code execution | Template Injection (SSTI) |
| **HIGH** | Direct security impact | SQL Injection, Command Injection, Hardcoded Secrets |
| **MEDIUM** | Indirect security risk | Weak Crypto, Open Redirect, Log Injection |
| **LOW** | Code quality / minor risk | Bare Except, ReDoS |

## CI/CD Examples

### GitHub Actions

**Strict Mode** - Fail on any HIGH+ findings:
```yaml
- name: Security Scan
  run: |
    pip install mikmbr
    mikmbr scan . --fail-on high --format json
```

**Permissive Mode** - Only fail on CRITICAL:
```yaml
- name: Security Scan
  run: |
    pip install mikmbr
    mikmbr scan . --fail-on critical --format json
  continue-on-error: false
```

**Report Only** - Never fail build:
```yaml
- name: Security Scan
  run: |
    pip install mikmbr
    mikmbr scan . --format json || true  # Always exit 0
```

### GitLab CI

```yaml
security_scan:
  script:
    - pip install mikmbr
    - mikmbr scan . --fail-on high --format json
  allow_failure: false  # Fail pipeline on HIGH+
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install mikmbr'
                sh 'mikmbr scan . --fail-on high'
            }
        }
    }
}
```

## Configuration File

You can set a default threshold in `.mikmbr.yaml`:

```yaml
output:
  fail_on: high  # Default threshold
```

CLI flag overrides config file:
```bash
mikmbr scan . --fail-on medium  # Overrides config
```

## Use Cases

### Development

**Local development** - See all issues:
```bash
mikmbr scan .
# No --fail-on flag, shows everything
```

### Pull Requests

**Block PRs with HIGH+ issues**:
```bash
mikmbr scan . --fail-on high
```

### Main Branch

**Strict enforcement**:
```bash
mikmbr scan . --fail-on medium
```

### Legacy Codebases

**Gradual adoption** - Only block CRITICAL initially:
```bash
mikmbr scan . --fail-on critical --format json
```

Then tighten over time:
1. Start: `--fail-on critical` (stop only critical issues)
2. After fixes: `--fail-on high` (tighten to high)
3. Eventually: `--fail-on medium` (full enforcement)

## Examples

### Example 1: Code with Multiple Severities

```python
# test.py
import hashlib

# HIGH - SQL Injection
query = f"SELECT * FROM users WHERE id = {user_id}"

# MEDIUM - Weak Crypto
password_hash = hashlib.md5(password.encode())

# LOW - Bare Except
try:
    risky_operation()
except:
    pass
```

**Results:**

```bash
# Default - fails on any finding
$ mikmbr scan test.py
Found 3 security issue(s)
$ echo $?
1

# Fail on HIGH+ only
$ mikmbr scan test.py --fail-on high
Found 3 security issue(s)
$ echo $?
1  # Exits 1 because SQL Injection is HIGH

# Fail on CRITICAL only
$ mikmbr scan test.py --fail-on critical
Found 3 security issue(s)
$ echo $?
0  # Exits 0 because no CRITICAL findings
```

### Example 2: Clean Code

```python
# clean.py
import hashlib

# Secure code
password_hash = hashlib.sha256(password.encode())
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

```bash
$ mikmbr scan clean.py --fail-on high
No security issues found.
$ echo $?
0
```

## Combining with Other Flags

### With --format json

```bash
mikmbr scan . --fail-on high --format json > results.json
if [ $? -eq 1 ]; then
  echo "HIGH+ security issues found!"
  cat results.json | jq '.findings[] | select(.severity == "HIGH")'
fi
```

### With --verbose

```bash
mikmbr scan . --fail-on high --verbose
```

Shows detailed output for all findings, but only fails on HIGH+.

### With SARIF

```bash
mikmbr scan . --fail-on high --format sarif > results.sarif
```

Generate SARIF for GitHub, but only fail on HIGH+.

## Best Practices

1. **Start Permissive** - Use `--fail-on critical` for legacy codebases
2. **Tighten Gradually** - Move to `--fail-on high` as you fix issues
3. **Different Thresholds** - Use stricter settings for production branches
4. **Document Your Policy** - Add threshold to README or CONTRIBUTING.md
5. **Review All Findings** - Even if build passes, review MEDIUM/LOW issues

## Version History

- **v1.7.0**: Added `--fail-on` flag with CRITICAL, HIGH, MEDIUM, LOW thresholds
- **v1.6.0**: Default behavior (fail on any finding)
