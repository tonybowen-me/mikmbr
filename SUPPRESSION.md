# Inline Suppression Guide

Mikmbr supports inline suppression comments to allow you to mark false positives or intentionally ignore specific security findings.

## Usage

### Suppress All Rules on a Line

```python
api_key = "test_key_for_development"  # mikmbr: ignore
```

This suppresses **all** security findings on this line.

### Suppress Specific Rules

```python
# Suppress only SQL injection detection
query = f"SELECT * FROM data WHERE safe_id = {validated_id}"  # mikmbr: ignore[SQL_INJECTION]

# Suppress multiple rules
eval(safe_ast_literal)  # mikmbr: ignore[DANGEROUS_EXEC, CODE_INJECTION]
```

### Suppress Previous Line

You can place the suppression comment on the line before:

```python
# mikmbr: ignore[HARDCODED_SECRET]
api_key = "sk_test_1234567890"  # This is a test key in documentation
```

### Block Suppression

Suppress entire code blocks:

```python
# mikmbr: disable
# Everything between disable and enable is suppressed
api_key = "test_key"
password = "test_pass"
eval(user_input)
# mikmbr: enable

# Detection resumes here
token = "real_token"  # Will be detected
```

If you use `# mikmbr: disable` without `# mikmbr: enable`, the rest of the file is suppressed.

## Rule IDs

Use these rule IDs for specific suppressions:

### Critical/High Severity
- `TEMPLATE_INJECTION` - Server-Side Template Injection (SSTI)
- `DANGEROUS_EXEC` - eval(), exec() usage
- `COMMAND_INJECTION` - os.system(), subprocess with shell=True
- `SQL_INJECTION` - String concatenation in SQL queries
- `SSRF` - Server-Side Request Forgery
- `HARDCODED_SECRET` - API keys, passwords in code
- `PATH_TRAVERSAL` - Unsafe file path construction
- `DEBUG_CODE` - Debug mode, breakpoints in production

### Medium Severity
- `INSECURE_DESERIALIZATION` - pickle, unsafe yaml.load()
- `OPEN_REDIRECT` - Unvalidated redirects
- `LOG_INJECTION` - Unsanitized user input in logs
- `TIMING_ATTACK` - Non-constant-time comparisons
- `WEAK_CRYPTO` - MD5, SHA1 usage
- `INSECURE_RANDOM` - random for security purposes
- `REGEX_DOS` - Catastrophic backtracking patterns
- `XXE` - XML External Entity vulnerabilities
- `WEAK_PASSWORD_HASH` - Weak password hashing
- `INSECURE_COOKIE` - Missing secure cookie flags
- `JWT_SECURITY` - JWT security issues
- `SESSION_SECURITY` - Session management issues

### Low Severity
- `BARE_EXCEPT` - Catches all exceptions
- `DEBUG_CODE` - Debug code patterns

## Best Practices

### ✅ Good Use Cases

**False Positives**
```python
# This looks like a secret but it's a public constant
PUBLIC_API_ENDPOINT = "https://api.example.com/v1/abc123def456"  # mikmbr: ignore[HARDCODED_SECRET]
```

**Intentional Design**
```python
# Admin backdoor for emergency access - approved in SEC-2024-001
# mikmbr: ignore[HARDCODED_SECRET]
EMERGENCY_ADMIN_TOKEN = os.getenv("EMERGENCY_TOKEN", "fallback_token_123")
```

**Test/Development Code**
```python
# Test fixtures
# mikmbr: disable
TEST_USERS = {
    "admin": "admin_password",
    "user": "user_password"
}
# mikmbr: enable
```

**Validated Input**
```python
# ID is validated and converted to int, safe from SQL injection
user_id = int(request.args.get('id'))  # Raises ValueError if not int
# mikmbr: ignore[SQL_INJECTION]
query = f"SELECT * FROM users WHERE id = {user_id}"
```

### ❌ Bad Use Cases

**Don't suppress real vulnerabilities**
```python
# BAD: This is a real security issue!
password = "admin123"  # mikmbr: ignore[HARDCODED_SECRET]
```

**Don't suppress instead of fixing**
```python
# BAD: Fix this instead of ignoring!
eval(user_input)  # mikmbr: ignore[DANGEROUS_EXEC]
```

**Don't disable large blocks**
```python
# BAD: Too broad, might hide real issues
# mikmbr: disable
# ... 500 lines of code ...
# mikmbr: enable
```

## Configuration

You can also disable rules globally in `.mikmbr.yaml`:

```yaml
rules:
  # Disable rules entirely
  REGEX_DOS: false
  BARE_EXCEPT: false

  # Or adjust severity
  LOG_INJECTION:
    severity: HIGH
```

Global disabling is better for rules you never want to check, while inline suppression is better for specific false positives.

## CI/CD Integration

In CI/CD, you might want to report suppressed findings for audit purposes:

```bash
# Fail on any HIGH findings, even if suppressed (not yet implemented)
mikmbr scan . --fail-on high --ignore-suppressions
```

## Audit Suppressions

To see suppression statistics:

```bash
# Future feature
mikmbr scan . --show-suppressions
```

Example output:
```
Found 5 security issues (2 suppressed):

Active Findings (3):
[HIGH] src/app.py:12 - SQL_INJECTION
[MED] src/utils.py:45 - WEAK_CRYPTO
[LOW] src/test.py:89 - BARE_EXCEPT

Suppressed Findings (2):
[HIGH] src/config.py:5 - HARDCODED_SECRET (reason: test key)
[MED] src/legacy.py:105 - INSECURE_RANDOM (entire block disabled)
```

## Security Notes

- Suppression comments are **not a security control** - they just hide findings
- Always document **why** you're suppressing a finding
- Regularly audit suppressed findings to ensure they're still valid
- Consider using configuration-based disabling for rules you never want

## Case Sensitivity

Suppression comments are **case-insensitive**:

```python
# All of these work:
# mikmbr: ignore
# MIKMBR: IGNORE
# Mikmbr: Ignore
```

Rule IDs in suppressions are also case-insensitive:

```python
# All of these work:
# mikmbr: ignore[SQL_INJECTION]
# mikmbr: ignore[sql_injection]
# mikmbr: ignore[Sql_Injection]
```

## Examples

### Example 1: Test File

```python
"""Test fixtures with hardcoded credentials."""

# mikmbr: disable
# All test credentials
TEST_ADMIN_USER = "admin"
TEST_ADMIN_PASS = "admin_password_123"
TEST_API_KEY = "sk_test_1234567890abcdef"
TEST_SECRET_KEY = "test_secret_key_for_jwt"
# mikmbr: enable
```

### Example 2: Configuration File

```python
"""Application configuration."""

# Production secret loaded from environment
SECRET_KEY = os.environ.get('SECRET_KEY')

# Default for development only
if not SECRET_KEY:
    # mikmbr: ignore[HARDCODED_SECRET]
    SECRET_KEY = "dev_secret_key_not_for_production"
    print("WARNING: Using development secret key!")
```

### Example 3: Legacy Code

```python
"""Legacy module being refactored."""

# TODO: Refactor this module to remove security issues
# Tracked in ticket SEC-2024-042
# mikmbr: disable

def legacy_query(user_id):
    # Using string concatenation - will be fixed in refactor
    return f"SELECT * FROM users WHERE id = {user_id}"

def legacy_exec(code):
    # Using eval - will be replaced with safe parser
    return eval(code)

# mikmbr: enable
```

## Version History

- **v1.6.0**: Introduced inline suppression system
  - Line-level suppression with `# mikmbr: ignore`
  - Rule-specific suppression with `# mikmbr: ignore[RULE_ID]`
  - Block suppression with `# mikmbr: disable/enable`
  - Support for suppressing previous line
  - Case-insensitive matching
