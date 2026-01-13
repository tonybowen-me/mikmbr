# Smart Secret Detection - Enhanced Security

## Overview

mikmbr v1.3 introduces **Smart Secret Detection** with three layers of detection:

1. **Known Pattern Matching** - Detects AWS keys, GitHub tokens, etc. (HIGH confidence)
2. **Entropy Analysis** - Identifies high-randomness strings (MEDIUM confidence)
3. **Variable Name Patterns** - Contextual detection (MEDIUM confidence)

Plus **smart filtering** to reduce false positives.

## Detection Methods

### 1. Known Pattern Detection (HIGH Confidence)

Detects industry-standard secret formats:

| Secret Type | Pattern Example | Detection |
|-------------|----------------|-----------|
| AWS Access Key | `AKIA...` | ✅ HIGH |
| AWS Secret Key | Context-aware | ✅ HIGH |
| GitHub Personal Token | `ghp_...` | ✅ HIGH |
| GitHub OAuth | `gho_...` | ✅ HIGH |
| GitHub App | `ghu_...`, `ghs_...` | ✅ HIGH |
| Slack Token | `xoxb-...`, `xoxp-...` | ✅ HIGH |
| Stripe API Key | `sk_live_...`, `rk_live_...` | ✅ HIGH |
| Google API Key | `AIza...` | ✅ HIGH |
| JWT Token | `eyJ...` | ✅ HIGH |
| Private Keys | `-----BEGIN PRIVATE KEY-----` | ✅ HIGH |
| Passwords in URLs | `mysql://user:pass@host` | ✅ HIGH |

**Example Detection:**
```python
# Detected with HIGH confidence
aws_key = "AKIAIOSFODNN7EXAMPLE"
github_token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234"
```

### 2. Entropy Analysis (MEDIUM Confidence)

Uses Shannon entropy to detect high-randomness strings:

**How it works:**
- Calculates information entropy of strings
- High entropy = high randomness = likely a secret
- Default threshold: 3.5 bits, minimum length: 20 chars

**Entropy Examples:**
```python
calculate_entropy("aaaaaaa")              # 0.0 (low)
calculate_entropy("password123")          # ~2.0 (medium)
calculate_entropy("aK9$mP2xQw7vBn5t")     # ~3.8 (high)
```

**Example Detection:**
```python
# Detected with MEDIUM confidence (high entropy)
api_key = "aK9$mP2xQw7vBn5tYu3zRe8pLs4hGf1jDc6"
```

### 3. Variable Name Patterns (MEDIUM Confidence)

Detects secrets based on variable naming:

**Monitored Patterns:**
- `api_key`, `api-key`
- `secret_key`, `secret-key`
- `access_token`, `access-token`
- `auth_token`, `auth-token`
- `password`, `passwd`
- `private_key`, `private-key`
- `api_secret`, `client_secret`
- `aws_secret`

**Example Detection:**
```python
# Detected with MEDIUM confidence (variable name + value length)
password = "my_secure_password_123"
api_key = "sk_prod_1234567890"
```

## Smart Filtering

### Automatic Test File Exclusion

Reduces false positives by skipping test files:

**Excluded Patterns:**
- `/test/`, `/tests/`
- `test_*.py`, `*_test.py`
- `/fixture/`, `/fixtures/`
- `/mock/`, `/example/`
- `conftest.py`

**Example:**
```python
# This file would be skipped:
# /project/tests/test_config.py

aws_key = "AKIAIOSFODNN7EXAMPLE"  # Not flagged (test file)
```

### Placeholder Detection

Automatically ignores obvious placeholder values:

**Detected Placeholders:**
- `changeme`, `your_api_key_here`
- `example`, `sample`, `dummy`
- `todo`, `fixme`
- `12345`, `password`, `test`
- Very short strings (<8 chars)
- Repeated characters (`xxxxxxxx`)

**Example:**
```python
# These are NOT flagged:
api_key = "your_api_key_here"  # Placeholder
password = "changeme"           # Placeholder
token = "example"               # Placeholder
pwd = "12345"                   # Too simple
```

## Confidence Levels Explained

| Confidence | What It Means | Action |
|------------|---------------|--------|
| **HIGH** | Known secret pattern matched | Fix immediately |
| **MEDIUM** | High entropy OR variable name match | Review and fix if secret |
| **LOW** | Heuristic detection | Manual review needed |

## Usage Examples

### Basic Scan
```bash
# Smart detection is automatic
mikmbr scan myproject/
```

### Verbose Output
```bash
# See detection method and confidence
mikmbr scan myproject/ --verbose
```

### Example Output
```
[HIGH] config.py:12
  Rule: HARDCODED_SECRET
  Confidence: HIGH
  CWE: CWE-798
  OWASP: A07:2021 - Identification and Authentication Failures
  Issue: Hardcoded GitHub Personal Access Token detected in 'token'
  Fix: Store GitHub Personal Access Token in environment variables...
  Code:
    >>> token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234"
```

## Comparison: Before vs After

### Before (v1.2) - Basic Detection
```python
# Detected:
api_key = "sk_live_1234567890"  # Variable name match

# Missed:
token = "aK9$mP2xQw7vBn5tYu3zRe8p"  # No variable pattern
aws = "AKIAIOSFODNN7EXAMPLE"       # No variable pattern
```

### After (v1.3) - Smart Detection
```python
# Detected with HIGH confidence:
token = "aK9$mP2xQw7vBn5tYu3zRe8p"  # Entropy
aws = "AKIAIOSFODNN7EXAMPLE"        # Known pattern

# Detected with MEDIUM confidence:
api_key = "sk_live_1234567890"      # Variable name

# Not detected (smart filtering):
test_key = "changeme"                # Placeholder
```

## Performance

- **No performance impact**: Same single AST pass
- **Entropy calculation**: O(n) where n = string length
- **Pattern matching**: Optimized regex
- **Test file detection**: Simple string checks

## Customization (Future)

Planned configuration options:

```yaml
# .mikmbr.yaml (coming soon)
rules:
  HARDCODED_SECRET:
    entropy:
      enabled: true
      min_length: 20
      min_entropy: 3.5
    patterns:
      enabled: true
    exclude_paths:
      - "*/tests/*"
      - "*/fixtures/*"
    custom_placeholders:
      - "my_placeholder"
```

## Testing

### Run Smart Secret Tests
```bash
pytest tests/test_smart_secrets.py -v
```

### Run Demo
```bash
python demo_smart_secrets.py
```

### Test Your Code
```bash
mikmbr scan --verbose path/to/your/code.py
```

## Known Limitations

1. **Entropy analysis** may flag:
   - Base64-encoded non-secrets
   - Long UUIDs
   - Encrypted configuration values

2. **Pattern matching** requires:
   - Exact format match
   - May miss custom secret formats

3. **Context awareness** is limited:
   - Cannot determine if value is actually used as secret
   - Cannot verify if secret is valid/active

## Best Practices

### For Developers
1. Use environment variables: `os.getenv("API_KEY")`
2. Use secret managers: AWS Secrets Manager, HashiCorp Vault
3. Never commit secrets to version control
4. Use `.env` files with `.gitignore`

### For Security Teams
1. Run mikmbr in CI/CD pipeline
2. Review HIGH confidence findings immediately
3. Investigate MEDIUM confidence findings
4. Configure custom patterns if needed

### For False Positives
1. Use descriptive variable names (not `key`, `secret`)
2. Add comments explaining non-secret values
3. Store in separate config files
4. Use test file conventions to auto-skip

## Future Enhancements

- **Machine learning** for better false positive reduction
- **Context analysis** to understand secret usage
- **Secret validation** (check if key is active)
- **Git history scanning** (detect committed secrets)
- **Custom pattern support** via configuration
- **Allowlist/denylist** management

---

**Version**: v1.3
**Detection Methods**: 3 layers
**Known Patterns**: 12+ types
**Smart Filtering**: Auto test-file exclusion
