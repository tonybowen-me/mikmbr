# Configuration Guide - mikmbr v1.4

## Overview

mikmbr v1.4 introduces comprehensive configuration support via `.mikmbr.yaml` files. Configure scanning behavior, rule settings, secret detection, and output formatting to match your project's needs.

## Quick Start

Create a `.mikmbr.yaml` file in your project root:

```yaml
version: "1.4"

# Disable specific rules
rules:
  REGEX_DOS: false

# Configure secret detection
secret_detection:
  entropy:
    min_entropy: 3.0  # More sensitive

# Output settings
output:
  verbose: true
```

Run mikmbr - it will automatically discover and use your config:

```bash
mikmbr scan .
```

## Configuration Discovery

mikmbr searches for configuration files in this order:

1. **Explicit path** via `--config` flag:
   ```bash
   mikmbr scan . --config /path/to/config.yaml
   ```

2. **Automatic discovery**: Walks up the directory tree from the scan path looking for:
   - `.mikmbr.yaml`
   - `.mikmbr.yml`

3. **Default configuration**: If no config file is found, uses built-in defaults

## Configuration Structure

### Top-Level Settings

```yaml
version: "1.4"  # Configuration schema version
```

### Rules Configuration

Control which rules are enabled and their severity levels.

#### Disable a Rule

```yaml
rules:
  DANGEROUS_EXEC: false
  REGEX_DOS: false
```

#### Override Rule Severity

```yaml
rules:
  SQL_INJECTION:
    enabled: true
    severity: CRITICAL  # Options: INFO, LOW, MEDIUM, HIGH, CRITICAL

  HARDCODED_SECRETS:
    enabled: true
    severity: HIGH
```

#### Available Rules

- `DANGEROUS_EXEC` - eval() and exec() detection
- `COMMAND_INJECTION` - OS command injection
- `SQL_INJECTION` - SQL injection vulnerabilities
- `WEAK_CRYPTO` - Weak cryptographic algorithms
- `HARDCODED_SECRETS` - Hardcoded secrets and API keys
- `INSECURE_DESERIALIZATION` - pickle/yaml deserialization
- `PATH_TRAVERSAL` - Directory traversal
- `INSECURE_RANDOM` - Insecure random number generation
- `REGEX_DOS` - ReDoS vulnerabilities
- `XXE` - XML External Entity attacks

### Secret Detection Configuration

Fine-tune the smart secret detection system.

#### Full Configuration

```yaml
secret_detection:
  enabled: true  # Master switch for all secret detection

  # Entropy-based detection
  entropy:
    enabled: true
    min_length: 20      # Minimum string length for analysis
    min_entropy: 3.5    # Shannon entropy threshold (0-8 scale)

  # Known pattern detection (AWS, GitHub, etc.)
  patterns:
    enabled: true

  # Variable name-based detection
  variable_names:
    enabled: true
    min_length: 8       # Minimum value length for matches

  # Additional paths to exclude
  exclude_paths:
    - "*/my_tests/*"
    - "demo_*.py"

  # Additional placeholder strings to ignore
  custom_placeholders:
    - "company_test_key"
    - "internal_placeholder"
```

#### Entropy Tuning

**More Sensitive** (catches more secrets, more false positives):
```yaml
secret_detection:
  entropy:
    min_entropy: 3.0
    min_length: 16
```

**Less Sensitive** (fewer false positives, may miss some secrets):
```yaml
secret_detection:
  entropy:
    min_entropy: 4.0
    min_length: 24
```

#### Disable Specific Detection Methods

```yaml
secret_detection:
  entropy:
    enabled: false  # Disable entropy-based detection
  patterns:
    enabled: true   # Keep pattern detection
```

### Output Configuration

Control how findings are displayed.

```yaml
output:
  format: human           # Options: human, json
  verbose: false          # Show CWE, OWASP, code snippets
  show_code: true         # Include code snippets
  color: true             # ANSI colors in terminal
  max_line_length: 120    # Maximum line length for snippets
```

#### Output Modes

**Human-Readable (Default)**:
```yaml
output:
  format: human
  verbose: false
```

**Detailed Output**:
```yaml
output:
  format: human
  verbose: true  # Includes CWE IDs, OWASP mappings, references
```

**JSON for CI/CD**:
```yaml
output:
  format: json
  verbose: false
```

### Scan Configuration

Control which files are scanned and how.

```yaml
scan:
  # File patterns to include
  include_patterns:
    - "*.py"
    - "*.pyx"

  # Patterns to exclude
  exclude_patterns:
    - "*.pyc"
    - "__pycache__/*"
    - ".git/*"
    - "venv/*"
    - "build/*"
    - "dist/*"

  # Maximum file size to scan (in KB)
  max_file_size_kb: 1024  # 1MB

  # Follow symbolic links
  follow_symlinks: false
```

## Configuration Examples

### Example 1: Strict CI/CD Configuration

For production builds where security is critical:

```yaml
version: "1.4"

rules:
  DANGEROUS_EXEC:
    enabled: true
    severity: CRITICAL
  COMMAND_INJECTION:
    enabled: true
    severity: CRITICAL
  SQL_INJECTION:
    enabled: true
    severity: CRITICAL
  HARDCODED_SECRETS:
    enabled: true
    severity: CRITICAL

secret_detection:
  entropy:
    min_entropy: 3.0  # More sensitive
  exclude_paths: []   # Scan everything, including tests

output:
  format: json
  verbose: true

scan:
  max_file_size_kb: 2048
```

### Example 2: Development Configuration

For local development with fewer false positives:

```yaml
version: "1.4"

rules:
  REGEX_DOS: false      # Skip for dev
  INSECURE_RANDOM: false

secret_detection:
  entropy:
    min_entropy: 3.8    # Less sensitive
  custom_placeholders:
    - "dev_test_key"
    - "local_token"

output:
  format: human
  verbose: false
  color: true
```

### Example 3: Security-Focused Configuration

For security audits:

```yaml
version: "1.4"

rules:
  HARDCODED_SECRETS:
    enabled: true
    severity: CRITICAL
  COMMAND_INJECTION:
    enabled: true
    severity: HIGH
  SQL_INJECTION:
    enabled: true
    severity: HIGH

secret_detection:
  entropy:
    min_entropy: 2.8    # Very sensitive
    min_length: 12
  patterns:
    enabled: true
  variable_names:
    enabled: true

output:
  format: human
  verbose: true
```

### Example 4: Minimal Configuration

Only essential settings:

```yaml
version: "1.4"

output:
  verbose: true
```

## CLI Overrides

Command-line arguments override configuration file settings:

```bash
# Override output format
mikmbr scan . --format json

# Override verbosity
mikmbr scan . --verbose

# Use specific config file
mikmbr scan . --config my-config.yaml
```

**Precedence Order**:
1. CLI arguments (highest priority)
2. Configuration file
3. Built-in defaults (lowest priority)

## Configuration Validation

mikmbr validates configuration on load:

- Invalid YAML syntax → Error message
- Unknown rule IDs → Warning (ignored)
- Invalid severity values → Warning (uses original severity)
- Missing required fields → Uses defaults

## Best Practices

### 1. Start with Defaults

Run without config to see default behavior:
```bash
mikmbr scan .
```

### 2. Incrementally Customize

Add configuration gradually based on your needs:
```yaml
# Start simple
version: "1.4"
output:
  verbose: true
```

### 3. Use Version Control

Commit `.mikmbr.yaml` to your repository:
```bash
git add .mikmbr.yaml
git commit -m "Add mikmbr configuration"
```

### 4. Different Configs for Different Environments

```bash
# Development
mikmbr scan . --config .mikmbr-dev.yaml

# CI/CD
mikmbr scan . --config .mikmbr-ci.yaml

# Production audit
mikmbr scan . --config .mikmbr-prod.yaml
```

### 5. Document Custom Settings

Add comments to your config:
```yaml
version: "1.4"

rules:
  # We use regex heavily, known to be safe
  REGEX_DOS: false

secret_detection:
  # Higher threshold to reduce false positives in tests
  entropy:
    min_entropy: 3.8
```

## Troubleshooting

### Config Not Being Loaded

1. Check file name: Must be `.mikmbr.yaml` or `.mikmbr.yml`
2. Check location: Must be in or above the scan path
3. Check YAML syntax: Use a YAML validator
4. Use `--config` flag to specify explicitly

### Rules Not Being Disabled

1. Check rule ID spelling (must be exact)
2. Check YAML indentation
3. Verify with `demo_config.py` script

### Secrets Still Detected Despite Exclusions

1. Verify path patterns use wildcards correctly
2. Check if paths use forward slashes
3. Add custom placeholders for specific values

## Advanced Usage

### Environment-Specific Configurations

Use shell aliases or scripts:

```bash
# ~/.bashrc
alias mikmbr-dev='mikmbr scan . --config .mikmbr-dev.yaml'
alias mikmbr-ci='mikmbr scan . --config .mikmbr-ci.yaml --format json'
```

### Per-Directory Configuration

Create `.mikmbr.yaml` in subdirectories for directory-specific settings:

```
project/
├── .mikmbr.yaml          # Project-wide settings
├── src/
│   └── .mikmbr.yaml      # Source-specific settings
└── tests/
    └── .mikmbr.yaml      # Test-specific settings
```

### Integrating with Pre-Commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: mikmbr
        name: mikmbr security scan
        entry: mikmbr scan --config .mikmbr-ci.yaml
        language: system
        pass_filenames: false
```

## Demo Script

Run the configuration demo:

```bash
python demo_config.py
```

Shows:
- Default configuration
- Loading from YAML
- Automatic discovery
- Rule enabling/disabling
- Secret detection tuning
- Example configurations

## Complete Reference

### Default Configuration

```yaml
version: "1.4"

rules: {}  # All rules enabled by default

secret_detection:
  enabled: true
  entropy:
    enabled: true
    min_length: 20
    min_entropy: 3.5
  patterns:
    enabled: true
  variable_names:
    enabled: true
    min_length: 8
  exclude_paths:
    - "*/test/*"
    - "*/tests/*"
    - "test_*.py"
    - "*_test.py"
    - "*/fixtures/*"
    - "*/fixture/*"
    - "*/mock/*"
    - "*/mocks/*"
    - "*/example/*"
    - "*/examples/*"
    - "conftest.py"
  custom_placeholders: []

output:
  format: human
  verbose: false
  show_code: true
  color: true
  max_line_length: 120

scan:
  include_patterns:
    - "*.py"
  exclude_patterns:
    - "*.pyc"
    - "__pycache__/*"
    - ".git/*"
    - "venv/*"
    - "env/*"
    - ".venv/*"
    - "node_modules/*"
    - "build/*"
    - "dist/*"
    - "*.egg-info/*"
  max_file_size_kb: 1024
  follow_symlinks: false
```

## Version History

- **v1.4**: Initial configuration support
  - YAML-based configuration
  - Rule enable/disable
  - Severity overrides
  - Secret detection tuning
  - Output configuration
  - Scan configuration
  - Automatic discovery

## Related Documentation

- [README.md](README.md) - Getting started guide
- [SMART_SECRETS.md](SMART_SECRETS.md) - Secret detection details
- [VERBOSE_MODE.md](VERBOSE_MODE.md) - Verbose output guide
- [ROADMAP.md](ROADMAP.md) - Future enhancements

---

**Version**: v1.4
**Configuration Format**: YAML
**File Names**: `.mikmbr.yaml`, `.mikmbr.yml`
**Discovery**: Automatic (walks up directory tree)
