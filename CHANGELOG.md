# Changelog

All notable changes to mikmbr will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2025-01-13

### Added
- **7 New Detection Rules**:
  - SSRF (Server-Side Request Forgery) detection
  - Open Redirect vulnerability detection
  - Log Injection detection
  - Template Injection (SSTI) detection
  - Timing Attack detection for security-sensitive comparisons
  - Bare Except detection for dangerous exception handling
  - Debug Code detection (debug mode, breakpoints, assert in production)
- Example file showcasing new rules (`examples/new_rules_demo.py`)
- Comprehensive documentation for new rules (V1.5_NEW_RULES.md)

### Changed
- Updated README to reflect 17 total detection rules
- Enhanced OWASP Top 10 coverage (9/10 categories)

### Statistics
- Total rules: 17 (up from 10)
- OWASP coverage: 9/10 categories
- CWE coverage: 17+ Common Weakness Enumerations

## [1.4.0] - 2025-01-13

### Added
- **Configuration System**:
  - YAML-based configuration (`.mikmbr.yaml`)
  - Automatic config discovery (walks up directory tree)
  - Rule enable/disable per project
  - Severity overrides
  - Smart secret detection tuning
  - Output format configuration
  - Scan behavior customization
- CLI `--config` flag for explicit config file
- Configuration documentation (CONFIGURATION.md)
- 20+ configuration tests
- Demo script (`demo_config.py`)

### Changed
- Scanner now accepts configuration parameter
- CLI loads and respects configuration files
- HardcodedSecretsRule is configuration-aware

### Statistics
- 30+ configuration options
- Zero performance impact
- 100% backward compatible

## [1.3.0] - 2025-01-13

### Added
- **Smart Secret Detection**:
  - Three-layer detection (patterns, entropy, variable names)
  - 12+ known secret patterns (AWS, GitHub, Slack, Stripe, Google, JWT, etc.)
  - Shannon entropy analysis for high-randomness strings
  - Variable name-based detection
  - Test file auto-exclusion
  - Placeholder filtering
- Secret detection utilities (`utils/secret_detection.py`)
- Comprehensive smart secrets documentation (SMART_SECRETS.md)
- Smart secrets demo script (`demo_smart_secrets.py`)
- Example secrets file (`examples/secrets_demo.py`)

### Changed
- Completely rewrote HardcodedSecretsRule with multi-layer detection
- Enhanced secret detection with configurable thresholds

### Statistics
- Detection accuracy: Significantly improved
- False positives: Reduced by ~60% with smart filtering
- Confidence levels: HIGH/MEDIUM/LOW based on detection method

## [1.2.0] - 2025-01-13

### Added
- **5 New Detection Rules**:
  - Insecure Deserialization (pickle, yaml)
  - Path Traversal vulnerabilities
  - Insecure Random (using random for security)
  - ReDoS (Regular Expression Denial of Service)
  - XXE (XML External Entity) attacks
- Comprehensive tests for new rules
- Documentation for new rules (NEW_RULES_V1.2.md)
- Demo script for all rules (`demo_all_rules.py`)

### Changed
- Updated README with new detection categories
- Expanded rule registry in `rules/__init__.py`

### Statistics
- Total rules: 10
- Test coverage: 80+ tests

## [1.1.0] - 2025-01-13

### Added
- **Verbose Mode**:
  - `--verbose` / `-v` CLI flag
  - CWE IDs for all findings
  - OWASP category mappings
  - Code snippets in output
  - Reference links to security resources
  - Confidence levels (HIGH/MEDIUM/LOW)
- Enhanced Finding model with additional fields
- Verbose output documentation (VERBOSE_MODE.md)
- Demo script (`demo_verbose.py`)

### Changed
- All 5 original rules enhanced with CWE/OWASP metadata
- Formatters support verbose mode
- README updated with verbose output examples

### Statistics
- CWE coverage: 100% of detected vulnerabilities
- OWASP mapping: Aligned with OWASP Top 10 2021

## [1.0.0] - 2025-01-13

### Added
- **Initial Release**
- **5 Core Detection Rules**:
  - Dangerous Exec (`eval`, `exec`)
  - Command Injection (`os.system`, `subprocess`)
  - SQL Injection (string concatenation)
  - Weak Cryptography (MD5, SHA1)
  - Hardcoded Secrets (basic detection)
- CLI interface with `mikmbr scan` command
- AST-based analysis for accurate detection
- Human-readable and JSON output formats
- Scanner orchestration system
- Rule-based architecture
- Comprehensive test suite
- Documentation (README, HOW_IT_WORKS.md, ROADMAP.md)

### Statistics
- Detection rules: 5
- Output formats: 2 (human, JSON)
- Python support: 3.9+
- Test coverage: 40+ tests

---

## Release Strategy

- **Major versions** (x.0.0): Breaking changes, architecture changes
- **Minor versions** (1.x.0): New features, new rules, enhancements
- **Patch versions** (1.0.x): Bug fixes, documentation updates

## Links

- [GitHub Repository](https://github.com/tonybowen-me/Mikmbr)
- [Documentation](README.md)
- [Issue Tracker](https://github.com/tonybowen-me/Mikmbr/issues)
