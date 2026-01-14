# Dependency Scanning - Mikmbr v1.8

## Overview

Mikmbr v1.8 introduces dependency vulnerability scanning powered by the [OSV (Open Source Vulnerabilities)](https://osv.dev/) database. This feature detects known security vulnerabilities in your project's third-party Python packages.

## Features

- **Comprehensive Coverage**: Scans requirements.txt and pyproject.toml files
- **OSV Integration**: Uses Google's Open Source Vulnerabilities database (free, no API key required)
- **CVE Mapping**: Links vulnerabilities to CVE IDs with CVSS scores
- **Fix Recommendations**: Provides specific version upgrade suggestions
- **Unified Output**: Works with all existing formatters (human, JSON, SARIF)
- **CI/CD Ready**: Integrates with `--fail-on` exit code control

## Usage

### Basic Dependency Scanning

```bash
# Scan code + dependencies
mikmbr scan . --check-deps

# Scan only dependencies (fast)
mikmbr scan . --deps-only

# Combine with other flags
mikmbr scan . --check-deps --fail-on high --format json
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan
  run: mikmbr scan . --check-deps --fail-on high
```

## Supported Dependency Files

### requirements.txt
```
django==2.2.0
flask>=1.0,<2.0
requests[security]==2.25.0
```

### pyproject.toml (PEP 621)
```toml
[project]
dependencies = [
    "django==2.2.0",
    "flask>=1.0"
]
```

### pyproject.toml (Poetry)
```toml
[tool.poetry.dependencies]
python = "^3.9"
django = "^2.2.0"
flask = "1.0.0"
```

## Example Output

```
[HIGH] requirements.txt:3
  Rule: VULN_DEPENDENCY
  CWE: CWE-89
  OWASP: A03:2021 - Injection

  Package django version 2.2.0 has known vulnerability CVE-2023-12345: SQL injection in admin panel

  Remediation: Upgrade django to >= 2.2.28

  References:
    - https://osv.dev/vulnerability/PYSEC-2023-12345
    - https://nvd.nist.gov/vuln/detail/CVE-2023-12345
```

## Architecture

### Module Structure
```
src/mikmbr/dependencies/
├── __init__.py          # Public API
├── scanner.py           # DependencyScanner class
├── parsers.py           # Dependency file parsers
└── osv_client.py        # OSV API client
```

### How It Works

1. **File Discovery**: Finds requirements.txt and pyproject.toml in target directory
2. **Parsing**: Extracts package names and version constraints
3. **Vulnerability Query**: Queries OSV API for each package
4. **Finding Creation**: Converts vulnerabilities to Mikmbr Finding objects
5. **Output**: Uses existing formatters (human, JSON, SARIF)

### OSV API

- **Endpoint**: https://api.osv.dev/v1/query
- **Authentication**: None required
- **Rate Limits**: None
- **Data**: CVEs, CVSS scores, affected versions, fix versions

## Severity Mapping

OSV severity is mapped to Mikmbr severity levels:

| CVSS Score | OSV Severity | Mikmbr Severity |
|------------|--------------|-----------------|
| 9.0 - 10.0 | CRITICAL     | CRITICAL        |
| 7.0 - 8.9  | HIGH         | HIGH            |
| 4.0 - 6.9  | MEDIUM       | MEDIUM          |
| 0.1 - 3.9  | LOW          | LOW             |
| Unknown    | UNKNOWN      | MEDIUM          |

## Testing

```bash
# Run dependency scanning tests
py -m pytest tests/test_dependency_scanning.py -v

# Run full v1.8 validation
py validate_v18.py
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `--check-deps` | Scan dependencies in addition to code |
| `--deps-only` | Skip code analysis, scan only dependencies |
| `--fail-on SEVERITY` | Works with dependency findings |
| `--format {human,json,sarif}` | All formats support dependency findings |
| `--verbose` | Shows detailed vulnerability information |

## Configuration

Future enhancement - add to `.mikmbr.yaml`:

```yaml
dependency_scanning:
  enabled: true
  sources:
    - requirements.txt
    - pyproject.toml
  severity_threshold: medium
```

## Limitations

- **Version Resolution**: Only checks exact versions (==). Ranges (>=, <) are not fully resolved yet.
- **Transitive Dependencies**: Does not check indirect dependencies (future enhancement).
- **Offline Mode**: Requires internet connection to query OSV API.
- **File Support**: Currently only requirements.txt and pyproject.toml. Pipfile, poetry.lock, setup.py coming soon.

## Roadmap

### v1.9 (Future)
- [ ] Support for Pipfile and poetry.lock
- [ ] Transitive dependency scanning
- [ ] Local vulnerability database caching
- [ ] Custom vulnerability sources
- [ ] Ignore/allowlist for known false positives

### v2.0 (Future)
- [ ] Dependency graph visualization
- [ ] License compliance checking
- [ ] Automated pull requests for fixes
- [ ] Integration with other vulnerability databases (GitHub Advisory, NVD)

## Implementation Details

### Key Classes

**DependencyScanner** (`scanner.py`)
- Main entry point for dependency scanning
- Coordinates file parsing and vulnerability checking
- Creates Finding objects from vulnerabilities

**OSVClient** (`osv_client.py`)
- HTTP client for OSV API
- Handles vulnerability queries and response parsing
- Maps OSV data to internal Vulnerability objects

**Dependency** (`parsers.py`)
- Represents a parsed dependency
- Extracts package name, version constraints, line numbers
- Provides version resolution utilities

### Error Handling

- **Network Errors**: Gracefully handled with warnings, scan continues
- **Parse Errors**: Invalid dependency files logged, scan continues
- **API Errors**: HTTP errors caught, empty results returned

### Performance

- **Parallel Requests**: Future enhancement for concurrent OSV queries
- **Caching**: 15-minute response cache in OSVClient
- **Efficiency**: --deps-only skips AST parsing for fast scans

## Contributing

To add support for new dependency file formats:

1. Add parser function to `parsers.py`
2. Update `find_dependency_files()` to detect new format
3. Add to `DependencyScanner.scan_directory()`
4. Write tests in `test_dependency_scanning.py`
5. Update documentation

## References

- [OSV Project](https://osv.dev/)
- [OSV API Documentation](https://osv.dev/docs/)
- [CVSS Scoring](https://www.first.org/cvss/)
- [OWASP Top 10](https://owasp.org/Top10/)
