# SARIF Output Format

Mikmbr supports SARIF (Static Analysis Results Interchange Format) output for seamless integration with GitHub Code Scanning and other security platforms.

## What is SARIF?

SARIF is an industry-standard JSON format for static analysis results. It's supported by:
- **GitHub Code Scanning** - Shows findings in pull requests and Security tab
- **Visual Studio Code** - SARIF Viewer extension
- **Azure DevOps** - Native SARIF support
- **GitLab** - Security dashboards
- **Many other tools** - Industry-wide adoption

## Usage

### Basic SARIF Output

```bash
mikmbr scan . --format sarif
```

This outputs SARIF JSON to stdout. Redirect to a file:

```bash
mikmbr scan . --format sarif > results.sarif
```

### Verbose SARIF

Include code snippets in the SARIF output:

```bash
mikmbr scan . --format sarif --verbose > results.sarif
```

## GitHub Code Scanning Integration

### Setup

1. **Create GitHub Actions Workflow**

Create `.github/workflows/mikmbr.yml`:

```yaml
name: Mikmbr Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write  # Required for Code Scanning
      contents: read

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install Mikmbr
      run: pip install mikmbr

    - name: Run Mikmbr scan
      run: mikmbr scan . --format sarif --verbose > results.sarif
      continue-on-error: true  # Don't fail workflow on findings

    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results.sarif
        category: mikmbr
```

2. **Commit and Push**

```bash
git add .github/workflows/mikmbr.yml
git commit -m "Add Mikmbr security scanning"
git push
```

3. **View Results**

- Go to your repository on GitHub
- Navigate to **Security** → **Code scanning alerts**
- View Mikmbr findings with file locations, severity, and remediation

### Pull Request Integration

Mikmbr findings will automatically appear as annotations in pull requests:

```
src/app.py
Line 42: [HIGH] SQL_INJECTION
  SQL query built with string concatenation/formatting
  Fix: Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
```

## SARIF Format Details

### Example SARIF Output

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Mikmbr",
          "version": "1.6.0",
          "informationUri": "https://github.com/tonybowen-me/Mikmbr",
          "rules": [
            {
              "id": "SQL_INJECTION",
              "name": "SQL_INJECTION",
              "shortDescription": {
                "text": "SQL query built with string concatenation/formatting"
              },
              "fullDescription": {
                "text": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
              },
              "defaultConfiguration": {
                "level": "error"
              },
              "properties": {
                "precision": "high",
                "tags": ["security", "sql", "injection"],
                "cwe": "CWE-89",
                "owasp": "A03:2021 - Injection"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "SQL_INJECTION",
          "level": "error",
          "message": {
            "text": "SQL query built with string concatenation/formatting"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "src/database.py"
                },
                "region": {
                  "startLine": 42,
                  "startColumn": 1
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### Severity Mapping

Mikmbr severity levels map to SARIF levels:

| Mikmbr Severity | SARIF Level | GitHub Display |
|----------------|-------------|----------------|
| HIGH | `error` | 🔴 High |
| MEDIUM | `warning` | 🟡 Medium |
| LOW | `note` | 🔵 Low |

### Tags

SARIF output includes tags for filtering:

- **Security category**: `security`
- **Severity**: `severity/high`, `severity/medium`, `severity/low`
- **CWE**: `cwe-89`, `cwe-78`, etc.
- **OWASP**: `owasp/a03`, `owasp/a07`, etc.
- **Vulnerability type**: `injection`, `sql`, `xss`, `secrets`, etc.

## Other SARIF Tools

### Visual Studio Code

1. Install **SARIF Viewer** extension
2. Open `.sarif` file in VS Code
3. Navigate to findings by clicking them

### SARIF Multitool

Microsoft's SARIF toolkit:

```bash
# Install
dotnet tool install -g Microsoft.CodeAnalysis.Sarif.Multitool

# Validate SARIF
sarif validate results.sarif

# Convert to other formats
sarif convert results.sarif --output results.csv --format csv
```

### sarif-tools (Python)

```bash
# Install
pip install sarif-tools

# View summary
sarif summary results.sarif

# View detailed info
sarif info results.sarif

# Convert to HTML
sarif html results.sarif
```

## Configuration

Configure SARIF output in `.mikmbr.yaml`:

```yaml
output:
  format: sarif
  verbose: true  # Include code snippets
```

Then simply run:

```bash
mikmbr scan .
```

## CI/CD Examples

### GitLab CI

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  image: python:3.11
  script:
    - pip install mikmbr
    - mikmbr scan . --format sarif > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Azure Pipelines

```yaml
# azure-pipelines.yml
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.11'

- script: |
    pip install mikmbr
    mikmbr scan . --format sarif > results.sarif
  displayName: 'Run Mikmbr Security Scan'

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'results.sarif'
    artifactName: 'CodeAnalysisLogs'
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install mikmbr'
                sh 'mikmbr scan . --format sarif > results.sarif'
                archiveArtifacts artifacts: 'results.sarif'
            }
        }
    }
}
```

## Filtering Results

### By Severity

GitHub Code Scanning allows filtering by severity level in the UI.

### By Rule

Filter by specific rule IDs:

```bash
# Use jq to filter SARIF
mikmbr scan . --format sarif | jq '.runs[0].results |= map(select(.ruleId == "SQL_INJECTION"))'
```

### By File

Filter findings from specific files:

```bash
# Only findings from src/
mikmbr scan src/ --format sarif > results.sarif
```

## Troubleshooting

### SARIF Validation Errors

Use Microsoft's validator:

```bash
sarif validate results.sarif
```

### GitHub Upload Fails

Common issues:
- Missing `security-events: write` permission
- SARIF file too large (>10MB limit)
- Invalid JSON format

### No Results in GitHub

- Check Actions logs for upload errors
- Verify scan found issues (empty SARIF is valid)
- Ensure repository has Code Scanning enabled

## Comparison with Other Formats

| Feature | SARIF | JSON | Human |
|---------|-------|------|-------|
| GitHub integration | ✅ Native | ❌ No | ❌ No |
| Machine-readable | ✅ Yes | ✅ Yes | ❌ No |
| Human-readable | ⚠️ Complex | ⚠️ Verbose | ✅ Yes |
| IDE support | ✅ VS Code | ❌ No | ❌ No |
| Industry standard | ✅ Yes | ⚠️ Custom | ❌ No |
| Code snippets | ✅ Optional | ✅ Yes | ✅ Yes |

## Resources

- [SARIF Specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [GitHub Code Scanning Docs](https://docs.github.com/en/code-security/code-scanning)
- [SARIF Tutorials](https://github.com/microsoft/sarif-tutorials)
- [SARIF Viewer Extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)

## Version History

- **v1.6.0**: Added SARIF output format
  - Full SARIF 2.1.0 specification compliance
  - GitHub Code Scanning integration
  - Severity and confidence mapping
  - CWE and OWASP tagging
  - Optional code snippets
