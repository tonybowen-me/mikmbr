# Code Context Lines

Show surrounding code context for better understanding of security findings.

## Usage

### Basic Usage

By default, Mikmbr shows only the line with the security issue:

```bash
mikmbr scan myfile.py
```

Output:
```
[HIGH] myfile.py:42
  Rule: SQL_INJECTION
  Issue: SQL query built with string concatenation
  Fix: Use parameterized queries
```

### With Context

Use `--context N` to show N lines before and after each finding:

```bash
mikmbr scan myfile.py --context 3
```

Output:
```
[HIGH] myfile.py:42
  Rule: SQL_INJECTION
  Issue: SQL query built with string concatenation
  Fix: Use parameterized queries
  Code:
     39 | def get_user(user_id):
     40 |     conn = sqlite3.connect('db.sqlite')
     41 |     cursor = conn.cursor()
  >  42 |     query = f"SELECT * FROM users WHERE id = {user_id}"
     43 |     cursor.execute(query)
     44 |     return cursor.fetchone()
     45 |
```

The `>` marker indicates the line with the security issue.

## --context Flag

### Syntax

```bash
mikmbr scan <path> --context <N>
```

Where `N` is the number of lines to show before and after the finding.

### Examples

**1 line of context:**
```bash
mikmbr scan . --context 1
```

Shows 1 line before and 1 line after (3 lines total).

**5 lines of context:**
```bash
mikmbr scan . --context 5
```

Shows 5 lines before and 5 lines after (11 lines total).

**No context (default):**
```bash
mikmbr scan .
# Equivalent to --context 0
```

## When to Use Context

### Quick Review (0-2 lines)

For rapid scanning, minimal context:
```bash
mikmbr scan . --context 0  # Default
mikmbr scan . --context 1  # Quick peek
```

### Detailed Analysis (3-5 lines)

For understanding the issue:
```bash
mikmbr scan . --context 3  # Recommended
mikmbr scan . --context 5  # More detail
```

### Deep Investigation (10+ lines)

For complex issues:
```bash
mikmbr scan . --context 10
```

## Combining with Other Flags

### With --verbose

When used together, `--context` takes precedence over verbose mode's code snippets:

```bash
mikmbr scan . --verbose --context 3
```

Shows:
- All verbose information (CWE, OWASP, references)
- Context lines (instead of the basic code snippet)

### With --format json

Context flag is ignored for JSON output (code_snippet field used instead):

```bash
mikmbr scan . --format json --context 3
# --context is ignored, JSON uses code_snippet field
```

### With --format sarif

Context flag is ignored for SARIF output:

```bash
mikmbr scan . --format sarif --context 3
# --context is ignored, SARIF uses its own snippet format
```

## Output Format

### Line Numbers

Context output includes line numbers for easy navigation:

```
  Code:
     10 | import sqlite3
     11 |
     12 | def get_user(user_id):
  >  13 |     query = f"SELECT * FROM users WHERE id = {user_id}"
     14 |     cursor.execute(query)
     15 |     return cursor.fetchone()
     16 |
```

- Line numbers are left-padded for alignment
- `>` marker indicates the vulnerable line
- Empty lines are preserved

### Edge Cases

**Start of file:**
```
  Code:
  >   1 | import os
      2 |
      3 | os.system(user_command)
```

**End of file:**
```
  Code:
     98 |     return result
     99 |
  > 100 | password = "hardcoded_secret"
```

## Examples

### Example 1: SQL Injection

```python
# database.py
def get_user_by_id(user_id):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE
    cursor.execute(query)
    return cursor.fetchone()
```

```bash
$ mikmbr scan database.py --context 2
```

Output:
```
[HIGH] database.py:5
  Rule: SQL_INJECTION
  Issue: SQL query built with string concatenation
  Fix: Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
  Code:
      3 |     conn = sqlite3.connect('app.db')
      4 |     cursor = conn.cursor()
  >   5 |     query = f"SELECT * FROM users WHERE id = {user_id}"
      6 |     cursor.execute(query)
      7 |     return cursor.fetchone()
```

### Example 2: Multiple Findings

When scanning a file with multiple issues, context helps distinguish them:

```bash
$ mikmbr scan app.py --context 2

[HIGH] app.py:15
  Rule: SQL_INJECTION
  Code:
     13 | def search_users(name):
     14 |     cursor = conn.cursor()
  >  15 |     query = f"SELECT * FROM users WHERE name = '{name}'"
     16 |     cursor.execute(query)
     17 |     return cursor.fetchall()

[HIGH] app.py:32
  Rule: COMMAND_INJECTION
  Code:
     30 | def run_command(cmd):
     31 |     import subprocess
  >  32 |     subprocess.call(cmd, shell=True)
     33 |     return "Command executed"
     34 |
```

### Example 3: Framework-Specific Issues

Context is especially useful for framework code:

```python
# views.py (Django)
from django.shortcuts import render
from django.utils.safestring import mark_safe

def show_profile(request):
    user_bio = request.GET.get('bio', '')
    safe_bio = mark_safe(user_bio)  # VULNERABLE
    return render(request, 'profile.html', {'bio': safe_bio})
```

```bash
$ mikmbr scan views.py --context 3
```

Output:
```
[MEDIUM] views.py:6
  Rule: DJANGO_SECURITY
  Issue: mark_safe() bypasses Django's XSS protection
  Fix: Only use mark_safe() on content you've explicitly sanitized
  Code:
      3 |
      4 | def show_profile(request):
      5 |     user_bio = request.GET.get('bio', '')
  >   6 |     safe_bio = mark_safe(user_bio)
      7 |     return render(request, 'profile.html', {'bio': safe_bio})
      8 |
      9 | def another_view(request):
```

## CI/CD Usage

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    pip install mikmbr
    mikmbr scan . --context 3 --fail-on high
```

Shows context in GitHub Actions logs for easier review.

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: mikmbr
        name: Mikmbr Security Scan
        entry: mikmbr scan --context 2
        language: system
        pass_filenames: false
```

## Performance

Context lines have minimal performance impact:
- Files are already read during scanning
- Only adds line extraction (negligible cost)
- No impact on detection accuracy

```bash
# With context
$ time mikmbr scan large_project/ --context 5
# ~8.3 seconds

# Without context
$ time mikmbr scan large_project/
# ~8.2 seconds
```

Difference is typically <5%.

## Configuration File

Currently, `--context` is CLI-only. Configuration file support may be added in future versions.

## Best Practices

1. **Default to 0** - Use minimal context for CI/CD speed
2. **Use 2-3 for local** - Good balance of context and readability
3. **Use 5+ for investigation** - When debugging specific issues
4. **Combine with --verbose** - Get full details + context
5. **Redirect to file** - Save output with context for later review:
   ```bash
   mikmbr scan . --context 5 > security-report.txt
   ```

## Troubleshooting

**Q: Context not showing?**
A: Context only works with human output format. Use `--format human` (default) not `--format json`.

**Q: Line numbers seem off?**
A: Ensure file hasn't changed since scanning. Context reads from disk at format time.

**Q: Can I use with SARIF?**
A: No, SARIF has its own snippet format. Use `--verbose` with SARIF for code snippets in results.

## Version History

- **v1.7.0**: Added `--context N` flag for code context lines
- **v1.6.0**: Basic code snippets in verbose mode
