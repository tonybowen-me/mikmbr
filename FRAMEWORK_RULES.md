# Framework-Specific Security Rules

Mikmbr includes specialized detection rules for popular Python web frameworks: Django, Flask, and FastAPI.

## Django Security Rules

### Detected Vulnerabilities

#### 1. Raw SQL Queries (HIGH)
**Pattern:** `Model.objects.raw()` without parameterization

```python
# VULNERABLE
User.objects.raw(f'SELECT * FROM users WHERE id = {user_id}')

# SECURE
User.objects.raw('SELECT * FROM users WHERE id = %s', [user_id])
```

**CWE:** CWE-89 (SQL Injection)
**OWASP:** A03:2021 - Injection

#### 2. mark_safe() Usage (MEDIUM)
**Pattern:** Using `mark_safe()` which bypasses XSS protection

```python
# VULNERABLE
from django.utils.safestring import mark_safe
return mark_safe(user_content)

# SECURE - Use template auto-escaping instead
return render(request, 'template.html', {'content': user_content})
```

**CWE:** CWE-79 (Cross-Site Scripting)
**OWASP:** A03:2021 - Injection

#### 3. QuerySet.extra() (HIGH)
**Pattern:** Using `.extra()` which can lead to SQL injection

```python
# VULNERABLE
User.objects.extra(where=[f"status = '{user_status}'"])

# SECURE
User.objects.filter(status=user_status)  # Use ORM methods
# Or use annotate/aggregate
```

**CWE:** CWE-89 (SQL Injection)
**OWASP:** A03:2021 - Injection

#### 4. DEBUG = True (HIGH)
**Pattern:** Hardcoded `DEBUG = True` in settings

```python
# VULNERABLE
DEBUG = True

# SECURE
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
```

**CWE:** CWE-489 (Debug Code)
**OWASP:** A05:2021 - Security Misconfiguration

#### 5. Empty/Wildcard ALLOWED_HOSTS (MEDIUM)
**Pattern:** `ALLOWED_HOSTS = []` or `ALLOWED_HOSTS = ['*']`

```python
# VULNERABLE
ALLOWED_HOSTS = []
ALLOWED_HOSTS = ['*']

# SECURE
ALLOWED_HOSTS = ['example.com', 'www.example.com']
```

**CWE:** CWE-20 (Improper Input Validation)
**OWASP:** A05:2021 - Security Misconfiguration

#### 6. Hardcoded SECRET_KEY (HIGH)
**Pattern:** Hardcoded Django `SECRET_KEY`

```python
# VULNERABLE
SECRET_KEY = "django-insecure-hardcoded-key"

# SECURE
SECRET_KEY = os.environ.get('SECRET_KEY')
```

**CWE:** CWE-798 (Hardcoded Credentials)
**OWASP:** A07:2021 - Identification and Authentication Failures

---

## Flask Security Rules

### Detected Vulnerabilities

#### 1. send_file() Path Traversal (HIGH)
**Pattern:** `send_file()` or `send_from_directory()` with user input

```python
# VULNERABLE
from flask import send_file

@app.route('/download/<filename>')
def download(filename):
    return send_file(filename)

# SECURE
from werkzeug.security import safe_join

@app.route('/download/<filename>')
def download(filename):
    safe_path = safe_join(UPLOAD_FOLDER, filename)
    return send_file(safe_path)
```

**CWE:** CWE-22 (Path Traversal)
**OWASP:** A01:2021 - Broken Access Control

#### 2. render_template_string() SSTI (HIGH)
**Pattern:** Server-Side Template Injection via `render_template_string()`

```python
# VULNERABLE
from flask import render_template_string

@app.route('/render')
def render(template):
    return render_template_string(template)  # User controls template!

# SECURE
from flask import render_template

@app.route('/render')
def render():
    return render_template('safe_template.html', data=user_data)
```

**CWE:** CWE-94 (Code Injection)
**OWASP:** A03:2021 - Injection

#### 3. Hardcoded app.secret_key (HIGH)
**Pattern:** Hardcoded Flask secret key

```python
# VULNERABLE
app.secret_key = "hardcoded_secret"

# SECURE
app.secret_key = os.environ.get('SECRET_KEY')
```

**CWE:** CWE-798 (Hardcoded Credentials)
**OWASP:** A07:2021 - Identification and Authentication Failures

#### 4. app.debug = True (HIGH)
**Pattern:** Debug mode enabled

```python
# VULNERABLE
app.debug = True

# SECURE
app.debug = False
# Or use environment variable
app.debug = os.environ.get('FLASK_DEBUG', 'False') == 'True'
```

**CWE:** CWE-489 (Debug Code)
**OWASP:** A05:2021 - Security Misconfiguration

#### 5. Insecure Cookies (MEDIUM)
**Pattern:** `set_cookie()` without security flags

```python
# VULNERABLE
response.set_cookie('session', session_id)

# SECURE
response.set_cookie('session', session_id,
                    secure=True,      # HTTPS only
                    httponly=True,    # No JavaScript access
                    samesite='Lax')   # CSRF protection
```

**CWE:** CWE-614 (Sensitive Cookie Without Secure Flag)
**OWASP:** A05:2021 - Security Misconfiguration

#### 6. Wildcard CORS (MEDIUM)
**Pattern:** CORS with `origins=['*']`

```python
# VULNERABLE
from flask_cors import CORS
CORS(app, origins=['*'])

# SECURE
CORS(app, origins=['https://trusted-domain.com'])
```

**CWE:** CWE-942 (Permissive Cross-domain Policy)
**OWASP:** A05:2021 - Security Misconfiguration

---

## FastAPI Security Rules

### Detected Vulnerabilities

#### 1. Unvalidated Input (MEDIUM)
**Pattern:** Route parameters using `dict` or `Any` without Pydantic validation

```python
# VULNERABLE
@app.post('/user')
def create_user(data: dict):
    return {"created": True}

# SECURE
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    email: str

@app.post('/user')
def create_user(user: UserCreate):
    return {"created": True}
```

**CWE:** CWE-20 (Improper Input Validation)
**OWASP:** A03:2021 - Injection

#### 2. FileResponse Path Traversal (HIGH)
**Pattern:** `FileResponse` with user-controlled path

```python
# VULNERABLE
from fastapi.responses import FileResponse

@app.get('/file')
def get_file(path: str):
    return FileResponse(path)

# SECURE
from pathlib import Path

@app.get('/file')
def get_file(filename: str):
    safe_path = Path(UPLOAD_DIR) / filename
    # Verify path is within allowed directory
    safe_path = safe_path.resolve()
    if not str(safe_path).startswith(str(Path(UPLOAD_DIR).resolve())):
        raise HTTPException(403, "Access denied")
    return FileResponse(safe_path)
```

**CWE:** CWE-22 (Path Traversal)
**OWASP:** A01:2021 - Broken Access Control

#### 3. HTMLResponse XSS (MEDIUM)
**Pattern:** `HTMLResponse` with unsanitized content

```python
# VULNERABLE
from fastapi.responses import HTMLResponse

@app.get('/html')
def get_html(content: str):
    return HTMLResponse(content)

# SECURE
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

@app.get('/html')
def get_html(request: Request, content: str):
    return templates.TemplateResponse("page.html",
                                    {"request": request, "content": content})
```

**CWE:** CWE-79 (Cross-Site Scripting)
**OWASP:** A03:2021 - Injection

#### 4. Wildcard CORS (MEDIUM)
**Pattern:** CORSMiddleware with `allow_origins=['*']`

```python
# VULNERABLE
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True
)

# SECURE
app.add_middleware(
    CORSMiddleware,
    allow_origins=['https://trusted-domain.com'],
    allow_credentials=True
)
```

**CWE:** CWE-942 (Permissive Cross-domain Policy)
**OWASP:** A05:2021 - Security Misconfiguration

#### 5. Missing Authentication (LOW)
**Pattern:** Route handlers (especially POST/PUT/DELETE) without authentication

```python
# VULNERABLE
@app.post('/admin/delete')
def delete_user(user_id: int):
    return {"deleted": user_id}

# SECURE
from fastapi import Depends
from .auth import get_current_admin_user

@app.post('/admin/delete')
def delete_user(user_id: int,
                admin: User = Depends(get_current_admin_user)):
    return {"deleted": user_id}
```

**CWE:** CWE-306 (Missing Authentication)
**OWASP:** A07:2021 - Identification and Authentication Failures

---

## Configuration

You can enable/disable framework-specific rules in `.mikmbr.yaml`:

```yaml
rules:
  # Disable all framework rules
  DJANGO_SECURITY: false
  FLASK_SECURITY: false
  FASTAPI_SECURITY: false

  # Or adjust severity
  DJANGO_SECURITY:
    severity: HIGH
```

## Usage

Framework rules are automatically enabled when you scan any Python code:

```bash
# Scan Django project
mikmbr scan myproject/

# Scan Flask app
mikmbr scan app.py --verbose

# Scan FastAPI project with JSON output
mikmbr scan api/ --format json
```

## Examples

See [examples/framework_vulnerabilities.py](examples/framework_vulnerabilities.py) for complete examples of each vulnerability.

```bash
mikmbr scan examples/framework_vulnerabilities.py --verbose
```

## Framework Detection

Mikmbr detects framework-specific issues based on:
- Import statements (e.g., `from django.db import models`)
- Function decorators (e.g., `@app.route()`, `@api.get()`)
- Configuration patterns (e.g., `DEBUG = True`, `SECRET_KEY`)
- Framework-specific APIs (e.g., `mark_safe()`, `send_file()`, `FileResponse`)

## Comparison with Other Tools

| Feature | Mikmbr | Bandit | Semgrep |
|---------|--------|--------|---------|
| Django-specific rules | ✅ 6 rules | ⚠️ Limited | ✅ Community rules |
| Flask-specific rules | ✅ 6 rules | ⚠️ Limited | ✅ Community rules |
| FastAPI-specific rules | ✅ 5 rules | ❌ None | ⚠️ Few rules |
| Zero config needed | ✅ Yes | ✅ Yes | ❌ Requires rules |
| Offline operation | ✅ Yes | ✅ Yes | ✅ Yes |

## Version History

- **v1.6.0**: Added framework-specific security rules
  - Django: 6 detection rules
  - Flask: 6 detection rules
  - FastAPI: 5 detection rules
  - Total: 17 new framework-specific checks
