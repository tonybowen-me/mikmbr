"""
Example file demonstrating framework-specific vulnerabilities in Django, Flask, and FastAPI.
Run mikmbr scan on this file to see framework-specific detections.
"""

# ===== Django Vulnerabilities =====

# Django: Raw SQL Query (HIGH)
from django.db import models

class User(models.Model):
    username = models.CharField(max_length=100)

def get_user_unsafe(user_id):
    # VULNERABLE: Using raw() without parameterization
    return User.objects.raw(f'SELECT * FROM users WHERE id = {user_id}')  # mikmbr will detect this

# Django: mark_safe() XSS Risk (MEDIUM)
from django.utils.safestring import mark_safe

def render_user_content(user_html):
    # VULNERABLE: Marking user content as safe can lead to XSS
    return mark_safe(user_html)  # mikmbr will detect this

# Django: DEBUG = True (HIGH)
# VULNERABLE: Debug mode in production
DEBUG = True  # mikmbr will detect this

# Django: Empty ALLOWED_HOSTS (MEDIUM)
# VULNERABLE: Host header attacks
ALLOWED_HOSTS = []  # mikmbr will detect this

# Django: Wildcard ALLOWED_HOSTS (MEDIUM)
# VULNERABLE: Host header attacks
ALLOWED_HOSTS = ['*']  # mikmbr will detect this

# Django: Hardcoded SECRET_KEY (HIGH)
# VULNERABLE: Compromises session security
SECRET_KEY = "django-insecure-hardcoded-secret-key-123456"  # mikmbr will detect this

# Django: QuerySet.extra() (HIGH)
def get_users_with_extra(filter_value):
    # VULNERABLE: extra() can lead to SQL injection
    return User.objects.extra(where=[f"status = '{filter_value}'"])  # mikmbr will detect this


# ===== Flask Vulnerabilities =====

from flask import Flask, render_template_string, send_file, make_response, Response

app = Flask(__name__)

# Flask: Hardcoded secret_key (HIGH)
# VULNERABLE: Hardcoded secret
app.secret_key = "hardcoded_flask_secret_key_123"  # mikmbr will detect this

# Flask: Debug mode (HIGH)
# VULNERABLE: Debug mode exposes sensitive info
app.debug = True  # mikmbr will detect this

# Flask: send_file() with user input (HIGH)
@app.route('/download')
def download_file(filename):
    # VULNERABLE: Path traversal
    return send_file(filename)  # mikmbr will detect this

# Flask: render_template_string() SSTI (HIGH)
@app.route('/render')
def render_user_template(template):
    # VULNERABLE: Server-Side Template Injection
    return render_template_string(template)  # mikmbr will detect this

# Flask: Insecure cookie (MEDIUM)
@app.route('/setcookie')
def set_cookie():
    response = Response("Cookie set")
    # VULNERABLE: Missing secure flags
    response.set_cookie('session_id', 'abc123')  # mikmbr will detect this
    return response

# Flask: Insecure CORS (MEDIUM)
from flask_cors import CORS
# VULNERABLE: Wildcard CORS origin
CORS(app, origins=['*'])  # mikmbr will detect this


# ===== FastAPI Vulnerabilities =====

from fastapi import FastAPI, Response, Query
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

api = FastAPI()

# FastAPI: Insecure CORS (MEDIUM)
# VULNERABLE: Wildcard CORS
api.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],  # mikmbr will detect this
    allow_credentials=True
)

# FastAPI: Unvalidated input (MEDIUM)
@api.post('/user')
def create_user(data: dict):  # mikmbr will detect this - should use Pydantic model
    return {"created": True}

# FastAPI: FileResponse with user path (HIGH)
@api.get('/file')
def get_file(filepath: str):
    # VULNERABLE: Path traversal
    return FileResponse(filepath)  # mikmbr will detect this

# FastAPI: HTMLResponse with unsanitized content (MEDIUM)
@api.get('/html')
def get_html(content: str):
    # VULNERABLE: XSS risk
    return HTMLResponse(content)  # mikmbr will detect this

# FastAPI: Missing authentication (LOW confidence)
@api.post('/admin/delete')
def delete_data(item_id: int):  # mikmbr will detect this - no authentication
    return {"deleted": item_id}

# FastAPI: Unvalidated query params (MEDIUM)
@api.get('/search')
def search(query):  # mikmbr will detect this - no type hint
    return {"results": []}


# ===== Secure Examples (won't be detected) =====

# Django: Secure raw() with parameterization
def get_user_safe(user_id):
    return User.objects.raw('SELECT * FROM users WHERE id = %s', [user_id])

# Django: Secure configuration
import os
DEBUG = os.environ.get('DEBUG', 'False') == 'True'
SECRET_KEY = os.environ.get('SECRET_KEY')
ALLOWED_HOSTS = ['example.com', 'www.example.com']

# Flask: Secure configuration
app2 = Flask(__name__)
app2.secret_key = os.environ.get('SECRET_KEY')
app2.debug = False

# Flask: Secure cookie
@app2.route('/secure_cookie')
def set_secure_cookie():
    response = Response("Secure cookie set")
    response.set_cookie('session_id', 'abc123', secure=True, httponly=True, samesite='Lax')
    return response

# FastAPI: Secure with Pydantic validation
from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    email: str

@api.post('/user/secure')
def create_user_secure(user: UserCreate):
    return {"created": True, "user": user.username}

# FastAPI: Secure CORS
api2 = FastAPI()
api2.add_middleware(
    CORSMiddleware,
    allow_origins=['https://trusted-domain.com'],
    allow_credentials=True
)
