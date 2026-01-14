"""
Vulnerable code examples for showcase page.
Each function demonstrates a specific security vulnerability that Mikmbr detects.
DO NOT USE THIS CODE IN PRODUCTION!
"""

import os
import subprocess
import pickle
import sqlite3
import hashlib
import random
import re
import xml.etree.ElementTree as ET
import logging
import requests
from flask import Flask, request, redirect


# ============================================================================
# CRITICAL SEVERITY
# ============================================================================

def template_injection_jinja2():
    """CRITICAL: Template Injection - Jinja2"""
    from jinja2 import Template
    user_input = request.args.get('name')
    template = Template(user_input)  # VULNERABLE: SSTI
    return template.render()


def template_injection_mako():
    """CRITICAL: Template Injection - Mako"""
    from mako.template import Template
    user_template = request.args.get('template')
    t = Template(user_template)  # VULNERABLE: SSTI
    return t.render()


# ============================================================================
# HIGH SEVERITY
# ============================================================================

def dangerous_exec_eval():
    """HIGH: Dangerous Code Execution - eval()"""
    user_code = request.args.get('code')
    result = eval(user_code)  # VULNERABLE: Arbitrary code execution
    return result


def dangerous_exec_exec():
    """HIGH: Dangerous Code Execution - exec()"""
    user_script = request.form.get('script')
    exec(user_script)  # VULNERABLE: Arbitrary code execution


def command_injection_os_system():
    """HIGH: Command Injection - os.system()"""
    filename = request.args.get('file')
    os.system(f"cat {filename}")  # VULNERABLE: Command injection


def command_injection_subprocess():
    """HIGH: Command Injection - subprocess with shell=True"""
    user_input = request.args.get('cmd')
    subprocess.run(f"ls {user_input}", shell=True)  # VULNERABLE: Command injection


def sql_injection_fstring():
    """HIGH: SQL Injection - f-string"""
    user_id = request.args.get('id')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE: SQL injection
    cursor.execute(query)
    return cursor.fetchone()


def sql_injection_concat():
    """HIGH: SQL Injection - String concatenation"""
    username = request.form.get('username')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"  # VULNERABLE
    cursor.execute(query)
    return cursor.fetchone()


def weak_crypto_md5():
    """HIGH: Weak Cryptography - MD5"""
    password = request.form.get('password')
    hashed = hashlib.md5(password.encode()).hexdigest()  # VULNERABLE: MD5 is broken
    return hashed


def weak_crypto_sha1():
    """HIGH: Weak Cryptography - SHA1"""
    data = request.get_data()
    signature = hashlib.sha1(data).hexdigest()  # VULNERABLE: SHA1 is weak
    return signature


def insecure_deserialization_pickle():
    """HIGH: Insecure Deserialization - pickle.loads()"""
    user_data = request.get_data()
    obj = pickle.loads(user_data)  # VULNERABLE: Arbitrary code execution
    return obj


def path_traversal_open():
    """HIGH: Path Traversal - open() with user input"""
    filename = request.args.get('file')
    with open(f"/var/www/uploads/{filename}", 'r') as f:  # VULNERABLE: Path traversal
        return f.read()


def hardcoded_secrets_api_key():
    """HIGH: Hardcoded Secrets - API key"""
    API_KEY = "sk_live_51HqT2KLm9N8pQr3X4vY5zW6aB7cD8eF9gH0iJ1kL2mN3oP4qR5sT6uV7wX8yZ9"  # VULNERABLE
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.get("https://api.example.com/data", headers=headers)


def hardcoded_secrets_password():
    """HIGH: Hardcoded Secrets - Database password"""
    DB_PASSWORD = "MySecretP@ssw0rd123!"  # VULNERABLE: Hardcoded credential
    conn_string = f"postgresql://user:{DB_PASSWORD}@localhost/db"
    return conn_string


def ssrf_requests():
    """HIGH: Server-Side Request Forgery - requests"""
    url = request.args.get('url')
    response = requests.get(url)  # VULNERABLE: SSRF
    return response.text


def ssrf_urllib():
    """HIGH: Server-Side Request Forgery - urllib"""
    import urllib.request
    target_url = request.form.get('target')
    response = urllib.request.urlopen(target_url)  # VULNERABLE: SSRF
    return response.read()


def open_redirect_flask():
    """HIGH: Open Redirect"""
    next_url = request.args.get('next')
    return redirect(next_url)  # VULNERABLE: Open redirect


def weak_password_hash_md5():
    """HIGH: Weak Password Hashing - MD5"""
    password = request.form.get('password')
    hashed_password = hashlib.md5(password.encode()).hexdigest()  # VULNERABLE
    return hashed_password


def jwt_security_none_algorithm():
    """HIGH: JWT Security - None algorithm"""
    import jwt
    token = jwt.encode({'user': 'admin'}, None, algorithm='none')  # VULNERABLE
    return token


# ============================================================================
# MEDIUM SEVERITY
# ============================================================================

def insecure_random_token():
    """MEDIUM: Insecure Random - Token generation"""
    token = ''.join([str(random.randint(0, 9)) for _ in range(32)])  # VULNERABLE
    return token


def insecure_random_password():
    """MEDIUM: Insecure Random - Password generation"""
    import string
    password = ''.join(random.choice(string.ascii_letters) for _ in range(16))  # VULNERABLE
    return password


def regex_dos_backtracking():
    """MEDIUM: Regular Expression DoS"""
    user_input = request.args.get('input')
    pattern = r'^(a+)+$'  # VULNERABLE: Catastrophic backtracking
    if re.match(pattern, user_input):
        return "Match"
    return "No match"


def xxe_etree_parse():
    """MEDIUM: XML External Entity (XXE)"""
    xml_data = request.get_data()
    tree = ET.parse(xml_data)  # VULNERABLE: XXE if not configured properly
    return tree.getroot()


def log_injection_logging():
    """MEDIUM: Log Injection"""
    username = request.args.get('username')
    logging.info(f"User logged in: {username}")  # VULNERABLE: Log injection
    return "Logged"


def timing_attack_comparison():
    """MEDIUM: Timing Attack - String comparison"""
    user_token = request.headers.get('X-API-Token')
    correct_token = "secret_api_token_12345"
    if user_token == correct_token:  # VULNERABLE: Timing attack
        return "Access granted"
    return "Access denied"


def insecure_cookie_no_httponly():
    """MEDIUM: Insecure Cookie - No HttpOnly"""
    from flask import make_response
    resp = make_response("Success")
    resp.set_cookie('session_id', 'abc123', httponly=False)  # VULNERABLE
    return resp


def insecure_cookie_no_secure():
    """MEDIUM: Insecure Cookie - No Secure flag"""
    from flask import make_response
    resp = make_response("Success")
    resp.set_cookie('auth_token', 'xyz789', secure=False)  # VULNERABLE
    return resp


def session_security_weak():
    """MEDIUM: Session Security - Weak configuration"""
    app = Flask(__name__)
    app.config['SESSION_COOKIE_HTTPONLY'] = False  # VULNERABLE
    app.config['SESSION_COOKIE_SECURE'] = False  # VULNERABLE
    return app


# ============================================================================
# LOW SEVERITY
# ============================================================================

def bare_except_handler():
    """LOW: Bare Except - Catches all exceptions"""
    try:
        risky_operation()
    except:  # VULNERABLE: Bare except
        pass


def debug_code_print():
    """LOW: Debug Code - print() statement"""
    user_data = request.get_json()
    print(f"DEBUG: User data = {user_data}")  # VULNERABLE: Debug code in production
    return process_data(user_data)


def debug_code_breakpoint():
    """LOW: Debug Code - breakpoint()"""
    result = calculate_result()
    breakpoint()  # VULNERABLE: Debug code in production
    return result


# ============================================================================
# FRAMEWORK-SPECIFIC: DJANGO
# ============================================================================

def django_raw_sql():
    """HIGH: Django - Raw SQL query"""
    from django.db import connection
    user_id = request.GET.get('id')
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # VULNERABLE
    return cursor.fetchall()


def django_mark_safe():
    """MEDIUM: Django - mark_safe() with user input"""
    from django.utils.safestring import mark_safe
    user_html = request.GET.get('html')
    return mark_safe(user_html)  # VULNERABLE: XSS


def django_debug_true():
    """MEDIUM: Django - DEBUG = True in settings"""
    DEBUG = True  # VULNERABLE: Debug mode in production
    SECRET_KEY = 'django-insecure-key'


def django_secret_key():
    """HIGH: Django - Hardcoded SECRET_KEY"""
    SECRET_KEY = 'django-insecure-^w#$m3lk4j5h6g7f8d9s0a1q2w3e4r5t6y7u8i9o0p'  # VULNERABLE


# ============================================================================
# FRAMEWORK-SPECIFIC: FLASK
# ============================================================================

def flask_send_file_traversal():
    """HIGH: Flask - send_file() with user input"""
    from flask import send_file
    filename = request.args.get('file')
    return send_file(filename)  # VULNERABLE: Path traversal


def flask_debug_mode():
    """MEDIUM: Flask - Debug mode enabled"""
    app = Flask(__name__)
    app.run(debug=True)  # VULNERABLE: Debug mode in production


def flask_template_string():
    """CRITICAL: Flask - render_template_string with user input"""
    from flask import render_template_string
    template = request.args.get('template')
    return render_template_string(template)  # VULNERABLE: SSTI


# ============================================================================
# FRAMEWORK-SPECIFIC: FASTAPI
# ============================================================================

def fastapi_path_traversal():
    """HIGH: FastAPI - Path parameter without validation"""
    from fastapi import FastAPI
    app = FastAPI()

    @app.get("/files/{file_path:path}")
    async def read_file(file_path: str):  # VULNERABLE: No validation
        with open(file_path) as f:
            return f.read()


def fastapi_no_input_validation():
    """MEDIUM: FastAPI - Missing input validation"""
    from fastapi import FastAPI
    app = FastAPI()

    @app.post("/user")
    async def create_user(username: str, age: int):  # VULNERABLE: No validation
        return {"username": username, "age": age}


# Helper functions (not scanned)
def risky_operation():
    pass

def process_data(data):
    return data

def calculate_result():
    return 42
