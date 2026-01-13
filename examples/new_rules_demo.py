"""Demo file showcasing new detection rules in mikmbr v1.5."""

import requests
import logging
from flask import redirect, render_template_string

logger = logging.getLogger(__name__)

# SSRF - Server-Side Request Forgery
def fetch_url(user_url):
    # Potential SSRF: Making request to user-controlled URL
    response = requests.get(user_url)
    return response.text

# Open Redirect
def redirect_user(next_url):
    # Potential open redirect: Redirecting to user-controlled URL
    return redirect(next_url)

# Log Injection
def log_user_action(username, action):
    # Potential log injection: Logging unsanitized user input
    logger.info(f"User {username} performed action: {action}")

# Template Injection (SSTI)
def render_dynamic_template(template_string):
    # CRITICAL: Server-Side Template Injection
    return render_template_string(template_string)

# Timing Attack
def check_password(password, stored_password):
    # Potential timing attack: Using == for password comparison
    if password == stored_password:
        return True
    return False

# Bare Except
def risky_operation():
    try:
        dangerous_function()
    except:  # Bare except catches everything!
        pass

# Debug Code
app.debug = True  # Debug mode in production!

# Breakpoint
def debug_function():
    breakpoint()  # Forgot to remove!
    return "result"

# Assert for security
def admin_only(user):
    assert user.is_admin  # Removed with python -O!
    perform_admin_action()
