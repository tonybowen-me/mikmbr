"""Test fixture with various security vulnerabilities."""

import os
import subprocess
import hashlib

# DANGEROUS_EXEC - eval
result = eval("1 + 1")

# DANGEROUS_EXEC - exec
exec("print('hello')")

# COMMAND_INJECTION - os.system
os.system("ls -la")

# COMMAND_INJECTION - subprocess with shell=True
subprocess.run("echo hello", shell=True)

# SQL_INJECTION - string concatenation
user_id = "123"
cursor.execute("SELECT * FROM users WHERE id = " + user_id)

# SQL_INJECTION - f-string
name = "admin"
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# WEAK_CRYPTO - MD5
hashlib.md5(b"data")

# WEAK_CRYPTO - SHA1
hashlib.sha1(b"data")

# HARDCODED_SECRET - API key
api_key = "sk_live_1234567890abcdef"

# HARDCODED_SECRET - password
password = "super_secret_pass123"
