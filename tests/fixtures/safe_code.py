"""Test fixture with safe code - no vulnerabilities."""

import os
import subprocess
import hashlib
import ast

# Safe alternatives to eval
result = ast.literal_eval("1 + 1")

# Safe subprocess usage
subprocess.run(["ls", "-la"])

# Safe SQL with parameterized queries
user_id = "123"
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# Strong cryptography
hashlib.sha256(b"data")
hashlib.sha512(b"data")

# Safe secret management
api_key = os.getenv("API_KEY")
password = os.getenv("PASSWORD")

# Regular functions
def process_data(data):
    """Process data safely."""
    return data.strip().lower()
