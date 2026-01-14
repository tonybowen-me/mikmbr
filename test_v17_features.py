"""Test file for v1.7 features: exit codes and context lines."""

# This file has multiple severity levels for testing --fail-on

# HIGH severity - SQL Injection
import sqlite3
def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL INJECTION
    cursor.execute(query)
    return cursor.fetchone()

# MEDIUM severity - Weak Crypto
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # WEAK CRYPTO

# LOW severity - Bare Except
def process_data(data):
    try:
        return int(data)
    except:  # BARE EXCEPT
        return None

print("Test file with multiple severity levels")
