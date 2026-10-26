"""Test fixture: intentionally vulnerable Python code for audit scanning.

Used by tests/test_audit.py to verify the audit engine detects known vulns.
"""

import os
import pickle


# VULN: eval injection
def process_user_input():
    cmd = input("Enter command: ")
    # This should be detected: taint from input() → eval()
    result = eval(cmd)
    return result


# VULN: SQL injection with f-string
def get_user(db_cursor):
    name = input("Name: ")
    # This should be detected: taint from input() → cursor.execute()
    query = f"SELECT * FROM users WHERE name = '{name}'"
    db_cursor.execute(query)


# VULN: Command injection via os.system
def run_admin_task():
    task = input("Task: ")
    # This should be detected: taint from input() → os.system()
    os.system(task)


# VULN: Hardcoded password (regex pattern match)
DB_PASSWORD = "admin123!"
API_SECRET_KEY = "sk-abcdefghijklmnop1234567890"


# VULN: Unsafe deserialization
def load_user_data(data):
    # This should be detected: sink-only — pickle.loads
    user = pickle.loads(data)
    return user


# SAFE: No user input, static call only
def safe_list_directory():
    files = os.listdir("/tmp")
    return files


# SAFE: Sanitized input
def safe_shell_command():
    import shlex
    cmd = input("Enter: ")
    # This should NOT be flagged: shlex.quote sanitizes
    os.system(shlex.quote(cmd))
