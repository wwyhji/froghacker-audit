"""Test fixture: clean Python code with no vulnerabilities."""


def add_numbers(a, b):
    """Return sum of two numbers."""
    return a + b


def greet(name):
    """Return a greeting string."""
    return f"Hello, {name}!"


class Calculator:
    """Simple calculator class."""

    def multiply(self, x, y):
        return x * y


def safe_file_read():
    """Safe file read with hardcoded path."""
    with open("/etc/hostname", "r") as f:
        return f.read().strip()
