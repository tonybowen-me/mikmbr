"""Detection rule for weak password hashing algorithms."""

import ast
from typing import List
from .base import Rule, RuleSeverity
from ..models import Finding


class WeakPasswordHashRule(Rule):
    """Detects use of weak algorithms for password hashing.

    Vulnerable patterns:
    - hashlib.md5(password)
    - hashlib.sha1(password)
    - hashlib.sha256(password)  # Not salted/stretched

    Safe alternatives:
    - bcrypt.hashpw()
    - argon2.hash()
    - PBKDF2 from hashlib
    - scrypt
    """

    rule_id = "WEAK_PASSWORD_HASH"
    severity = RuleSeverity.HIGH
    cwe_id = "CWE-916"
    owasp_category = "A02:2021 - Cryptographic Failures"

    # Weak hashing functions for passwords
    WEAK_HASH_FUNCS = {
        'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
        'blake2b', 'blake2s', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512'
    }

    # Password-related variable names (heuristic)
    PASSWORD_INDICATORS = {
        'password', 'passwd', 'pwd', 'pass', 'secret',
        'credential', 'auth', 'login', 'user_input'
    }

    def check(self, tree: ast.AST, filename: str) -> List[Finding]:
        """Check for weak password hashing."""
        findings = []

        for node in ast.walk(tree):
            # Check for hashlib.md5(password), hashlib.sha1(password), etc.
            if isinstance(node, ast.Call):
                finding = self._check_hashlib_call(node, filename)
                if finding:
                    findings.append(finding)

        return findings

    def _check_hashlib_call(self, node: ast.Call, filename: str) -> Finding:
        """Check if this is a weak hashlib call on password data."""
        # Check for hashlib.md5(...), hashlib.sha1(...), etc.
        if isinstance(node.func, ast.Attribute):
            if (isinstance(node.func.value, ast.Name) and
                node.func.value.id == 'hashlib' and
                node.func.attr in self.WEAK_HASH_FUNCS):

                # Check if argument looks like a password
                if node.args and self._looks_like_password(node.args[0]):
                    return Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        filename=filename,
                        line_number=node.lineno,
                        message=f"Weak password hashing algorithm: {node.func.attr}",
                        code_snippet=ast.get_source_segment(open(filename).read(), node) if hasattr(ast, 'get_source_segment') else None,
                        cwe_id=self.cwe_id,
                        owasp_category=self.owasp_category,
                        recommendation="Use bcrypt, argon2, or PBKDF2: import bcrypt; bcrypt.hashpw(password.encode(), bcrypt.gensalt())"
                    )

        return None

    def _looks_like_password(self, arg: ast.AST) -> bool:
        """Heuristic to detect if argument might be a password."""
        # Check variable names
        if isinstance(arg, ast.Name):
            name_lower = arg.id.lower()
            return any(indicator in name_lower for indicator in self.PASSWORD_INDICATORS)

        # Check method calls like user.password, request.form['password']
        if isinstance(arg, ast.Attribute):
            attr_lower = arg.attr.lower()
            return any(indicator in attr_lower for indicator in self.PASSWORD_INDICATORS)

        # Check subscripts like data['password']
        if isinstance(arg, ast.Subscript):
            if isinstance(arg.slice, ast.Constant) and isinstance(arg.slice.value, str):
                key_lower = arg.slice.value.lower()
                return any(indicator in key_lower for indicator in self.PASSWORD_INDICATORS)

        # Conservative: if we can't determine, flag it
        return True
