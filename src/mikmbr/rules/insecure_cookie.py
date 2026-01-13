"""Detection rule for insecure cookie configurations."""

import ast
from typing import List
from .base import Rule, RuleSeverity
from ..models import Finding


class InsecureCookieRule(Rule):
    """Detects cookies set without security flags.

    Vulnerable patterns:
    - response.set_cookie('session', value)  # Missing HttpOnly, Secure
    - cookie['session'] = value  # No security flags

    Safe alternatives:
    - response.set_cookie('session', value, httponly=True, secure=True, samesite='Strict')
    """

    rule_id = "INSECURE_COOKIE"
    severity = RuleSeverity.MEDIUM
    cwe_id = "CWE-614"
    owasp_category = "A05:2021 - Security Misconfiguration"

    def check(self, tree: ast.AST, filename: str) -> List[Finding]:
        """Check for insecure cookie settings."""
        findings = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for response.set_cookie() calls
                if self._is_set_cookie_call(node):
                    missing_flags = self._get_missing_security_flags(node)
                    if missing_flags:
                        findings.append(Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            filename=filename,
                            line_number=node.lineno,
                            message=f"Cookie set without security flags: {', '.join(missing_flags)}",
                            code_snippet=ast.get_source_segment(open(filename).read(), node) if hasattr(ast, 'get_source_segment') else None,
                            cwe_id=self.cwe_id,
                            owasp_category=self.owasp_category,
                            recommendation="Set security flags: set_cookie(..., httponly=True, secure=True, samesite='Strict')"
                        ))

        return findings

    def _is_set_cookie_call(self, node: ast.Call) -> bool:
        """Check if this is a set_cookie method call."""
        if isinstance(node.func, ast.Attribute):
            # response.set_cookie(), session.set_cookie(), etc.
            if node.func.attr == 'set_cookie':
                return True
        return False

    def _get_missing_security_flags(self, node: ast.Call) -> List[str]:
        """Check which security flags are missing."""
        missing = []

        # Extract keyword arguments
        kwargs = {kw.arg: kw.value for kw in node.keywords}

        # Check httponly flag
        if 'httponly' not in kwargs:
            missing.append('httponly')
        elif isinstance(kwargs['httponly'], ast.Constant):
            if not kwargs['httponly'].value:  # httponly=False
                missing.append('httponly')

        # Check secure flag
        if 'secure' not in kwargs:
            missing.append('secure')
        elif isinstance(kwargs['secure'], ast.Constant):
            if not kwargs['secure'].value:  # secure=False
                missing.append('secure')

        # Check samesite flag
        if 'samesite' not in kwargs:
            missing.append('samesite')

        return missing
